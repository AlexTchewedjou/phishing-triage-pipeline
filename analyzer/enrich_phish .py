#!/usr/bin/env python3
"""
enrich_phish.py  -  Enriched phishing (.eml) analyzer for SOC triage.

Builds on analyze_phish.py. In addition to parsing headers / auth / URLs /
attachments, it:
  1. CLASSIFIES each email  -> LIKELY MALICIOUS / SUSPICIOUS / LIKELY BULK
     using auth results, BEC heuristics, and ESP awareness (cuts false positives).
  2. ENRICHES the indicators from the suspicious/malicious emails against:
       - VirusTotal   (domains, IPs, file hashes)
       - AbuseIPDB    (IP abuse confidence)
       - URLScan.io   (prior scans of a domain)
  3. Writes an enriched report + an enriched IOC CSV with reputation verdicts.

API keys are read from a .env file (default: secrets/.env), never hard-coded.
Standard library only (urllib) - no pip installs needed.
Read-only: never opens links, never executes attachments.

Usage:
    python enrich_phish.py samples/ -o output/ --env secrets/.env
    python enrich_phish.py samples/ -o output/ --no-enrich      (skip API calls)
"""

import argparse
import csv
import email
import email.policy
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime

# ----------------------------------------------------------------- reference data

FREE_WEBMAIL = {
    "gmail.com", "yahoo.com", "yahoo.co.uk", "outlook.com", "hotmail.com",
    "icloud.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "mail.com",
    "live.com", "msn.com", "ymail.com",
}

# Known Email Service Provider infrastructure (bounce / tracking domains).
# When auth PASSES and a mismatch is only against one of these, it's normal — not phishing.
ESP_INFRA = (
    "hubspotemail.net", "hs-sites.com", "hubspotlinks.com", "mktomail.com",
    "sendgrid.net", "sparkpostmail.com", "mailgun.org", "amazonses.com",
    "sendinblue.com", "sibautomation.com", "mcsv.net", "rsgsv.net", "mailchimp.com",
    "constantcontact.com", "cmail", "exacttarget.com", "mcdlv.net", "salesforce.com",
    "everestengagement.com", "transat.com", "veritaclaims.com", "insightsmr.org",
    "diginsights.com", "confirmit.ca", "decipherinc.com", "goldcast.io",
)

# Display-name words that, from a free-webmail sender, signal authority-impersonation (BEC).
AUTHORITY_WORDS = [
    "fbi", "cia", "irs", "bank", "imf", "director", "ceo", "cfo", "agent",
    "federal", "united nations", "government", "attorney", "police", "interpol",
    "minister", "president", "chairman", "governor", "treasury", "reserve",
    "monetary fund", "lottery", "inheritance", "beneficiary", "diplomat", "embassy",
    "settlement", "compensation", "fund",
]

# TLDs disproportionately used for throwaway malicious domains.
SUSPICIOUS_TLDS = {
    "club", "top", "vip", "xyz", "my", "online", "click", "link", "live", "buzz",
    "surf", "rest", "monster", "cfd", "sbs", "lol", "quest", "mom", "fun",
}

RISKY_ATTACH_RE = re.compile(
    r'\.(exe|scr|js|vbs|hta|jar|docm|xlsm|iso|lnk|cmd|bat|ps1|htm|html|zip|rar|7z)$',
    re.IGNORECASE)

URL_RE = re.compile(r'https?://[^\s"\'<>)\]]+', re.IGNORECASE)
IP_RE = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
PRIVATE_RE = re.compile(r'^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.)')


# ----------------------------------------------------------------- small helpers

def defang(s):
    return s.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def domain_of(url):
    m = re.match(r'https?://([^/:?#]+)', url, re.IGNORECASE)
    return m.group(1).lower() if m else ""


def addr_domain(header_value):
    if not header_value:
        return ""
    m = re.search(r'@([A-Za-z0-9.\-]+)', header_value)
    return m.group(1).lower() if m else ""


def tld_of(domain):
    return domain.rsplit(".", 1)[-1].lower() if "." in domain else ""


def is_esp(domain):
    return any(e in domain for e in ESP_INFRA)


def sha256_of(data):
    return hashlib.sha256(data).hexdigest()


# ----------------------------------------------------------------- parsing (from v1)

def get_auth_results(msg):
    verdict = {"spf": "not found", "dkim": "not found", "dmarc": "not found"}
    ar = " ".join(msg.get_all("Authentication-Results", []))
    ar += " " + " ".join(msg.get_all("ARC-Authentication-Results", []))
    for key in ("spf", "dkim", "dmarc"):
        m = re.search(rf'\b{key}=(\w+)', ar, re.IGNORECASE)
        if m:
            verdict[key] = m.group(1).lower()
    return verdict


def originating_ip(msg):
    for hop in reversed(msg.get_all("Received", [])):
        for ip in IP_RE.findall(hop):
            if not PRIVATE_RE.match(ip):
                return ip
    return ""


def extract_urls(msg):
    urls = set()
    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            try:
                body = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True)
                body = payload.decode(errors="replace") if payload else ""
            if isinstance(body, bytes):
                body = body.decode(errors="replace")
            for u in URL_RE.findall(body):
                urls.add(u.rstrip('.,;"\')'))
    return urls


def extract_attachments(msg):
    out = []
    for part in msg.walk():
        disp = (part.get_content_disposition() or "")
        filename = part.get_filename()
        if disp == "attachment" or filename:
            payload = part.get_payload(decode=True) or b""
            out.append({
                "filename": filename or "(unnamed)",
                "content_type": part.get_content_type(),
                "size": len(payload),
                "sha256": sha256_of(payload) if payload else "",
            })
    return out


# ----------------------------------------------------------------- classification

def classify(r):
    """Heuristic triage. Returns (verdict, reasons[]). Not ground truth — enrichment confirms."""
    reasons = []
    strong = False
    suspicious = False

    from_dom = r["from_domain"]
    reply_dom = addr_domain(r["reply_to"])
    rp_dom = addr_domain(r["return_path"])
    display = r["from"].lower()

    # --- strong (likely malicious) signals ---
    if r["dmarc"] == "fail":
        strong = True; reasons.append("DMARC fail (not legitimately from its domain)")
    if r["spf"] in ("fail", "softfail") and r["dmarc"] != "pass":
        strong = True; reasons.append(f"SPF {r['spf']} without DMARC pass")

    # authority impersonation from free webmail (BEC)
    if from_dom in FREE_WEBMAIL and any(w in display for w in AUTHORITY_WORDS):
        strong = True
        reasons.append("Free-webmail sender with authority/official display name (BEC pattern)")

    # reply hijack: Reply-To is personal webmail, different from sender
    if reply_dom in FREE_WEBMAIL and reply_dom != from_dom:
        strong = True
        reasons.append(f"Reply-To redirects to personal webmail ({reply_dom}) — reply-hijack")

    # risky executable-type attachment
    for a in r["attachments"]:
        if RISKY_ATTACH_RE.search(a["filename"]):
            strong = True; reasons.append(f"Risky attachment type: {a['filename']}")

    # --- suspicious signals ---
    if r["dmarc"] == "unknown":
        suspicious = True; reasons.append("DMARC could not be evaluated")
    bad_tld_links = sorted({d for d in r["link_domains"] if tld_of(d) in SUSPICIOUS_TLDS})
    if bad_tld_links:
        suspicious = True
        reasons.append("Links on throwaway TLDs: " + ", ".join(defang(d) for d in bad_tld_links))
    if r["attachments"] and not strong:
        suspicious = True
        reasons.append("Has attachment(s) to inspect: " +
                       ", ".join(a["filename"] for a in r["attachments"]))

    # mismatch that is NOT explained by a known ESP, and auth didn't fully pass
    if rp_dom and from_dom and rp_dom != from_dom and not (is_esp(rp_dom) or is_esp(from_dom)):
        if not (r["spf"] == "pass" and r["dkim"] == "pass" and r["dmarc"] == "pass"):
            suspicious = True
            reasons.append(f"Unexplained Return-Path mismatch ({rp_dom} vs {from_dom})")

    if strong:
        return "LIKELY MALICIOUS", reasons
    if suspicious:
        return "SUSPICIOUS", reasons
    if r["spf"] == "pass" and r["dkim"] == "pass" and r["dmarc"] == "pass":
        return "LIKELY BULK/BENIGN", reasons or ["Authenticated; no strong red flags"]
    return "REVIEW", reasons or ["No clear verdict — review manually"]


def analyze_file(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    r = {
        "file": os.path.basename(path),
        "from": str(msg.get("From", "")),
        "from_domain": addr_domain(str(msg.get("From", ""))),
        "return_path": str(msg.get("Return-Path", "")),
        "reply_to": str(msg.get("Reply-To", "")),
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "src_ip": originating_ip(msg),
        "urls": sorted(extract_urls(msg)),
        "attachments": extract_attachments(msg),
    }
    auth = get_auth_results(msg)
    r.update(spf=auth["spf"], dkim=auth["dkim"], dmarc=auth["dmarc"])
    r["link_domains"] = sorted({domain_of(u) for u in r["urls"] if domain_of(u)})
    r["verdict"], r["reasons"] = classify(r)
    return r


# ----------------------------------------------------------------- enrichment (APIs)

def load_env(path):
    keys = {}
    try:
        with open(path, encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    keys[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return keys


def http_json(url, headers, timeout=25):
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except Exception as e:
        return {"_error": str(e)}


class Enricher:
    def __init__(self, keys):
        self._vt_key = keys.get("VIRUSTOTAL_API_KEY", "").strip()
        self._abuse_key = keys.get("ABUSEIPDB_API_KEY", "").strip()
        self._urlscan_key = keys.get("URLSCAN_API_KEY", "").strip()
        self.cache = {}
        self._last_vt = 0.0

    def _vt_wait(self):
        # VirusTotal free tier: 4 lookups/minute -> >=15s apart
        elapsed = time.time() - self._last_vt
        if elapsed < 15:
            time.sleep(15 - elapsed)
        self._last_vt = time.time()

    def vt(self, kind, value):
        if not self._vt_key:
            return None
        ck = ("vt", kind, value)
        if ck in self.cache:
            return self.cache[ck]
        self._vt_wait()
        url = f"https://www.virustotal.com/api/v3/{kind}/{urllib.parse.quote(value, safe='')}"
        data = http_json(url, {"x-apikey": self._vt_key})
        stats = (data.get("data", {}).get("attributes", {}) or {}).get("last_analysis_stats")
        out = None
        if stats:
            out = {"malicious": stats.get("malicious", 0),
                   "suspicious": stats.get("suspicious", 0),
                   "harmless": stats.get("harmless", 0),
                   "undetected": stats.get("undetected", 0)}
        elif "_error" in data:
            out = {"error": data["_error"]}
        self.cache[ck] = out
        return out

    def abuseipdb(self, ip):
        if not self._abuse_key:
            return None
        ck = ("abuse", ip)
        if ck in self.cache:
            return self.cache[ck]
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        data = http_json(url, {"Key": self._abuse_key, "Accept": "application/json"})
        d = data.get("data")
        out = None
        if d:
            out = {"score": d.get("abuseConfidenceScore", 0),
                   "country": d.get("countryCode"),
                   "isp": d.get("isp"),
                   "reports": d.get("totalReports", 0),
                   "domain": d.get("domain")}
        elif "_error" in data:
            out = {"error": data["_error"]}
        self.cache[ck] = out
        return out

    def urlscan_search(self, domain):
        ck = ("us", domain)
        if ck in self.cache:
            return self.cache[ck]
        headers = {"API-Key": self._urlscan_key} if self._urlscan_key else {}
        url = f"https://urlscan.io/api/v1/search/?q=domain:{urllib.parse.quote(domain)}"
        data = http_json(url, headers)
        out = None
        if "results" in data:
            res = data["results"]
            out = {"count": data.get("total", len(res)),
                   "latest": res[0]["result"] if res else None}
        elif "_error" in data:
            out = {"error": data["_error"]}
        self.cache[ck] = out
        return out

    def enabled(self):
        return bool(self._vt_key or self._abuse_key or self._urlscan_key)


# ----------------------------------------------------------------- reporting

def vt_label(v):
    if not v:
        return "n/a"
    if "error" in v:
        return "lookup error"
    m, s = v["malicious"], v["suspicious"]
    total = m + s + v["harmless"] + v["undetected"]
    if m or s:
        return f"⚠️ {m} malicious / {s} suspicious of {total} engines"
    return f"clean ({total} engines)"


def write_reports(results, enr, outdir, enrich_on):
    os.makedirs(outdir, exist_ok=True)
    n = len(results)
    buckets = Counter(r["verdict"] for r in results)

    # gather indicators ONLY from suspicious/malicious emails
    focus = [r for r in results if r["verdict"] in ("LIKELY MALICIOUS", "SUSPICIOUS", "REVIEW")]
    domains, ips, hashes = {}, {}, {}
    for r in focus:
        for d in r["link_domains"]:
            domains.setdefault(d, 0)
            domains[d] += 1
        if r["src_ip"]:
            ips.setdefault(r["src_ip"], 0)
            ips[r["src_ip"]] += 1
        for a in r["attachments"]:
            if a["sha256"]:
                hashes[a["sha256"]] = a["filename"]

    # enrichment pass
    dom_enr, ip_enr, hash_enr = {}, {}, {}
    if enrich_on and enr.enabled():
        total = len(domains) + len(ips) + len(hashes)
        print(f"[*] Enriching {total} indicators from {len(focus)} suspicious/malicious emails...")
        for i, d in enumerate(sorted(domains), 1):
            print(f"    domain {i}/{len(domains)}: {d}")
            dom_enr[d] = {"vt": enr.vt("domains", d), "urlscan": enr.urlscan_search(d)}
        for i, ip in enumerate(sorted(ips), 1):
            print(f"    ip {i}/{len(ips)}: {ip}")
            ip_enr[ip] = {"vt": enr.vt("ip_addresses", ip), "abuse": enr.abuseipdb(ip)}
        for i, h in enumerate(sorted(hashes), 1):
            print(f"    hash {i}/{len(hashes)}: {h[:16]}...")
            hash_enr[h] = {"vt": enr.vt("files", h)}

    # ---- enriched IOC CSV
    with open(os.path.join(outdir, "iocs_enriched.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["type", "indicator_defanged", "seen_in", "vt_verdict", "extra"])
        for d, c in sorted(domains.items()):
            e = dom_enr.get(d, {})
            us = e.get("urlscan") or {}
            extra = f"urlscan prior scans: {us.get('count')}" if us and "count" in us else ""
            w.writerow(["domain", defang(d), c, vt_label(e.get("vt")), extra])
        for ip, c in sorted(ips.items()):
            e = ip_enr.get(ip, {})
            ab = e.get("abuse") or {}
            extra = ""
            if ab and "score" in ab:
                extra = f"AbuseIPDB {ab['score']}% ({ab.get('reports')} reports, {ab.get('country')}, {ab.get('isp')})"
            w.writerow(["src_ip", ip.replace(".", "[.]"), c, vt_label(e.get("vt")), extra])
        for h, fn in sorted(hashes.items()):
            e = hash_enr.get(h, {})
            w.writerow(["sha256", h, fn, vt_label(e.get("vt")), ""])

    # ---- markdown report
    md = []
    md.append("# Enriched Phishing Corpus Analysis\n")
    md.append(f"_Generated {datetime.now():%Y-%m-%d %H:%M} — {n} samples._\n")
    md.append("> Indicators are **defanged**. Static analysis only — no links opened, "
              "no attachments executed. Verdicts are heuristic triage confirmed by reputation enrichment.\n")

    md.append("\n## Triage summary\n")
    md.append("| Verdict | Count |")
    md.append("|---|---|")
    for v in ("LIKELY MALICIOUS", "SUSPICIOUS", "REVIEW", "LIKELY BULK/BENIGN"):
        if buckets.get(v):
            md.append(f"| {v} | {buckets[v]} |")

    md.append("\n## Enriched indicators (from suspicious/malicious mail only)\n")
    if ips:
        md.append("\n### Source IPs\n")
        md.append("| IP | Emails | VirusTotal | AbuseIPDB |")
        md.append("|---|---|---|---|")
        for ip, c in sorted(ips.items(), key=lambda x: -x[1]):
            e = ip_enr.get(ip, {})
            ab = e.get("abuse") or {}
            abs_ = (f"{ab.get('score')}% · {ab.get('reports')} reports · {ab.get('country')} · {ab.get('isp')}"
                    if ab and "score" in ab else "n/a")
            md.append(f"| `{ip.replace('.', '[.]')}` | {c} | {vt_label(e.get('vt'))} | {abs_} |")
    if domains:
        md.append("\n### Link domains\n")
        md.append("| Domain | Emails | VirusTotal | URLScan prior scans |")
        md.append("|---|---|---|---|")
        for d, c in sorted(domains.items(), key=lambda x: -x[1]):
            e = dom_enr.get(d, {})
            us = e.get("urlscan") or {}
            uss = str(us.get("count")) if us and "count" in us else "n/a"
            md.append(f"| `{defang(d)}` | {c} | {vt_label(e.get('vt'))} | {uss} |")
    if hashes:
        md.append("\n### Attachment hashes\n")
        md.append("| SHA-256 | File | VirusTotal |")
        md.append("|---|---|---|")
        for h, fn in hashes.items():
            e = hash_enr.get(h, {})
            md.append(f"| `{h}` | {fn} | {vt_label(e.get('vt'))} |")

    md.append("\n## Per-email verdicts\n")
    order = {"LIKELY MALICIOUS": 0, "SUSPICIOUS": 1, "REVIEW": 2, "LIKELY BULK/BENIGN": 3}
    for r in sorted(results, key=lambda x: order.get(x["verdict"], 9)):
        md.append(f"\n### [{r['verdict']}] {r['file']}\n")
        md.append(f"- **From:** `{r['from']}`")
        if r["reply_to"]:
            md.append(f"- **Reply-To:** `{r['reply_to']}`")
        md.append(f"- **Subject:** {r['subject']}")
        md.append(f"- **Auth:** SPF={r['spf']} · DKIM={r['dkim']} · DMARC={r['dmarc']}")
        md.append(f"- **Source IP:** `{r['src_ip'].replace('.', '[.]') or 'n/a'}`")
        if r["link_domains"]:
            md.append("- **Link domains:** " + ", ".join(f"`{defang(d)}`" for d in r["link_domains"]))
        if r["attachments"]:
            for a in r["attachments"]:
                md.append(f"- **Attachment:** `{a['filename']}` ({a['content_type']}, {a['size']} B) "
                          f"SHA-256 `{a['sha256'] or 'n/a'}`")
        md.append("- **Why:** " + "; ".join(r["reasons"]))

    with open(os.path.join(outdir, "report_enriched.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")

    return buckets, len(domains), len(ips), len(hashes)


# ----------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Enriched .eml phishing analyzer (read-only).")
    ap.add_argument("folder", help="folder of .eml files")
    ap.add_argument("-o", "--outdir", default="output")
    ap.add_argument("--env", default="secrets/.env", help="path to API-keys file")
    ap.add_argument("--no-enrich", action="store_true", help="skip all API lookups")
    args = ap.parse_args()

    if not os.path.isdir(args.folder):
        sys.exit(f"[!] Not a folder: {args.folder}")
    files = [os.path.join(args.folder, f) for f in sorted(os.listdir(args.folder))
             if f.lower().endswith(".eml")]
    if not files:
        sys.exit(f"[!] No .eml files in {args.folder}")

    keys = load_env(args.env)
    enr = Enricher(keys)
    enrich_on = not args.no_enrich
    if enrich_on and not enr.enabled():
        print(f"[!] No API keys found in {args.env} — running WITHOUT enrichment.")
        print(f"    (Add keys to {args.env} or pass --no-enrich to silence this.)")
        enrich_on = False

    print(f"[*] Analyzing {len(files)} email(s)...\n")
    results = []
    for p in files:
        try:
            r = analyze_file(p)
            results.append(r)
            print(f"  [{r['verdict']:<18}] {r['file']}")
        except Exception as e:
            print(f"  [!] Failed on {os.path.basename(p)}: {e}")

    print()
    buckets, nd, nip, nh = write_reports(results, enr, args.outdir, enrich_on)
    print(f"[+] Done. Verdicts: " + ", ".join(f"{k}={v}" for k, v in buckets.items()))
    print(f"[+] Enriched {nd} domains, {nip} IPs, {nh} hashes (from suspicious/malicious mail).")
    print(f"[+] Reports in {args.outdir}/ : report_enriched.md, iocs_enriched.csv")


if __name__ == "__main__":
    main()
