#!/usr/bin/env python3
"""
analyze_phish.py  -  Batch phishing email (.eml) analyzer for SOC triage.

Parses a folder of .eml files and extracts, per email:
  - Sender identity (From, Return-Path, Reply-To) and alignment mismatches
  - Subject, Date
  - Received-chain hops and originating IP
  - SPF / DKIM / DMARC verdicts (read from the receiver's Authentication-Results)
  - URLs and unique domains (defanged), flagged for display-vs-href mismatch
  - Attachments (filename, type, size, SHA-256)

Then writes an AGGREGATE report across all samples:
  - summary table of every email
  - consolidated IOC lists (domains, URLs, sender IPs, attachment hashes)
  - auth-failure statistics and top senders

Standard library only. Read-only: it never opens links or executes attachments.
Usage:
    python analyze_phish.py samples/ -o output/
"""

import argparse
import csv
import email
import email.policy
import hashlib
import os
import re
import sys
from collections import Counter
from datetime import datetime

# ----------------------------------------------------------------------------- helpers

URL_RE = re.compile(r'https?://[^\s"\'<>)\]]+', re.IGNORECASE)
IP_RE = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
# private / local ranges we ignore when picking the "originating" public IP
PRIVATE_RE = re.compile(r'^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.)')


def defang(s: str) -> str:
    """Make a URL/domain unclickable for safe reporting."""
    return s.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def domain_of(url: str) -> str:
    m = re.match(r'https?://([^/:?#]+)', url, re.IGNORECASE)
    return m.group(1).lower() if m else ""


def addr_domain(header_value: str) -> str:
    """Pull the domain out of an address header like 'Name <a@b.com>'."""
    if not header_value:
        return ""
    m = re.search(r'@([A-Za-z0-9.\-]+)', header_value)
    return m.group(1).lower() if m else ""


def get_auth_results(msg) -> dict:
    """Read SPF/DKIM/DMARC verdicts from Authentication-Results headers."""
    verdict = {"spf": "not found", "dkim": "not found", "dmarc": "not found"}
    ar = " ".join(msg.get_all("Authentication-Results", []))
    ar += " " + " ".join(msg.get_all("ARC-Authentication-Results", []))
    for key in ("spf", "dkim", "dmarc"):
        m = re.search(rf'{key}=(\w+)', ar, re.IGNORECASE)
        if m:
            verdict[key] = m.group(1).lower()
    return verdict


def originating_ip(msg) -> str:
    """Walk the Received chain; return the earliest public IP seen (the source)."""
    received = msg.get_all("Received", [])
    # Received headers are listed newest-first; the originating hop is last.
    for hop in reversed(received):
        for ip in IP_RE.findall(hop):
            if not PRIVATE_RE.match(ip):
                return ip
    return ""


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_urls(msg):
    """Collect URLs from every text/html and text/plain part."""
    urls = set()
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype in ("text/plain", "text/html"):
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


# ----------------------------------------------------------------------------- per-file analysis

def analyze_file(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    from_hdr = str(msg.get("From", ""))
    return_path = str(msg.get("Return-Path", ""))
    reply_to = str(msg.get("Reply-To", ""))
    subject = str(msg.get("Subject", ""))
    date = str(msg.get("Date", ""))

    from_dom = addr_domain(from_hdr)
    rp_dom = addr_domain(return_path)
    reply_dom = addr_domain(reply_to)

    auth = get_auth_results(msg)
    src_ip = originating_ip(msg)
    urls = extract_urls(msg)
    attachments = extract_attachments(msg)

    # red flags
    flags = []
    if rp_dom and from_dom and rp_dom != from_dom:
        flags.append(f"Return-Path domain ({rp_dom}) != From domain ({from_dom})")
    if reply_dom and from_dom and reply_dom != from_dom:
        flags.append(f"Reply-To domain ({reply_dom}) != From domain ({from_dom})")
    if auth["spf"] in ("fail", "softfail", "none"):
        flags.append(f"SPF {auth['spf']}")
    if auth["dkim"] in ("fail", "none"):
        flags.append(f"DKIM {auth['dkim']}")
    if auth["dmarc"] in ("fail", "none"):
        flags.append(f"DMARC {auth['dmarc']}")
    link_domains = {domain_of(u) for u in urls if domain_of(u)}
    off_domain_links = {d for d in link_domains if from_dom and from_dom not in d and d not in from_dom}
    if off_domain_links:
        flags.append(f"Links point to {len(off_domain_links)} domain(s) different from sender")
    for a in attachments:
        if re.search(r'\.(exe|scr|js|vbs|hta|jar|docm|xlsm|zip|rar|7z|iso|lnk|html?)$',
                     a["filename"], re.IGNORECASE):
            flags.append(f"Risky attachment: {a['filename']}")

    return {
        "file": os.path.basename(path),
        "from": from_hdr,
        "from_domain": from_dom,
        "return_path": return_path,
        "reply_to": reply_to,
        "subject": subject,
        "date": date,
        "src_ip": src_ip,
        "spf": auth["spf"],
        "dkim": auth["dkim"],
        "dmarc": auth["dmarc"],
        "urls": sorted(urls),
        "link_domains": sorted(link_domains),
        "attachments": attachments,
        "flags": flags,
    }


# ----------------------------------------------------------------------------- reporting

def write_reports(results, outdir):
    os.makedirs(outdir, exist_ok=True)

    # ---- aggregate IOCs
    all_domains = Counter()
    all_urls = set()
    all_ips = Counter()
    all_hashes = {}  # sha -> filename
    sender_domains = Counter()
    auth_fail = {"spf": 0, "dkim": 0, "dmarc": 0}

    for r in results:
        sender_domains[r["from_domain"]] += 1 if r["from_domain"] else 0
        if r["src_ip"]:
            all_ips[r["src_ip"]] += 1
        for d in r["link_domains"]:
            all_domains[d] += 1
        for u in r["urls"]:
            all_urls.add(u)
        for a in r["attachments"]:
            if a["sha256"]:
                all_hashes[a["sha256"]] = a["filename"]
        for k in auth_fail:
            if r[k] in ("fail", "softfail", "none", "not found"):
                auth_fail[k] += 1

    n = len(results)

    # ---- summary CSV
    with open(os.path.join(outdir, "summary.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["file", "from_domain", "subject", "src_ip", "spf", "dkim",
                    "dmarc", "num_urls", "num_attachments", "num_flags"])
        for r in results:
            w.writerow([r["file"], r["from_domain"], r["subject"][:60], r["src_ip"],
                        r["spf"], r["dkim"], r["dmarc"], len(r["urls"]),
                        len(r["attachments"]), len(r["flags"])])

    # ---- IOC CSV
    with open(os.path.join(outdir, "iocs.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["type", "indicator_defanged", "count_or_source"])
        for d, c in all_domains.most_common():
            w.writerow(["domain", defang(d), c])
        for ip, c in all_ips.most_common():
            w.writerow(["src_ip", ip.replace(".", "[.]"), c])
        for sha, fn in all_hashes.items():
            w.writerow(["sha256", sha, fn])
        for u in sorted(all_urls):
            w.writerow(["url", defang(u), ""])

    # ---- Markdown report
    md = []
    md.append("# Phishing Corpus Analysis\n")
    md.append(f"_Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} — {n} samples analyzed._\n")
    md.append("> All indicators are **defanged** for safe handling. No links were opened "
              "and no attachments were executed; analysis is static only.\n")

    md.append("\n## Aggregate findings\n")
    md.append(f"- **Samples analyzed:** {n}")
    if n:
        md.append(f"- **SPF not passing:** {auth_fail['spf']}/{n} "
                  f"({100*auth_fail['spf']//n}%)")
        md.append(f"- **DKIM not passing:** {auth_fail['dkim']}/{n} "
                  f"({100*auth_fail['dkim']//n}%)")
        md.append(f"- **DMARC not passing:** {auth_fail['dmarc']}/{n} "
                  f"({100*auth_fail['dmarc']//n}%)")
    md.append(f"- **Unique malicious/link domains:** {len(all_domains)}")
    md.append(f"- **Unique sender source IPs:** {len(all_ips)}")
    md.append(f"- **Unique attachment hashes:** {len(all_hashes)}")

    if all_domains:
        md.append("\n### Top link domains (defanged)\n")
        md.append("| Domain | Seen in # emails |")
        md.append("|---|---|")
        for d, c in all_domains.most_common(15):
            md.append(f"| `{defang(d)}` | {c} |")

    if all_ips:
        md.append("\n### Sender source IPs\n")
        md.append("| IP | Emails |")
        md.append("|---|---|")
        for ip, c in all_ips.most_common(15):
            md.append(f"| `{ip.replace('.', '[.]')}` | {c} |")

    if all_hashes:
        md.append("\n### Attachment hashes (SHA-256)\n")
        md.append("| SHA-256 | Filename |")
        md.append("|---|---|")
        for sha, fn in all_hashes.items():
            md.append(f"| `{sha}` | {fn} |")

    md.append("\n## Per-email breakdown\n")
    for r in results:
        md.append(f"\n### {r['file']}\n")
        md.append(f"- **From:** `{r['from']}`")
        md.append(f"- **Subject:** {r['subject']}")
        md.append(f"- **Date:** {r['date']}")
        md.append(f"- **Source IP:** `{r['src_ip'].replace('.', '[.]') or 'n/a'}`")
        md.append(f"- **SPF:** {r['spf']}  |  **DKIM:** {r['dkim']}  |  **DMARC:** {r['dmarc']}")
        if r["return_path"]:
            md.append(f"- **Return-Path:** `{r['return_path']}`")
        if r["reply_to"]:
            md.append(f"- **Reply-To:** `{r['reply_to']}`")
        if r["link_domains"]:
            md.append(f"- **Link domains:** " + ", ".join(f"`{defang(d)}`" for d in r["link_domains"]))
        if r["attachments"]:
            md.append("- **Attachments:**")
            for a in r["attachments"]:
                md.append(f"    - `{a['filename']}` ({a['content_type']}, {a['size']} B) "
                          f"SHA-256 `{a['sha256'] or 'n/a'}`")
        if r["flags"]:
            md.append("- **🚩 Red flags:**")
            for fl in r["flags"]:
                md.append(f"    - {fl}")
        else:
            md.append("- No automated red flags (review manually).")

    with open(os.path.join(outdir, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")

    return n, len(all_domains), len(all_ips), len(all_hashes)


# ----------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Batch .eml phishing analyzer (read-only).")
    ap.add_argument("folder", help="folder containing .eml files")
    ap.add_argument("-o", "--outdir", default="output", help="output folder (default: output)")
    args = ap.parse_args()

    if not os.path.isdir(args.folder):
        sys.exit(f"[!] Not a folder: {args.folder}")

    files = [os.path.join(args.folder, f) for f in sorted(os.listdir(args.folder))
             if f.lower().endswith(".eml")]
    if not files:
        sys.exit(f"[!] No .eml files found in {args.folder}")

    print(f"[*] Analyzing {len(files)} email(s)...\n")
    results = []
    for p in files:
        try:
            r = analyze_file(p)
            results.append(r)
            flag = f"{len(r['flags'])} flag(s)" if r["flags"] else "clean-looking"
            print(f"  - {r['file']:<30} SPF={r['spf']:<9} DKIM={r['dkim']:<9} "
                  f"DMARC={r['dmarc']:<9} {flag}")
        except Exception as e:
            print(f"  [!] Failed on {os.path.basename(p)}: {e}")

    n, nd, nip, nh = write_reports(results, args.outdir)
    print(f"\n[+] Done. {n} analyzed.")
    print(f"    {nd} link domains, {nip} source IPs, {nh} attachment hashes extracted.")
    print(f"[+] Reports written to: {args.outdir}/")
    print(f"      report.md    (full write-up)")
    print(f"      summary.csv  (one row per email)")
    print(f"      iocs.csv     (consolidated indicators, defanged)")


if __name__ == "__main__":
    main()
