#!/usr/bin/env python3
r"""
inspect_attachments.py  -  Safely extract and STATICALLY inspect .eml attachments.

For each .eml it:
  1. Extracts every attachment to an output folder (default: malware/).
  2. Checks the TRUE file type from magic bytes vs the claimed extension
     (catches extension spoofing — a huge red flag).
  3. Pulls strings and from them any URLs, emails, IPs, phone numbers
     (callback/vishing lures hide a phone number inside an image).
  4. For PDFs: flags risky structures (/JavaScript, /OpenAction, /Launch,
     /EmbeddedFile, /URI...) and extracts link targets.
  5. For BMP/images: reports dimensions and any appended "overlay" data.

READ-ONLY and SAFE: it only reads bytes. It NEVER opens or executes anything.
Standard library only.

Usage:
    python inspect_attachments.py samples\DuBuque.eml --out malware\
    python inspect_attachments.py samples\ --out malware\        (whole folder)

⚠️ Extracted files may be live malware. Do NOT double-click them. This script
   does not run them; neither should you.
"""

import argparse
import email
import email.policy
import hashlib
import os
import re
import struct
import sys

# ------------------------------------------------- magic-byte signatures

MAGIC = [
    (b"%PDF",            "PDF document"),
    (b"BM",              "BMP image"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff",    "JPEG image"),
    (b"GIF8",            "GIF image"),
    (b"PK\x03\x04",      "ZIP / Office-OOXML / JAR"),
    (b"\xd0\xcf\x11\xe0", "OLE (legacy Office doc/xls)"),
    (b"\x7fELF",         "ELF executable (Linux)"),
    (b"MZ",              "PE executable (Windows .exe/.dll)"),
    (b"{\\rtf",          "RTF document"),
    (b"Rar!",            "RAR archive"),
    (b"7z\xbc\xaf",      "7-Zip archive"),
    (b"\x1f\x8b",        "GZIP archive"),
]

EXT_FOR_TYPE = {
    "PDF document": {"pdf"},
    "BMP image": {"bmp", "dib"},
    "PNG image": {"png"},
    "JPEG image": {"jpg", "jpeg"},
    "GIF image": {"gif"},
    "ZIP / Office-OOXML / JAR": {"zip", "docx", "xlsx", "pptx", "jar"},
    "OLE (legacy Office doc/xls)": {"doc", "xls", "ppt", "msg"},
    "PE executable (Windows .exe/.dll)": {"exe", "dll", "scr"},
    "RTF document": {"rtf"},
    "RAR archive": {"rar"},
    "7-Zip archive": {"7z"},
}

PDF_RISKY = [b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch",
             b"/EmbeddedFile", b"/URI", b"/SubmitForm", b"/GoToR",
             b"/RichMedia", b"/XFA"]

URL_RE = re.compile(r'https?://[^\s"\'<>)\]}]+', re.IGNORECASE)
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
PHONE_RE = re.compile(r'(?<!\d)(?:\+?\d[\d\s().\-]{7,}\d)(?!\d)')
PDF_URI_RE = re.compile(rb'/URI\s*\(([^)]{1,300}?)\)')


def defang(s):
    return s.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def sanitize(name):
    name = os.path.basename(name or "unnamed")
    return re.sub(r'[^A-Za-z0-9._\- ]', "_", name).strip() or "unnamed"


def magic_type(data):
    for sig, label in MAGIC:
        if data.startswith(sig):
            return label
    return "unknown / not a known type"


def extract_strings(data, min_len=4):
    out = []
    for m in re.findall(rb'[\x20-\x7e]{%d,}' % min_len, data):
        out.append(m.decode("ascii", "replace"))
    for m in re.findall(rb'(?:[\x20-\x7e]\x00){%d,}' % min_len, data):
        out.append(m.decode("utf-16-le", "replace"))
    return out


def iocs_from_strings(strings):
    blob = "\n".join(strings)
    urls = {u.rstrip('.,);"\'') for u in URL_RE.findall(blob)}
    emails = set(EMAIL_RE.findall(blob))
    ips = {ip for ip in IP_RE.findall(blob)
           if not ip.startswith(("0.", "127.", "255.")) and ip.count(".") == 3}
    phones = {p.strip() for p in PHONE_RE.findall(blob)
              if sum(c.isdigit() for c in p) >= 9}      # >=9 digits to cut noise
    return {"urls": urls, "emails": emails, "ips": ips, "phones": phones}


def analyze_pdf(data):
    found = {}
    for kw in PDF_RISKY:
        c = data.count(kw)
        if c:
            found[kw.decode()] = c
    uris = {u.decode("latin-1", "replace") for u in PDF_URI_RE.findall(data)}
    return found, uris


def analyze_bmp(data):
    info = {}
    try:
        file_size = struct.unpack_from("<I", data, 2)[0]       # header-declared size
        pix_offset = struct.unpack_from("<I", data, 10)[0]
        width = struct.unpack_from("<i", data, 18)[0]
        height = struct.unpack_from("<i", data, 22)[0]
        info["dimensions"] = f"{width} x {abs(height)} px"
        info["declared_size"] = file_size
        info["actual_size"] = len(data)
        info["pixel_offset"] = pix_offset
        overlay = len(data) - file_size
        if file_size and 0 < overlay:
            info["overlay_bytes"] = overlay            # data appended past the image
    except Exception as e:
        info["parse_error"] = str(e)
    return info


def process_attachment(filename, data, outdir, idx):
    sha = hashlib.sha256(data).hexdigest()
    safe = f"{idx:02d}_{sanitize(filename)}"
    path = os.path.join(outdir, safe)
    with open(path, "wb") as f:
        f.write(data)

    claimed_ext = (filename.rsplit(".", 1)[-1].lower() if "." in (filename or "") else "")
    real = magic_type(data)
    spoofed = (real in EXT_FOR_TYPE and claimed_ext and
               claimed_ext not in EXT_FOR_TYPE[real])

    print(f"\n  ── Attachment: {filename}")
    print(f"     saved as     : {path}")
    print(f"     size         : {len(data):,} bytes")
    print(f"     SHA-256      : {sha}")
    print(f"     claimed ext  : .{claimed_ext or '(none)'}")
    print(f"     TRUE type    : {real}")
    if spoofed:
        print(f"     🚩 EXTENSION SPOOF: file is really {real}, not .{claimed_ext}!")

    if real == "PDF document":
        risky, uris = analyze_pdf(data)
        if risky:
            print("     🚩 PDF active-content markers: " +
                  ", ".join(f"{k}×{v}" for k, v in risky.items()))
        else:
            print("     PDF: no active-content markers found")
        if uris:
            print("     PDF link targets:")
            for u in sorted(uris):
                print(f"        - {defang(u)}")

    if real == "BMP image":
        info = analyze_bmp(data)
        print(f"     BMP info     : {info.get('dimensions','?')}, "
              f"declared {info.get('declared_size','?')} / actual {info.get('actual_size','?')} bytes")
        if info.get("overlay_bytes"):
            print(f"     🚩 OVERLAY: {info['overlay_bytes']:,} bytes appended after the image "
                  f"(possible hidden payload)")

    strings = extract_strings(data)
    iocs = iocs_from_strings(strings)
    for label, key in (("URLs", "urls"), ("Emails", "emails"),
                       ("IPs", "ips"), ("Phone numbers", "phones")):
        if iocs[key]:
            shown = sorted(iocs[key])[:15]
            pretty = [defang(x) if key in ("urls",) else x for x in shown]
            print(f"     {label} in file: " + "; ".join(pretty) +
                  (f"  (+{len(iocs[key])-15} more)" if len(iocs[key]) > 15 else ""))
    return sha


def process_eml(path, outdir):
    print(f"\n=== {os.path.basename(path)} ===")
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)
    idx = 0
    any_att = False
    for part in msg.walk():
        disp = (part.get_content_disposition() or "")
        fn = part.get_filename()
        if disp == "attachment" or fn:
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            idx += 1
            any_att = True
            process_attachment(fn or f"part{idx}", payload, outdir, idx)
    if not any_att:
        print("  (no attachments found)")


def main():
    ap = argparse.ArgumentParser(description="Extract + statically inspect .eml attachments (read-only).")
    ap.add_argument("target", help="a .eml file or a folder of them")
    ap.add_argument("--out", default="malware", help="where to save extracted attachments")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    if os.path.isdir(args.target):
        files = [os.path.join(args.target, f) for f in sorted(os.listdir(args.target))
                 if f.lower().endswith(".eml")]
    elif os.path.isfile(args.target):
        files = [args.target]
    else:
        sys.exit(f"[!] Not found: {args.target}")

    if not files:
        sys.exit("[!] No .eml files found.")

    print("⚠️  Extracted files may be live malware — do NOT open them. This tool only reads bytes.")
    for p in files:
        try:
            process_eml(p, args.out)
        except Exception as e:
            print(f"  [!] Failed on {os.path.basename(p)}: {e}")
    print(f"\n[+] Done. Extracted attachments are in: {args.out}\\  (git-ignored)")


if __name__ == "__main__":
    main()
