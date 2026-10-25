#!/usr/bin/env python3
"""
Email Risk Analyzer
--------------------
Scans raw email files (.eml) for phishing indicators and spoofing signs:
  - Parses headers (Received, Return-Path, SPF, DKIM/DMARC results)
  - Scans body text for suspicious links, domain spoofing, and urgency language
  - Assigns a phishing-likelihood risk score
  - Generates a plain-text email security audit report

Usage:
    python email_analyzer.py -f sample_phishing.eml
    python email_analyzer.py -f sample_legit.eml
    python email_analyzer.py -d sample_emails/          # scan a whole folder

Author: <your name>
"""

import argparse
import email
import os
import re
import sys
from email import policy
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Step 2 (body scan): suspicious keyword / urgency lure patterns
# ---------------------------------------------------------------------------
URGENCY_PHRASES = [
    "verify your account", "act now", "urgent action required",
    "your account will be suspended", "confirm your identity",
    "click here immediately", "limited time", "unusual activity detected",
    "your account has been locked", "password will expire",
    "final notice", "avoid suspension", "update your payment",
]

SUSPICIOUS_TLDS = {".zip", ".mov", ".xyz", ".top", ".click", ".fit", ".link"}


# ---------------------------------------------------------------------------
# Step 1: parse raw email headers (Received, Return-Path, SPF, DKIM)
# ---------------------------------------------------------------------------
def load_email(path: str):
    with open(path, "rb") as f:
        return email.message_from_binary_file(f, policy=policy.default)


def extract_header_info(msg) -> dict:
    from_header = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    reply_to = msg.get("Reply-To", "")
    received = msg.get_all("Received", [])
    auth_results = msg.get("Authentication-Results", "")

    spf_result = _extract_auth_field(auth_results, "spf")
    dkim_result = _extract_auth_field(auth_results, "dkim")
    dmarc_result = _extract_auth_field(auth_results, "dmarc")

    return {
        "from": from_header,
        "return_path": return_path,
        "reply_to": reply_to,
        "received_hops": len(received),
        "spf": spf_result,
        "dkim": dkim_result,
        "dmarc": dmarc_result,
    }


def _extract_auth_field(auth_results: str, field: str) -> str:
    """Pull e.g. 'spf=fail' out of an Authentication-Results header."""
    match = re.search(rf"{field}=(\w+)", auth_results, re.IGNORECASE)
    return match.group(1).lower() if match else "none"


def extract_domain(address: str) -> str:
    match = re.search(r"@([\w\.-]+)", address)
    return match.group(1).lower() if match else ""


def check_from_reply_mismatch(headers: dict) -> bool:
    """Flag when Reply-To domain differs from From domain — a classic spoof sign."""
    from_domain = extract_domain(headers["from"])
    reply_domain = extract_domain(headers["reply_to"])
    return bool(reply_domain) and reply_domain != from_domain


def check_from_returnpath_mismatch(headers: dict) -> bool:
    from_domain = extract_domain(headers["from"])
    rp_domain = extract_domain(headers["return_path"])
    return bool(rp_domain) and rp_domain != from_domain


# ---------------------------------------------------------------------------
# Step 2: scan body text for suspicious links, domain spoofing, urgency
# ---------------------------------------------------------------------------
def get_body_text(msg) -> str:
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    parts.append(part.get_content())
                except Exception:
                    pass
        return "\n".join(parts)
    try:
        return msg.get_content()
    except Exception:
        return ""


def find_urls(body: str) -> list:
    return re.findall(r"https?://[^\s\"'>)]+", body)


def analyze_links(urls: list) -> list:
    """Flag IP-based URLs, suspicious TLDs, or use of a URL shortener."""
    flags = []
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"}
    for url in urls:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            flags.append(f"IP-address link (not a domain): {url}")
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            flags.append(f"Suspicious top-level domain: {url}")
        if host in shorteners:
            flags.append(f"URL shortener obscuring destination: {url}")
    return flags


def find_urgency_language(body: str) -> list:
    body_lower = body.lower()
    return [phrase for phrase in URGENCY_PHRASES if phrase in body_lower]


# ---------------------------------------------------------------------------
# Step 3: assign a risk score indicating phishing likelihood
# ---------------------------------------------------------------------------
def calculate_risk_score(headers: dict, link_flags: list, urgency_hits: list,
                          reply_mismatch: bool, rp_mismatch: bool) -> int:
    score = 0
    if headers["spf"] == "fail":
        score += 25
    elif headers["spf"] == "softfail":
        score += 10
    if headers["dkim"] == "fail":
        score += 25
    if headers["dmarc"] == "fail":
        score += 15
    if reply_mismatch:
        score += 15
    if rp_mismatch:
        score += 10
    score += min(len(link_flags) * 10, 30)
    score += min(len(urgency_hits) * 5, 20)
    return min(score, 100)


def classify_risk(score: int) -> str:
    if score >= 70:
        return "HIGH RISK — likely phishing"
    elif score >= 35:
        return "MEDIUM RISK — suspicious, review manually"
    else:
        return "LOW RISK — no strong phishing indicators"


# ---------------------------------------------------------------------------
# Step 4: generate an email security audit report
# ---------------------------------------------------------------------------
def analyze_email(path: str) -> dict:
    msg = load_email(path)
    headers = extract_header_info(msg)
    body = get_body_text(msg)

    urls = find_urls(body)
    link_flags = analyze_links(urls)
    urgency_hits = find_urgency_language(body)
    reply_mismatch = check_from_reply_mismatch(headers)
    rp_mismatch = check_from_returnpath_mismatch(headers)

    score = calculate_risk_score(headers, link_flags, urgency_hits, reply_mismatch, rp_mismatch)
    verdict = classify_risk(score)

    return {
        "file": os.path.basename(path),
        "subject": msg.get("Subject", "(no subject)"),
        "from": headers["from"],
        "headers": headers,
        "reply_mismatch": reply_mismatch,
        "rp_mismatch": rp_mismatch,
        "urls_found": len(urls),
        "link_flags": link_flags,
        "urgency_hits": urgency_hits,
        "score": score,
        "verdict": verdict,
    }


def print_report(result: dict) -> None:
    print("=" * 62)
    print(f"File           : {result['file']}")
    print(f"Subject        : {result['subject']}")
    print(f"From           : {result['from']}")
    print("-" * 62)
    print("Header Authentication:")
    print(f"  SPF   : {result['headers']['spf']}")
    print(f"  DKIM  : {result['headers']['dkim']}")
    print(f"  DMARC : {result['headers']['dmarc']}")
    print(f"  Reply-To domain mismatch   : {'YES' if result['reply_mismatch'] else 'No'}")
    print(f"  Return-Path domain mismatch: {'YES' if result['rp_mismatch'] else 'No'}")
    print("-" * 62)
    print(f"URLs found in body: {result['urls_found']}")
    if result["link_flags"]:
        print("Link flags:")
        for f in result["link_flags"]:
            print(f"  * {f}")
    else:
        print("Link flags: none")
    print("-" * 62)
    if result["urgency_hits"]:
        print("Urgency / pressure language detected:")
        for phrase in result["urgency_hits"]:
            print(f"  * \"{phrase}\"")
    else:
        print("Urgency / pressure language detected: none")
    print("-" * 62)
    print(f"RISK SCORE : {result['score']} / 100")
    print(f"VERDICT    : {result['verdict']}")
    print("=" * 62 + "\n")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Email Risk Analyzer — phishing indicator scanner")
    parser.add_argument("-f", "--file", help="Path to a single .eml file")
    parser.add_argument("-d", "--dir", help="Path to a folder of .eml files")
    args = parser.parse_args()

    files = []
    if args.file:
        files = [args.file]
    elif args.dir:
        files = [os.path.join(args.dir, f) for f in sorted(os.listdir(args.dir))
                 if f.lower().endswith(".eml")]
    else:
        print("Error: provide -f <file.eml> or -d <folder>")
        sys.exit(1)

    for path in files:
        if not os.path.exists(path):
            print(f"Error: file not found: {path}")
            continue
        result = analyze_email(path)
        print_report(result)


if __name__ == "__main__":
    main()
