# Email Risk Analyzer

A Python script that scans raw email files (`.eml`) for phishing indicators
and spoofing signs, then produces a risk score and a PDF audit report.

## Objective

Identify phishing vectors, suspicious SPF/DKIM/DMARC authentication
results, and urgent "lure" language commonly used in phishing emails.

## How it works

1. **Header parsing** — reads `From`, `Reply-To`, `Return-Path`, `Received`,
   and `Authentication-Results` headers; extracts SPF/DKIM/DMARC pass/fail
   status and flags sender/reply-to/return-path domain mismatches.
2. **Body scanning** — extracts all URLs from the email body and flags:
   - IP-address links instead of domain names
   - suspicious top-level domains (`.zip`, `.xyz`, `.top`, etc.)
   - URL shorteners that obscure the real destination
   It also scans for common urgency/pressure phrases used in social
   engineering ("verify your account", "act now", "final notice", etc.).
3. **Risk scoring** — combines all signals into a 0–100 score and a
   verdict: LOW / MEDIUM / HIGH RISK.
4. **Audit report** — `generate_report.py` runs the analyzer over a folder
   of sample emails and produces `Phishing_Analysis_Report.pdf` with a
   summary table and per-email detailed findings.

## Usage

```bash
# Analyze a single email
python email_analyzer.py -f sample_emails/sample_phishing.eml

# Analyze every .eml file in a folder
python email_analyzer.py -d sample_emails/

# Generate the PDF report (scans sample_emails/ automatically)
python generate_report.py
```

## Example output (console)

```
==============================================================
File           : sample_phishing.eml
Subject        : Urgent Action Required: Verify Your Account Now
From           : Account Security <security@examplebank-alerts.com>
--------------------------------------------------------------
Header Authentication:
  SPF   : fail
  DKIM  : fail
  DMARC : fail
  Reply-To domain mismatch   : YES
  Return-Path domain mismatch: YES
--------------------------------------------------------------
URLs found in body: 2
Link flags:
  * IP-address link (not a domain): http://192.0.2.44/verify-account
  * URL shortener obscuring destination: http://bit.ly/acct-verify-now
--------------------------------------------------------------
Urgency / pressure language detected:
  * "act now"
  * "confirm your identity"
  * "final notice"
  * "avoid suspension"
--------------------------------------------------------------
RISK SCORE : 100 / 100
VERDICT    : HIGH RISK — likely phishing
==============================================================
```

## Project structure

```
email-risk-analyzer/
├── email_analyzer.py          # main analyzer (headers + body + scoring)
├── generate_report.py         # builds the PDF audit report
├── sample_emails/
│   ├── sample_phishing.eml    # synthetic phishing example (fictional domains)
│   └── sample_legit.eml       # synthetic legitimate example
├── Phishing_Analysis_Report.pdf
└── README.md
```

## Notes

- Sample `.eml` files use entirely fictional domains and example/reserved
  IP ranges (`192.0.2.x`, `.example.com`) — no real organizations or
  addresses are referenced.
- Risk scoring weights are heuristic (as in a typical student/portfolio
  project) and intended to demonstrate the detection approach, not to
  replace a production-grade email security gateway.
