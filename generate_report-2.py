#!/usr/bin/env python3
"""Generates the Phishing Analysis Report PDF from the sample email scans."""

import os
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.units import inch
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, PageBreak)
from reportlab.lib import colors

from email_analyzer import analyze_email

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "sample_emails")
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "Phishing_Analysis_Report.pdf")

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="ReportBody", parent=styles["Normal"],
                           fontSize=10, leading=14, alignment=TA_LEFT, spaceAfter=6))
styles.add(ParagraphStyle(name="SectionHead", parent=styles["Heading2"],
                           spaceBefore=14, spaceAfter=6))
styles.add(ParagraphStyle(name="VerdictHigh", parent=styles["Normal"],
                           fontSize=12, textColor=colors.HexColor("#b00020"), spaceAfter=6))
styles.add(ParagraphStyle(name="VerdictLow", parent=styles["Normal"],
                           fontSize=12, textColor=colors.HexColor("#1b7a1b"), spaceAfter=6))


def build_email_section(result: dict, story: list):
    story.append(Paragraph(f"Email File: {result['file']}", styles["SectionHead"]))
    story.append(Paragraph(f"<b>Subject:</b> {result['subject']}", styles["ReportBody"]))
    story.append(Paragraph(f"<b>From:</b> {result['from']}", styles["ReportBody"]))

    auth_data = [
        ["Check", "Result"],
        ["SPF", result["headers"]["spf"]],
        ["DKIM", result["headers"]["dkim"]],
        ["DMARC", result["headers"]["dmarc"]],
        ["Reply-To domain mismatch", "YES" if result["reply_mismatch"] else "No"],
        ["Return-Path domain mismatch", "YES" if result["rp_mismatch"] else "No"],
    ]
    table = Table(auth_data, colWidths=[2.6 * inch, 2.6 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(Spacer(1, 6))
    story.append(table)
    story.append(Spacer(1, 8))

    story.append(Paragraph(f"<b>URLs found in body:</b> {result['urls_found']}", styles["ReportBody"]))
    if result["link_flags"]:
        story.append(Paragraph("<b>Link flags:</b>", styles["ReportBody"]))
        for f in result["link_flags"]:
            story.append(Paragraph(f"&bull; {f}", styles["ReportBody"]))
    else:
        story.append(Paragraph("<b>Link flags:</b> none", styles["ReportBody"]))

    if result["urgency_hits"]:
        story.append(Paragraph("<b>Urgency / pressure language detected:</b>", styles["ReportBody"]))
        for phrase in result["urgency_hits"]:
            story.append(Paragraph(f"&bull; \"{phrase}\"", styles["ReportBody"]))
    else:
        story.append(Paragraph("<b>Urgency / pressure language detected:</b> none", styles["ReportBody"]))

    story.append(Spacer(1, 6))
    style = styles["VerdictHigh"] if result["score"] >= 70 else styles["VerdictLow"]
    story.append(Paragraph(f"<b>Risk Score:</b> {result['score']} / 100", styles["ReportBody"]))
    story.append(Paragraph(f"<b>Verdict:</b> {result['verdict']}", style))
    story.append(Spacer(1, 16))


def main():
    files = sorted(f for f in os.listdir(SAMPLE_DIR) if f.lower().endswith(".eml"))
    results = [analyze_email(os.path.join(SAMPLE_DIR, f)) for f in files]

    doc = SimpleDocTemplate(OUTPUT_PATH, pagesize=letter,
                             topMargin=0.7 * inch, bottomMargin=0.7 * inch)
    story = []

    story.append(Paragraph("Email Risk Analyzer — Phishing Analysis Report", styles["Title"]))
    story.append(Paragraph(
        "This report summarizes an automated scan of email headers and body "
        "content for phishing indicators and spoofing signs, including SPF/DKIM/"
        "DMARC authentication results, sender/reply-to domain mismatches, "
        "suspicious links, and urgency-based social engineering language.",
        styles["ReportBody"]))
    story.append(Spacer(1, 10))

    summary_data = [["File", "Verdict", "Score"]] + [
        [r["file"], r["verdict"].split(" — ")[0], f"{r['score']}/100"] for r in results
    ]
    summary_table = Table(summary_data, colWidths=[2.4 * inch, 2.4 * inch, 1.0 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(Paragraph("Summary", styles["SectionHead"]))
    story.append(summary_table)
    story.append(PageBreak())

    story.append(Paragraph("Detailed Findings", styles["Heading1"]))
    for result in results:
        build_email_section(result, story)

    doc.build(story)
    print(f"Report written to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
