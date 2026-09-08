"""
Threat-Trace PDF Forensic Report Generator

Generates an investigator-friendly PDF report from the unified
Threat-Trace analysis result.

Dependency:
    reportlab
"""

from pathlib import Path
from datetime import datetime, timezone
from html import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


# ============================================================
# HELPERS
# ============================================================

def safe(value, default="N/A"):
    """Convert a value into safe display text."""
    if value is None or value == "":
        return default
    return escape(str(value))


def get_nested(data, *keys, default=None):
    """Safely retrieve nested dictionary values."""
    current = data

    for key in keys:
        if not isinstance(current, dict):
            return default

        current = current.get(key)

        if current is None:
            return default

    return current


def make_table(rows, widths=None):
    """Create a styled forensic table."""
    table = Table(
        rows,
        colWidths=widths,
        repeatRows=1,
        hAlign="LEFT",
    )

    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("LEADING", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ])
    )

    return table


# ============================================================
# PAGE HEADER / FOOTER
# ============================================================

def draw_page(canvas, document):
    """Draw report header and page number."""

    canvas.saveState()

    width, height = A4

    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(
        18 * mm,
        height - 12 * mm,
        "THREAT-TRACE | DIGITAL EMAIL FORENSICS"
    )

    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(
        width - 18 * mm,
        8 * mm,
        f"Page {document.page}"
    )

    canvas.restoreState()


# ============================================================
# MAIN REPORT FUNCTION
# ============================================================

def generate_forensic_report(
    analysis: dict,
    output_path,
) -> str:
    """
    Generate a PDF forensic report.

    Parameters
    ----------
    analysis:
        Unified result returned by Threat-Trace analysis.

    output_path:
        Destination PDF path.

    Returns
    -------
    str
        Absolute path to generated PDF.
    """

    output_path = Path(output_path)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ThreatTraceTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        alignment=TA_CENTER,
        spaceAfter=10,
    )

    subtitle_style = ParagraphStyle(
        "ThreatTraceSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        alignment=TA_CENTER,
        spaceAfter=18,
    )

    section_style = ParagraphStyle(
        "Section",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        spaceBefore=12,
        spaceAfter=8,
    )

    normal_style = ParagraphStyle(
        "NormalForensic",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        spaceAfter=5,
    )

    small_style = ParagraphStyle(
        "Small",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
    )

    # --------------------------------------------------------
    # Extract unified analysis
    # --------------------------------------------------------

    case_id = get_nested(
        analysis,
        "case",
        "case_id",
        default="N/A",
    )

    created_at = get_nested(
        analysis,
        "case",
        "created_at",
        default=datetime.now(timezone.utc).isoformat(),
    )

    score = analysis.get(
        "threat_score",
        0,
    )

    classification = analysis.get(
        "classification",
        "unknown",
    )

    risk_level = analysis.get(
        "risk_level",
        get_nested(
            analysis,
            "risk",
            "risk_level",
            default="UNKNOWN",
        ),
    )

    sender = analysis.get("sender", "")
    recipient = analysis.get("recipient", "")
    subject = analysis.get("subject", "")
    date = analysis.get("date", "")

    originating_ip = analysis.get(
        "originating_ip",
        get_nested(
            analysis,
            "ip_analysis",
            "originating_ip",
            default=None,
        ),
    )

    origin_confidence = get_nested(
        analysis,
        "origin_trace",
        "confidence",
        default=get_nested(
            analysis,
            "ip_analysis",
            "origin_confidence",
            default="unknown",
        ),
    )

    country = analysis.get(
        "country",
        get_nested(
            analysis,
            "geolocation",
            "country",
            default=None,
        ),
    )

    region = analysis.get(
        "region",
        get_nested(
            analysis,
            "geolocation",
            "region",
            default=None,
        ),
    )

    city = analysis.get(
        "city",
        get_nested(
            analysis,
            "geolocation",
            "city",
            default=None,
        ),
    )

    isp = analysis.get(
        "isp",
        get_nested(
            analysis,
            "geolocation",
            "isp",
            default=None,
        ),
    )

    # Authentication
    spf = analysis.get("spf", "unknown")
    dkim = analysis.get("dkim", "unknown")
    dmarc = analysis.get("dmarc", "unknown")

    # Evidence
    iocs = analysis.get(
        "indicators_of_compromise",
        [],
    )

    evidence = analysis.get(
        "evidence",
        [],
    )

    forensic_summary = analysis.get(
        "forensic_summary",
        "",
    )

    psychological_tactic = analysis.get(
        "psychological_tactic",
        "",
    )

    # URL intelligence
    url_analysis = analysis.get(
        "url_analysis",
        analysis.get(
            "urls",
            {},
        ),
    )

    urls = (
        url_analysis.get("urls", [])
        if isinstance(url_analysis, dict)
        else []
    )

    suspicious_url_count = (
        url_analysis.get(
            "suspicious_url_count",
            0,
        )
        if isinstance(url_analysis, dict)
        else 0
    )

    url_risk = (
        url_analysis.get(
            "risk_score",
            0,
        )
        if isinstance(url_analysis, dict)
        else 0
    )

    # Integrity
    original_hash = get_nested(
        analysis,
        "case",
        "evidence_integrity",
        "original_email_sha256",
        default="N/A",
    )

    evidence_hash = get_nested(
        analysis,
        "case",
        "evidence_integrity",
        "forensic_evidence_sha256",
        default="N/A",
    )

    # --------------------------------------------------------
    # Document
    # --------------------------------------------------------

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=15 * mm,
        title=f"Threat-Trace Forensic Report - {case_id}",
        author="Threat-Trace",
    )

    story = []

    # --------------------------------------------------------
    # COVER
    # --------------------------------------------------------

    story.append(Spacer(1, 20 * mm))

    story.append(
        Paragraph(
            "THREAT-TRACE",
            title_style,
        )
    )

    story.append(
        Paragraph(
            "Automated Email Forensics & Threat Intelligence",
            subtitle_style,
        )
    )

    story.append(
        Paragraph(
            "DIGITAL FORENSIC INVESTIGATION REPORT",
            ParagraphStyle(
                "Cover",
                parent=styles["Heading1"],
                alignment=TA_CENTER,
                fontSize=15,
                spaceAfter=18,
            ),
        )
    )

    cover_rows = [
        [
            Paragraph("<b>Case ID</b>", normal_style),
            Paragraph(safe(case_id), normal_style),
        ],
        [
            Paragraph("<b>Classification</b>", normal_style),
            Paragraph(safe(classification).upper(), normal_style),
        ],
        [
            Paragraph("<b>Threat Score</b>", normal_style),
            Paragraph(f"<b>{safe(score)}/100</b>", normal_style),
        ],
        [
            Paragraph("<b>Risk Level</b>", normal_style),
            Paragraph(safe(risk_level).upper(), normal_style),
        ],
        [
            Paragraph("<b>Generated</b>", normal_style),
            Paragraph(safe(created_at), normal_style),
        ],
    ]

    cover_table = Table(
        cover_rows,
        colWidths=[55 * mm, 105 * mm],
    )

    cover_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e5e7eb")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ])
    )

    story.append(cover_table)
    story.append(Spacer(1, 15 * mm))

    story.append(
        Paragraph(
            "CONFIDENTIAL FORENSIC EVIDENCE",
            ParagraphStyle(
                "Warning",
                parent=normal_style,
                alignment=TA_CENTER,
                fontName="Helvetica-Bold",
            ),
        )
    )

    story.append(PageBreak())

    # --------------------------------------------------------
    # 1. EXECUTIVE SUMMARY
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "1. Executive Summary",
            section_style,
        )
    )

    story.append(
        Paragraph(
            safe(
                forensic_summary,
                "No AI forensic summary was available.",
            ),
            normal_style,
        )
    )

    story.append(
        Paragraph(
            f"<b>Classification:</b> {safe(classification).upper()}",
            normal_style,
        )
    )

    story.append(
        Paragraph(
            f"<b>Threat Score:</b> {safe(score)}/100",
            normal_style,
        )
    )

    story.append(
        Paragraph(
            f"<b>Risk Level:</b> {safe(risk_level).upper()}",
            normal_style,
        )
    )

    if psychological_tactic:
        story.append(
            Paragraph(
                f"<b>Psychological Tactic:</b> "
                f"{safe(psychological_tactic)}",
                normal_style,
            )
        )

    # --------------------------------------------------------
    # 2. EMAIL DETAILS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "2. Email Details",
            section_style,
        )
    )

    email_rows = [
        ["Field", "Value"],
        ["From", safe(sender)],
        ["To", safe(recipient)],
        ["Subject", safe(subject)],
        ["Date", safe(date)],
    ]

    story.append(
        make_table(
            email_rows,
            widths=[45 * mm, 115 * mm],
        )
    )

    # --------------------------------------------------------
    # 3. AUTHENTICATION
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "3. Email Authentication",
            section_style,
        )
    )

    auth_rows = [
        ["Authentication", "Result"],
        ["SPF", safe(spf).upper()],
        ["DKIM", safe(dkim).upper()],
        ["DMARC", safe(dmarc).upper()],
    ]

    story.append(
        make_table(
            auth_rows,
            widths=[75 * mm, 85 * mm],
        )
    )

    # --------------------------------------------------------
    # 4. ORIGIN TRACE
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "4. Origin Trace / IP Intelligence",
            section_style,
        )
    )

    origin_rows = [
        ["Field", "Value"],
        ["Originating IP", safe(originating_ip)],
        ["Origin Confidence", safe(origin_confidence).upper()],
        ["Country", safe(country)],
        ["Region", safe(region)],
        ["City", safe(city)],
        ["ISP", safe(isp)],
    ]

    story.append(
        make_table(
            origin_rows,
            widths=[55 * mm, 105 * mm],
        )
    )

    story.append(
        Spacer(1, 4 * mm)
    )

    story.append(
        Paragraph(
            "Forensic note: the originating IP is the earliest "
            "public IP observed in the available Received-header "
            "chain. It is not, by itself, proof of the attacker's "
            "physical location or identity.",
            small_style,
        )
    )

    # --------------------------------------------------------
    # 5. URL INTELLIGENCE
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "5. URL Intelligence",
            section_style,
        )
    )

    story.append(
        Paragraph(
            f"<b>Total URLs:</b> {len(urls)} &nbsp;&nbsp; "
            f"<b>Suspicious URLs:</b> {safe(suspicious_url_count)} "
            f"&nbsp;&nbsp; "
            f"<b>URL Risk:</b> {safe(url_risk)}/100",
            normal_style,
        )
    )

    if urls:

        url_rows = [
            ["URL", "Domain", "Risk", "Severity"]
        ]

        for item in urls:

            if not isinstance(item, dict):
                continue

            url_rows.append([
                Paragraph(
                    safe(item.get("url")),
                    small_style,
                ),
                Paragraph(
                    safe(item.get("domain")),
                    small_style,
                ),
                safe(item.get("risk_score", 0)),
                safe(item.get("severity", "LOW")),
            ])

        if len(url_rows) > 1:

            story.append(
                make_table(
                    url_rows,
                    widths=[
                        72 * mm,
                        45 * mm,
                        18 * mm,
                        25 * mm,
                    ],
                )
            )

    else:

        story.append(
            Paragraph(
                "No URLs were detected in the analyzed email body.",
                normal_style,
            )
        )

    # --------------------------------------------------------
    # 6. INDICATORS OF COMPROMISE
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "6. Indicators of Compromise",
            section_style,
        )
    )

    if iocs:

        for index, ioc in enumerate(iocs, 1):

            story.append(
                Paragraph(
                    f"{index}. {safe(ioc)}",
                    normal_style,
                )
            )

    else:

        story.append(
            Paragraph(
                "No indicators of compromise were reported.",
                normal_style,
            )
        )

    # --------------------------------------------------------
    # 7. FORENSIC EVIDENCE
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "7. Explainable Evidence",
            section_style,
        )
    )

    if evidence:

        for index, item in enumerate(evidence, 1):

            if isinstance(item, dict):

                indicator = item.get(
                    "indicator",
                    item.get("description", ""),
                )

                severity = item.get(
                    "severity",
                    "",
                )

                points = item.get(
                    "score",
                    "",
                )

                text = (
                    f"{index}. {safe(indicator)}"
                    f" — {safe(severity).upper()}"
                )

                if points != "":
                    text += f" ({safe(points)} points)"

            else:

                text = f"{index}. {safe(item)}"

            story.append(
                Paragraph(
                    text,
                    normal_style,
                )
            )

    else:

        story.append(
            Paragraph(
                "No explainable evidence items were returned.",
                normal_style,
            )
        )

    # --------------------------------------------------------
    # 8. EVIDENCE INTEGRITY
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "8. Evidence Integrity",
            section_style,
        )
    )

    integrity_rows = [
        ["Artifact", "SHA-256"],
        [
            "Original Email",
            Paragraph(
                safe(original_hash),
                small_style,
            ),
        ],
        [
            "Forensic Evidence",
            Paragraph(
                safe(evidence_hash),
                small_style,
            ),
        ],
    ]

    story.append(
        make_table(
            integrity_rows,
            widths=[50 * mm, 110 * mm],
        )
    )

    story.append(
        Spacer(1, 5 * mm)
    )

    story.append(
        Paragraph(
            "SHA-256 hashes can be recalculated later to verify "
            "that the corresponding evidence representation has "
            "not changed.",
            small_style,
        )
    )

    # --------------------------------------------------------
    # 9. INVESTIGATOR NOTES
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "9. Investigator Notes",
            section_style,
        )
    )

    notes = [
        "This report is generated automatically by Threat-Trace.",
        "Risk scores are analytical indicators and should be reviewed by an investigator.",
        "Received headers may be forged or altered before reaching the analysis system.",
        "IP geolocation represents network-location metadata and does not establish a person's identity.",
        "AI-generated conclusions should be corroborated with email headers, authentication results, URLs, and other evidence.",
    ]

    for note in notes:

        story.append(
            Paragraph(
                f"• {note}",
                normal_style,
            )
        )

    # --------------------------------------------------------
    # BUILD PDF
    # --------------------------------------------------------

    doc.build(
        story,
        onFirstPage=draw_page,
        onLaterPages=draw_page,
    )

    return str(
        output_path.resolve()
    )


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    test_analysis = {

        "case": {
            "case_id": "TT-20260908-DEMO1234",
            "created_at":
                datetime.now(timezone.utc).isoformat(),

            "evidence_integrity": {
                "original_email_sha256":
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",

                "forensic_evidence_sha256":
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",

                "algorithm": "SHA-256",
            },
        },

        "threat_score": 94,

        "classification": "bec",

        "risk_level": "CRITICAL",

        "sender":
            "CEO <ceo@micros0ft-finance.com>",

        "recipient":
            "accounts@company.com",

        "subject":
            "URGENT: Wire Transfer Required",

        "date":
            "Tue, 08 Sep 2026 10:30:00 +0000",

        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail",

        "originating_ip":
            "185.220.101.5",

        "origin_trace": {
            "confidence": "high",
        },

        "country": "Netherlands",

        "region": "",

        "city": "",

        "isp": "Tor Exit Relay",

        "url_analysis": {
            "url_count": 1,
            "suspicious_url_count": 1,
            "risk_score": 90,
            "urls": [
                {
                    "url":
                        "https://micros0ft-finance-login.xyz/verify",
                    "domain":
                        "micros0ft-finance-login.xyz",
                    "risk_score": 90,
                    "severity": "CRITICAL",
                }
            ],
        },

        "psychological_tactic":
            "False urgency and authority bias",

        "forensic_summary":
            "The message exhibits characteristics of a business email compromise attempt.",

        "indicators_of_compromise": [
            "SPF failed",
            "DKIM failed",
            "DMARC failed",
            "Possible Microsoft typosquatting",
            "Urgent financial transfer request",
        ],

        "evidence": [
            {
                "indicator": "SPF failed",
                "severity": "high",
                "score": 20,
            },
            {
                "indicator": "DMARC failed",
                "severity": "high",
                "score": 20,
            },
            {
                "indicator": "Financial transfer language detected",
                "severity": "critical",
                "score": 20,
            },
        ],
    }

    output = (
        Path(__file__).resolve().parent
        / "test_forensic_report.pdf"
    )

    print(
        generate_forensic_report(
            test_analysis,
            output,
        )
    )