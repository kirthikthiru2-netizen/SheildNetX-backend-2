"""
ShieldNetX PDF investigation report generator.

Turns a scan record (from the database) into a formatted PDF suitable
for a fraud/security investigator to attach to a case file.
"""

import io
from datetime import datetime, timezone

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
)
from reportlab.lib.enums import TA_CENTER

VERDICT_COLORS = {
    "SAFE": colors.HexColor("#1a7f37"),
    "SUSPICIOUS": colors.HexColor("#b58105"),
    "DANGEROUS": colors.HexColor("#cf222e"),
}


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", parent=styles["Title"], fontSize=20, spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="ReportSubtitle", parent=styles["Normal"], fontSize=10,
        textColor=colors.HexColor("#57606a"), spaceAfter=16,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading", parent=styles["Heading2"], fontSize=13,
        spaceBefore=16, spaceAfter=8, textColor=colors.HexColor("#1a1a1a"),
    ))
    styles.add(ParagraphStyle(
        name="VerdictBig", parent=styles["Normal"], fontSize=28, leading=34,
        alignment=TA_CENTER, spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="ScoreBig", parent=styles["Normal"], fontSize=14, leading=18,
        alignment=TA_CENTER, textColor=colors.HexColor("#57606a"),
    ))
    styles.add(ParagraphStyle(
        name="CellWrap", parent=styles["Normal"], fontSize=8, leading=10,
    ))
    return styles


def _table_style(header_bg="#f6f8fa"):
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_bg)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1a1a1a")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
    ])


def generate_apk_report_pdf(record: dict) -> bytes:
    """record is the dict shape returned by db.record_to_dict()."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
    )
    styles = _styles()
    story = []

    # --- Header ---
    story.append(Paragraph("ShieldNetX — APK Investigation Report", styles["ReportTitle"]))
    story.append(Paragraph(
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · "
        f"GenAI-assisted static &amp; behavioral analysis",
        styles["ReportSubtitle"],
    ))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#d0d7de"), thickness=1))
    story.append(Spacer(1, 12))

    # --- Verdict banner ---
    verdict = record.get("verdict", "UNKNOWN")
    verdict_color = VERDICT_COLORS.get(verdict, colors.grey)
    verdict_style = ParagraphStyle(
        name="VerdictColored", parent=styles["VerdictBig"], textColor=verdict_color,
    )
    story.append(Paragraph(verdict, verdict_style))
    story.append(Paragraph(f"Risk Score: {record.get('risk_score', 0)} / 100", styles["ScoreBig"]))
    story.append(Spacer(1, 12))

    # --- File identity ---
    story.append(Paragraph("File Identity", styles["SectionHeading"]))
    identity_rows = [
        ["Field", "Value"],
        ["Filename", record.get("filename") or "—"],
        ["Package Name", record.get("package_name") or "—"],
        ["App Name", record.get("app_name") or "—"],
        ["SHA-256", Paragraph(record.get("sha256", ""), styles["CellWrap"])],
        ["First Analyzed", record.get("first_analyzed_at", "—")],
        ["Last Analyzed", record.get("last_analyzed_at", "—")],
        ["Times Submitted", str(record.get("scan_count", 1))],
    ]
    identity_table = Table(identity_rows, colWidths=[1.6 * inch, 4.9 * inch])
    identity_table.setStyle(_table_style())
    story.append(identity_table)
    story.append(Spacer(1, 12))

    # --- Blocklist match (if any) ---
    blocklist_match = record.get("blocklist_match")
    if blocklist_match:
        story.append(Paragraph("Known Threat Match", styles["SectionHeading"]))
        story.append(Paragraph(
            f"<b>This exact file matches a known-malware entry in ShieldNetX's "
            f"threat database.</b> Label: {blocklist_match.get('label', 'N/A')} · "
            f"Source: {blocklist_match.get('source', 'N/A')} · "
            f"Added: {blocklist_match.get('added_at', 'N/A')}",
            styles["Normal"],
        ))
        story.append(Spacer(1, 12))

    # --- Score breakdown ---
    story.append(Paragraph("Score Breakdown", styles["SectionHeading"]))
    score_rows = [
        ["Component", "Score"],
        ["Static Analysis (permissions, signing)", f"{record.get('static_score', 0)} / 100"],
        ["Dynamic Indicators (behavior patterns, URLs)", f"{record.get('dynamic_score', 0)} / 100"],
        ["GenAI Assessment", f"{record.get('ai_score')} / 100" if record.get("ai_score") is not None else "Not available"],
        ["Composite Risk Score", f"{record.get('risk_score', 0)} / 100"],
    ]
    score_table = Table(score_rows, colWidths=[4.4 * inch, 2.1 * inch])
    score_table.setStyle(_table_style())
    story.append(score_table)
    story.append(Spacer(1, 12))

    # --- Permissions ---
    permissions = record.get("permissions_found", [])
    if permissions:
        story.append(Paragraph("Dangerous Permissions Requested", styles["SectionHeading"]))
        cell_style = styles["CellWrap"]
        perm_rows = [["Permission", "Risk Points"]]
        for p in permissions:
            perm_rows.append([Paragraph(p.get("permission", ""), cell_style), str(p.get("risk_points", ""))])
        perm_table = Table(perm_rows, colWidths=[4.9 * inch, 1.6 * inch])
        perm_table.setStyle(_table_style())
        story.append(perm_table)
        story.append(Spacer(1, 12))

    # --- Suspicious APIs ---
    apis = record.get("suspicious_apis", [])
    if apis:
        story.append(Paragraph("Suspicious API Usage", styles["SectionHeading"]))
        cell_style = styles["CellWrap"]
        api_rows = [["API Pattern", "Description", "Occurrences"]]
        for a in apis:
            api_rows.append([
                Paragraph(a.get("pattern", ""), cell_style),
                Paragraph(a.get("description", ""), cell_style),
                str(a.get("occurrences", "")),
            ])
        api_table = Table(api_rows, colWidths=[2.3 * inch, 3.0 * inch, 1.2 * inch])
        api_table.setStyle(_table_style())
        story.append(api_table)
        story.append(Spacer(1, 12))

    # --- Dynamic indicators ---
    indicators = record.get("dynamic_indicators", [])
    if indicators:
        story.append(Paragraph("Behavioral Indicators", styles["SectionHeading"]))
        for d in indicators:
            story.append(Paragraph(
                f"- <b>{d.get('indicator', '')}</b> (+{d.get('risk_points', 0)} pts): "
                f"{d.get('description', '')}",
                styles["Normal"],
            ))
        story.append(Spacer(1, 12))

    # --- Embedded URLs ---
    urls = record.get("embedded_urls", [])
    if urls:
        story.append(Paragraph("Embedded URLs / Network Endpoints", styles["SectionHeading"]))
        for u in urls:
            story.append(Paragraph(f"- {u}", styles["Normal"]))
        story.append(Spacer(1, 12))

    # --- GenAI Summary ---
    story.append(Paragraph("GenAI Threat Summary", styles["SectionHeading"]))
    story.append(Paragraph(record.get("ai_summary", "Not available"), styles["Normal"]))
    story.append(Spacer(1, 12))

    # --- Recommendations ---
    recs = record.get("recommendations", [])
    if recs:
        story.append(Paragraph("Recommended Actions", styles["SectionHeading"]))
        for r in recs:
            story.append(Paragraph(f"- {r}", styles["Normal"]))
        story.append(Spacer(1, 12))

    # --- Footer note ---
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#d0d7de"), thickness=1))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report was generated automatically by ShieldNetX using static analysis, "
        "simulated-dynamic behavior detection, and GenAI-assisted threat classification. "
        "It is intended to support — not replace — human security review.",
        ParagraphStyle(name="Footer", parent=styles["Normal"], fontSize=8,
                        textColor=colors.HexColor("#57606a")),
    ))

    doc.build(story)
    return buf.getvalue()
