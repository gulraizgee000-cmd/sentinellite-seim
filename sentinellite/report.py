from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_pdf_report(
    output_path: Path,
    logs: pd.DataFrame,
    alerts: pd.DataFrame,
    anomalies: pd.DataFrame,
    analyst_name: str,
    course: str,
    run_id: str | None = None,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=0.7 * inch,
        leftMargin=0.7 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.7 * inch,
    )

    story = [
        Paragraph("SentinelLite SIEM Analysis Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Analyst: {analyst_name}", styles["Normal"]),
        Paragraph(f"Course: {course}", styles["Normal"]),
        Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]),
    ]
    if run_id:
        story.append(Paragraph(f"Run ID: {run_id}", styles["Normal"]))

    story.extend(
        [
            Spacer(1, 14),
            Paragraph("Executive Summary", styles["Heading2"]),
            Paragraph(
                (
                    f"The analysis processed {len(logs)} log events and produced "
                    f"{len(alerts)} rule-based security alerts and {len(anomalies)} anomaly findings. "
                    "SentinelLite combines explainable detection rules with Isolation Forest anomaly scoring "
                    "to support lightweight security monitoring for small lab environments."
                ),
                styles["BodyText"],
            ),
            Spacer(1, 12),
            Paragraph("Detection Summary", styles["Heading2"]),
            _summary_table(alerts, anomalies),
            Spacer(1, 12),
            Paragraph("Top Alerts", styles["Heading2"]),
            _alerts_table(alerts),
            Spacer(1, 12),
            Paragraph("Anomaly Findings", styles["Heading2"]),
            _anomaly_table(anomalies),
            Spacer(1, 12),
            Paragraph("Testing Notes", styles["Heading2"]),
            Paragraph(
                (
                    "The included sample logs use documentation-only IP ranges and safe payload strings. "
                    "Rule coverage includes brute-force login attempts, SQL injection probes, path traversal, "
                    "scanner user agents, repeated 404 probing, port scan patterns, suspicious PowerShell execution, "
                    "and audit-log clearing."
                ),
                styles["BodyText"],
            ),
        ]
    )
    doc.build(story)
    return output_path


def _summary_table(alerts: pd.DataFrame, anomalies: pd.DataFrame) -> Table:
    severity_counts = alerts["severity"].value_counts().to_dict() if not alerts.empty else {}
    data = [
        ["Metric", "Value"],
        ["Critical alerts", str(severity_counts.get("critical", 0))],
        ["High alerts", str(severity_counts.get("high", 0))],
        ["Medium alerts", str(severity_counts.get("medium", 0))],
        ["Low alerts", str(severity_counts.get("low", 0))],
        ["ML anomaly windows", str(len(anomalies))],
    ]
    return _styled_table(data, widths=[2.4 * inch, 3.8 * inch])


def _alerts_table(alerts: pd.DataFrame) -> Table:
    if alerts.empty:
        return _styled_table([["Status"], ["No rule-based alerts generated."]], widths=[6.2 * inch])
    data = [["Severity", "Alert", "Source", "Evidence"]]
    for _, row in alerts.head(10).iterrows():
        data.append(
            [
                str(row["severity"]).upper(),
                str(row["alert_name"]),
                str(row.get("source_ip", "")),
                _trim(str(row.get("evidence", "")), 58),
            ]
        )
    return _styled_table(data, widths=[0.85 * inch, 1.55 * inch, 1.0 * inch, 2.8 * inch])


def _anomaly_table(anomalies: pd.DataFrame) -> Table:
    if anomalies.empty:
        return _styled_table([["Status"], ["No anomaly windows generated."]], widths=[6.2 * inch])
    data = [["Score", "Entity", "Reason"]]
    for _, row in anomalies.head(8).iterrows():
        data.append([str(row["anomaly_score"]), str(row["entity"]), _trim(str(row["reason"]), 70)])
    return _styled_table(data, widths=[0.75 * inch, 1.15 * inch, 4.3 * inch])


def _styled_table(data: list[list[str]], widths: list[float]) -> Table:
    table = Table(data, colWidths=widths, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _trim(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."
