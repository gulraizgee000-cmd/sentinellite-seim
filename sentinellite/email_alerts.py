from __future__ import annotations

import smtplib
from email.message import EmailMessage

import pandas as pd


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def filter_alerts_for_email(alerts: pd.DataFrame, min_severity: str) -> pd.DataFrame:
    if alerts.empty:
        return alerts
    minimum = SEVERITY_ORDER.get(min_severity, 3)
    return alerts[alerts["severity"].map(SEVERITY_ORDER).fillna(0) >= minimum].copy()


def build_email_preview(alerts: pd.DataFrame, min_severity: str = "high") -> str:
    selected = filter_alerts_for_email(alerts, min_severity)
    if selected.empty:
        return "No alerts meet the selected email severity threshold."

    lines = [
        "Subject: SentinelLite SIEM Alert Digest",
        "",
        f"{len(selected)} alert(s) meet the '{min_severity}' threshold.",
        "",
    ]
    for _, alert in selected.head(8).iterrows():
        lines.append(
            f"- [{str(alert['severity']).upper()}] {alert['alert_name']} "
            f"from {alert.get('source_ip', 'unknown')}: {alert.get('evidence', '')}"
        )
    if len(selected) > 8:
        lines.append(f"- plus {len(selected) - 8} more alert(s).")
    return "\n".join(lines)


def email_delivery_status(enabled: bool) -> str:
    if not enabled:
        return "Email alerts are disabled. Settings are saved for the later SMTP implementation."
    return "Email alert delivery is enabled. Use the Send Alert Digest button after entering SMTP details."


def send_alert_digest(alerts: pd.DataFrame, settings: dict, password: str = "") -> tuple[bool, str]:
    selected = filter_alerts_for_email(alerts, settings.get("min_severity", "high"))
    if selected.empty:
        return False, "No alerts meet the configured severity threshold."

    missing = [
        key
        for key in ("smtp_host", "smtp_port", "sender_email", "recipient_email")
        if not settings.get(key)
    ]
    if missing:
        return False, f"Missing SMTP setting(s): {', '.join(missing)}"
    if not password:
        return False, "SMTP password/app password is required to send. It is not stored by SentinelLite."

    message = EmailMessage()
    message["Subject"] = "SentinelLite SIEM Alert Digest"
    message["From"] = settings["sender_email"]
    message["To"] = settings["recipient_email"]
    message.set_content(build_email_preview(alerts, settings.get("min_severity", "high")))

    try:
        with smtplib.SMTP(settings["smtp_host"], int(settings["smtp_port"]), timeout=20) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(settings["sender_email"], password)
            smtp.send_message(message)
        return True, f"Sent {len(selected)} alert(s) to {settings['recipient_email']}."
    except Exception as exc:
        return False, f"Email send failed: {exc}"
