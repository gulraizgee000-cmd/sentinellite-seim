from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

import pandas as pd


SEVERITY_SCORES = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 90,
}


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    name: str
    category: str
    severity: str
    mitre: str
    description: str
    recommendation: str


RULES = {
    "WEB-SQLI-001": DetectionRule(
        "WEB-SQLI-001",
        "SQL injection probe",
        "Web Attack",
        "high",
        "T1190 - Exploit Public-Facing Application",
        "Request path contains common SQL injection indicators.",
        "Validate inputs, parameterize queries, and review WAF/application logs for the source IP.",
    ),
    "WEB-PATH-002": DetectionRule(
        "WEB-PATH-002",
        "Path traversal probe",
        "Web Attack",
        "high",
        "T1083 - File and Directory Discovery",
        "Request path attempts to access parent directories or sensitive local files.",
        "Normalize paths server-side and block traversal payloads at the application and gateway layers.",
    ),
    "WEB-UA-003": DetectionRule(
        "WEB-UA-003",
        "Suspicious scanning user agent",
        "Reconnaissance",
        "medium",
        "T1595 - Active Scanning",
        "User-Agent header matches a known security scanner or scripted client pattern.",
        "Rate-limit the source, verify whether scanning was authorized, and review adjacent requests.",
    ),
    "WEB-404-004": DetectionRule(
        "WEB-404-004",
        "Repeated 404 probing",
        "Reconnaissance",
        "medium",
        "T1595 - Active Scanning",
        "Source IP generated many not-found responses inside a short time window.",
        "Block noisy probes and check whether the source is enumerating hidden paths.",
    ),
    "AUTH-BRUTE-005": DetectionRule(
        "AUTH-BRUTE-005",
        "Authentication brute-force burst",
        "Credential Attack",
        "high",
        "T1110 - Brute Force",
        "Multiple failed authentication events from the same source in a short window.",
        "Enforce lockout/MFA, block the source temporarily, and verify whether any login later succeeded.",
    ),
    "AUTH-SUCCESS-006": DetectionRule(
        "AUTH-SUCCESS-006",
        "Successful login after failures",
        "Credential Attack",
        "critical",
        "T1078 - Valid Accounts",
        "A successful login occurred soon after repeated failures from the same source IP.",
        "Treat as possible credential compromise; review account activity and rotate the password.",
    ),
    "WIN-PS-007": DetectionRule(
        "WIN-PS-007",
        "Suspicious PowerShell execution",
        "Endpoint Execution",
        "high",
        "T1059.001 - PowerShell",
        "Windows process creation event includes encoded or hidden PowerShell execution.",
        "Collect command-line details, isolate the host if needed, and inspect parent process lineage.",
    ),
    "WIN-AUDIT-008": DetectionRule(
        "WIN-AUDIT-008",
        "Audit log cleared",
        "Defense Evasion",
        "critical",
        "T1070.001 - Clear Windows Event Logs",
        "Windows audit log clearing indicates possible attempt to remove evidence.",
        "Preserve host evidence immediately and identify the user/process responsible for clearing logs.",
    ),
    "NET-PORTSCAN-009": DetectionRule(
        "NET-PORTSCAN-009",
        "Port scan pattern",
        "Reconnaissance",
        "high",
        "T1046 - Network Service Discovery",
        "A source IP touched many destination ports in a short window.",
        "Confirm whether scanning was authorized, block the source if hostile, and inspect exposed services.",
    ),
}

SQLI_RE = re.compile(
    r"(\bunion\b.*\bselect\b|\bor\b\s+1\s*=\s*1|information_schema|sleep\s*\(|benchmark\s*\(|--|%27)",
    re.IGNORECASE,
)
PATH_TRAVERSAL_RE = re.compile(r"(\.\./|%2e%2e|/etc/passwd|boot\.ini|win\.ini)", re.IGNORECASE)
SUSPICIOUS_UA_RE = re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|python-requests|curl/)", re.IGNORECASE)
POWERSHELL_RE = re.compile(r"(powershell|pwsh).*(-enc|-encodedcommand|hidden|bypass)", re.IGNORECASE)
DEST_PORT_RE = re.compile(r"\bDPT=(?P<port>\d{1,5})\b", re.IGNORECASE)


def apply_detection_rules(logs: pd.DataFrame) -> pd.DataFrame:
    alerts = []
    if logs.empty:
        return empty_alerts_frame()

    logs = logs.copy()
    logs["timestamp"] = pd.to_datetime(logs["timestamp"], errors="coerce")
    logs["source_ip"] = logs["source_ip"].fillna("").astype(str)
    logs["raw_message"] = logs["raw_message"].fillna("").astype(str)

    for idx, row in logs.iterrows():
        path = str(row.get("path", ""))
        raw_message = str(row.get("raw_message", ""))
        searchable = _decode_for_detection(f"{path} {raw_message}")

        if SQLI_RE.search(searchable):
            alerts.append(_row_alert(row, idx, RULES["WEB-SQLI-001"], evidence=path or raw_message))
        if PATH_TRAVERSAL_RE.search(searchable):
            alerts.append(_row_alert(row, idx, RULES["WEB-PATH-002"], evidence=path or raw_message))
        if POWERSHELL_RE.search(raw_message):
            alerts.append(_row_alert(row, idx, RULES["WIN-PS-007"], evidence=raw_message))
        if str(row.get("event_type", "")) == "audit_log_cleared":
            alerts.append(_row_alert(row, idx, RULES["WIN-AUDIT-008"], evidence=raw_message))

    alerts.extend(_windowed_failed_login_alerts(logs))
    alerts.extend(_windowed_404_alerts(logs))
    alerts.extend(_windowed_scanner_user_agent_alerts(logs))
    alerts.extend(_successful_after_failures_alerts(logs))
    alerts.extend(_windowed_port_scan_alerts(logs))

    if not alerts:
        return empty_alerts_frame()
    return pd.DataFrame(alerts).sort_values(["risk_score", "timestamp"], ascending=[False, True]).reset_index(drop=True)


def empty_alerts_frame() -> pd.DataFrame:
    return pd.DataFrame(
        columns=[
            "timestamp",
            "rule_id",
            "alert_name",
            "category",
            "severity",
            "risk_score",
            "confidence",
            "attack_phase",
            "source_ip",
            "user",
            "evidence",
            "mitre_technique",
            "recommendation",
            "log_index",
        ]
    )


def _row_alert(row: pd.Series, log_index: int, rule: DetectionRule, evidence: str) -> dict:
    return {
        "timestamp": row.get("timestamp"),
        "rule_id": rule.rule_id,
        "alert_name": rule.name,
        "category": rule.category,
        "severity": rule.severity,
        "risk_score": SEVERITY_SCORES[rule.severity],
        "confidence": _confidence(rule.rule_id),
        "attack_phase": _attack_phase(rule.rule_id),
        "source_ip": row.get("source_ip", ""),
        "user": row.get("user", ""),
        "evidence": _shorten(evidence),
        "mitre_technique": rule.mitre,
        "recommendation": rule.recommendation,
        "log_index": log_index,
    }


def _aggregate_alert(timestamp, rule: DetectionRule, source_ip: str, user: str, evidence: str) -> dict:
    return {
        "timestamp": timestamp,
        "rule_id": rule.rule_id,
        "alert_name": rule.name,
        "category": rule.category,
        "severity": rule.severity,
        "risk_score": SEVERITY_SCORES[rule.severity],
        "confidence": _confidence(rule.rule_id),
        "attack_phase": _attack_phase(rule.rule_id),
        "source_ip": source_ip,
        "user": user,
        "evidence": _shorten(evidence),
        "mitre_technique": rule.mitre,
        "recommendation": rule.recommendation,
        "log_index": -1,
    }


def _windowed_failed_login_alerts(logs: pd.DataFrame) -> list[dict]:
    failed = logs[(logs["event_type"] == "failed_login") & logs["timestamp"].notna()].copy()
    if failed.empty:
        return []
    failed["window"] = failed["timestamp"].dt.floor("10min")
    grouped = failed.groupby(["source_ip", "window"], dropna=False)
    alerts = []
    for (source_ip, window), group in grouped:
        if source_ip and len(group) >= 3:
            users = ", ".join(sorted({u for u in group["user"].astype(str) if u})[:4])
            evidence = f"{len(group)} failed logins in 10 minutes; users={users or 'unknown'}"
            alerts.append(_aggregate_alert(window, RULES["AUTH-BRUTE-005"], source_ip, users, evidence))
    return alerts


def _windowed_404_alerts(logs: pd.DataFrame) -> list[dict]:
    web = logs[(logs["status_code"] == 404) & logs["timestamp"].notna()].copy()
    if web.empty:
        return []
    web["window"] = web["timestamp"].dt.floor("10min")
    alerts = []
    for (source_ip, window), group in web.groupby(["source_ip", "window"], dropna=False):
        distinct_paths = group["path"].nunique()
        if source_ip and len(group) >= 5 and distinct_paths >= 4:
            evidence = f"{len(group)} not-found responses across {distinct_paths} paths"
            alerts.append(_aggregate_alert(window, RULES["WEB-404-004"], source_ip, "", evidence))
    return alerts


def _windowed_scanner_user_agent_alerts(logs: pd.DataFrame) -> list[dict]:
    web = logs[(logs["timestamp"].notna()) & (logs["user_agent"].str.len() > 0)].copy()
    if web.empty:
        return []
    web["scanner_match"] = web["user_agent"].str.extract(SUSPICIOUS_UA_RE, expand=False)
    web = web[web["scanner_match"].notna()].copy()
    if web.empty:
        return []
    web["window"] = web["timestamp"].dt.floor("10min")
    alerts = []
    for (source_ip, window), group in web.groupby(["source_ip", "window"], dropna=False):
        agents = sorted({str(agent) for agent in group["user_agent"] if str(agent)})
        evidence = f"{len(group)} request(s) with scanner-like user agent: {', '.join(agents[:3])}"
        alerts.append(_aggregate_alert(window, RULES["WEB-UA-003"], source_ip, "", evidence))
    return alerts


def _successful_after_failures_alerts(logs: pd.DataFrame) -> list[dict]:
    auth = logs[(logs["event_type"].isin(["failed_login", "successful_login"])) & logs["timestamp"].notna()].copy()
    if auth.empty:
        return []
    alerts = []
    for source_ip, group in auth.sort_values("timestamp").groupby("source_ip"):
        if not source_ip:
            continue
        failures = []
        for _, row in group.iterrows():
            if row["event_type"] == "failed_login":
                failures.append(row)
                continue
            recent_failures = [
                failure
                for failure in failures
                if (row["timestamp"] - failure["timestamp"]).total_seconds() <= 900
            ]
            if len(recent_failures) >= 3:
                evidence = f"Success for user {row.get('user', 'unknown')} after {len(recent_failures)} recent failures"
                alerts.append(_aggregate_alert(row["timestamp"], RULES["AUTH-SUCCESS-006"], source_ip, row.get("user", ""), evidence))
                break
    return alerts


def _windowed_port_scan_alerts(logs: pd.DataFrame) -> list[dict]:
    firewall = logs[logs["timestamp"].notna()].copy()
    firewall["destination_port"] = firewall["raw_message"].str.extract(DEST_PORT_RE)["port"]
    firewall = firewall[firewall["destination_port"].notna()].copy()
    if firewall.empty:
        return []
    firewall["window"] = firewall["timestamp"].dt.floor("10min")
    alerts = []
    for (source_ip, window), group in firewall.groupby(["source_ip", "window"], dropna=False):
        ports = sorted({str(port) for port in group["destination_port"] if str(port).isdigit()}, key=int)
        if source_ip and len(ports) >= 5:
            evidence = f"{len(ports)} destination ports touched in 10 minutes: {', '.join(ports[:10])}"
            alerts.append(_aggregate_alert(window, RULES["NET-PORTSCAN-009"], source_ip, "", evidence))
    return alerts


def _shorten(value: str, limit: int = 260) -> str:
    value = " ".join(str(value).split())
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _decode_for_detection(value: str) -> str:
    decoded = value
    for _ in range(2):
        decoded = unquote_plus(decoded)
    return f"{value} {decoded}"


def _confidence(rule_id: str) -> str:
    if rule_id in {"AUTH-SUCCESS-006", "WIN-AUDIT-008", "NET-PORTSCAN-009"}:
        return "high"
    if rule_id in {"WEB-SQLI-001", "WEB-PATH-002", "AUTH-BRUTE-005", "WIN-PS-007"}:
        return "medium-high"
    return "medium"


def _attack_phase(rule_id: str) -> str:
    if rule_id.startswith(("WEB-UA", "WEB-404", "NET-PORTSCAN")):
        return "Reconnaissance"
    if rule_id.startswith("AUTH"):
        return "Credential Access"
    if rule_id.startswith(("WEB-SQLI", "WEB-PATH")):
        return "Initial Access"
    if rule_id.startswith("WIN-AUDIT"):
        return "Defense Evasion"
    if rule_id.startswith("WIN-PS"):
        return "Execution"
    return "Investigation"
