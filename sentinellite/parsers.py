from __future__ import annotations

import csv
import io
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable

import pandas as pd


LOG_COLUMNS = [
    "timestamp",
    "source_file",
    "log_type",
    "host",
    "source_ip",
    "user",
    "event_type",
    "method",
    "path",
    "status_code",
    "bytes_sent",
    "user_agent",
    "raw_message",
]

APACHE_RE = re.compile(
    r"^(?P<source_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "
    r'"(?P<method>\S+) (?P<path>.*?) (?P<protocol>HTTP/\d(?:\.\d)?)" '
    r"(?P<status_code>\d{3}) (?P<bytes_sent>\S+) "
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"$'
)

SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<program>[\w.-]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$"
)

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def parse_paths(paths: Iterable[Path]) -> pd.DataFrame:
    frames = [parse_file(path) for path in paths]
    if not frames:
        return empty_logs_frame()
    return normalize_logs(pd.concat(frames, ignore_index=True))


def parse_uploaded_file(name: str, content: bytes) -> pd.DataFrame:
    text = content.decode("utf-8", errors="replace")
    suffix = Path(name).suffix.lower()
    if suffix == ".csv":
        return normalize_logs(_parse_windows_csv(name, text))

    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parsed = parse_line(line.strip(), name)
        if parsed:
            rows.append(parsed)
    return normalize_logs(pd.DataFrame(rows, columns=LOG_COLUMNS))


def parse_file(path: Path) -> pd.DataFrame:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".csv":
        return normalize_logs(_parse_windows_csv(path.name, text))

    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parsed = parse_line(line.strip(), path.name)
        if parsed:
            rows.append(parsed)
    return normalize_logs(pd.DataFrame(rows, columns=LOG_COLUMNS))


def parse_line(line: str, source_file: str) -> dict | None:
    apache_match = APACHE_RE.match(line)
    if apache_match:
        data = apache_match.groupdict()
        status_code = int(data["status_code"])
        return {
            "timestamp": _parse_apache_time(data["timestamp"]),
            "source_file": source_file,
            "log_type": "apache",
            "host": "web-server",
            "source_ip": data["source_ip"],
            "user": "",
            "event_type": _apache_event_type(status_code, data["path"]),
            "method": data["method"],
            "path": data["path"],
            "status_code": status_code,
            "bytes_sent": _parse_int(data["bytes_sent"]),
            "user_agent": data["user_agent"],
            "raw_message": line,
        }

    syslog_match = SYSLOG_RE.match(line)
    if syslog_match:
        data = syslog_match.groupdict()
        message = data["message"]
        source_ip = _first_ip(message)
        return {
            "timestamp": _parse_syslog_time(data["month"], data["day"], data["time"]),
            "source_file": source_file,
            "log_type": "auth",
            "host": data["host"],
            "source_ip": source_ip,
            "user": _extract_user(message),
            "event_type": _auth_event_type(message),
            "method": "",
            "path": "",
            "status_code": None,
            "bytes_sent": None,
            "user_agent": "",
            "raw_message": line,
        }

    return {
        "timestamp": pd.NaT,
        "source_file": source_file,
        "log_type": "generic",
        "host": "",
        "source_ip": _first_ip(line),
        "user": "",
        "event_type": "generic_event",
        "method": "",
        "path": "",
        "status_code": None,
        "bytes_sent": None,
        "user_agent": "",
        "raw_message": line,
    }


def normalize_logs(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return empty_logs_frame()
    for column in LOG_COLUMNS:
        if column not in df.columns:
            df[column] = None
    df = df[LOG_COLUMNS].copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["status_code"] = pd.to_numeric(df["status_code"], errors="coerce")
    df["bytes_sent"] = pd.to_numeric(df["bytes_sent"], errors="coerce")
    string_columns = [
        "source_file",
        "log_type",
        "host",
        "source_ip",
        "user",
        "event_type",
        "method",
        "path",
        "user_agent",
        "raw_message",
    ]
    for column in string_columns:
        df[column] = df[column].fillna("").astype(str)
    return df.sort_values("timestamp", na_position="last").reset_index(drop=True)


def empty_logs_frame() -> pd.DataFrame:
    return pd.DataFrame(columns=LOG_COLUMNS)


def _parse_windows_csv(source_file: str, text: str) -> pd.DataFrame:
    rows = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        message = row.get("message", "")
        rows.append(
            {
                "timestamp": row.get("timestamp"),
                "source_file": source_file,
                "log_type": "windows",
                "host": row.get("host", "windows-host"),
                "source_ip": row.get("source_ip", "") or _first_ip(message),
                "user": row.get("user", ""),
                "event_type": _windows_event_type(row.get("event_id", ""), message),
                "method": "",
                "path": "",
                "status_code": None,
                "bytes_sent": None,
                "user_agent": "",
                "raw_message": f"EventID={row.get('event_id', '')} Provider={row.get('provider', '')} {message}".strip(),
            }
        )
    return pd.DataFrame(rows, columns=LOG_COLUMNS)


def _parse_apache_time(value: str) -> datetime | pd.NaT:
    try:
        return datetime.strptime(value.split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return pd.NaT


def _parse_syslog_time(month: str, day: str, time_value: str) -> datetime | pd.NaT:
    # The sample logs are for the course year, so add 2026 to syslog timestamps.
    try:
        return datetime.strptime(f"2026 {month} {day} {time_value}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return pd.NaT


def _apache_event_type(status_code: int, path: str) -> str:
    lowered = path.lower()
    if status_code in (401, 403):
        return "web_access_denied"
    if status_code == 404:
        return "web_not_found"
    if any(token in lowered for token in ("union", "../", "etc/passwd", ".env", "wp-admin")):
        return "web_attack_probe"
    return "web_request"


def _auth_event_type(message: str) -> str:
    lowered = message.lower()
    if "ufw block" in lowered or "dpt=" in lowered or "spt=" in lowered:
        return "firewall_block"
    if "failed password" in lowered or "authentication failure" in lowered:
        return "failed_login"
    if "accepted password" in lowered or "accepted publickey" in lowered:
        return "successful_login"
    if "invalid user" in lowered:
        return "invalid_user"
    if "sudo" in lowered:
        return "privilege_event"
    return "auth_event"


def _windows_event_type(event_id: str, message: str) -> str:
    lowered = message.lower()
    if event_id == "4625" or "failed logon" in lowered:
        return "failed_login"
    if event_id == "4624" or "successful logon" in lowered:
        return "successful_login"
    if event_id == "4688" or "process created" in lowered:
        return "process_creation"
    if event_id == "1102" or "audit log was cleared" in lowered:
        return "audit_log_cleared"
    return "windows_event"


def _first_ip(value: str) -> str:
    match = IP_RE.search(value or "")
    return match.group(0) if match else ""


def _extract_user(message: str) -> str:
    patterns = [
        r"for invalid user (?P<user>[\w.-]+)",
        r"Failed password for (?P<user>[\w.-]+)",
        r"Accepted password for (?P<user>[\w.-]+)",
        r"user=(?P<user>[\w.-]+)",
        r"session opened for user (?P<user>[\w.-]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, message, flags=re.IGNORECASE)
        if match:
            return match.group("user")
    return ""


def _parse_int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
