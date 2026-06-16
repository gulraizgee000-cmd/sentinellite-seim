from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd


DB_PATH = Path(__file__).resolve().parents[1] / "data" / "sentinellite.db"


def init_db(db_path: Path = DB_PATH) -> Path:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                analyst TEXT NOT NULL,
                log_count INTEGER NOT NULL,
                alert_count INTEGER NOT NULL,
                anomaly_count INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS email_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                enabled INTEGER NOT NULL DEFAULT 0,
                smtp_host TEXT,
                smtp_port INTEGER,
                sender_email TEXT,
                recipient_email TEXT,
                min_severity TEXT,
                updated_at TEXT
            )
            """
        )
    return db_path


def save_run(
    logs: pd.DataFrame,
    alerts: pd.DataFrame,
    anomalies: pd.DataFrame,
    analyst: str,
    db_path: Path = DB_PATH,
) -> str:
    init_db(db_path)
    run_id = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?)",
            (
                run_id,
                datetime.utcnow().isoformat(timespec="seconds"),
                analyst,
                int(len(logs)),
                int(len(alerts)),
                int(len(anomalies)),
            ),
        )
        _append_frame(conn, "logs", _with_run_id(logs, run_id))
        _append_frame(conn, "alerts", _with_run_id(alerts, run_id))
        _append_frame(conn, "anomalies", _with_run_id(anomalies, run_id))
    return run_id


def load_runs(db_path: Path = DB_PATH) -> pd.DataFrame:
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        try:
            return pd.read_sql_query("SELECT * FROM runs ORDER BY created_at DESC", conn)
        except Exception:
            return pd.DataFrame()


def save_email_settings(settings: dict, db_path: Path = DB_PATH) -> None:
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO email_settings (
                id, enabled, smtp_host, smtp_port, sender_email, recipient_email, min_severity, updated_at
            )
            VALUES (1, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                enabled=excluded.enabled,
                smtp_host=excluded.smtp_host,
                smtp_port=excluded.smtp_port,
                sender_email=excluded.sender_email,
                recipient_email=excluded.recipient_email,
                min_severity=excluded.min_severity,
                updated_at=excluded.updated_at
            """,
            (
                1 if settings.get("enabled") else 0,
                settings.get("smtp_host", ""),
                int(settings.get("smtp_port") or 0),
                settings.get("sender_email", ""),
                settings.get("recipient_email", ""),
                settings.get("min_severity", "high"),
                datetime.utcnow().isoformat(timespec="seconds"),
            ),
        )


def load_email_settings(db_path: Path = DB_PATH) -> dict:
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT * FROM email_settings WHERE id = 1").fetchone()
        if not row:
            return {
                "enabled": False,
                "smtp_host": "",
                "smtp_port": 587,
                "sender_email": "",
                "recipient_email": "",
                "min_severity": "high",
            }
        columns = [description[0] for description in conn.execute("SELECT * FROM email_settings WHERE id = 1").description]
        data = dict(zip(columns, row))
    return {
        "enabled": bool(data.get("enabled")),
        "smtp_host": data.get("smtp_host") or "",
        "smtp_port": data.get("smtp_port") or 587,
        "sender_email": data.get("sender_email") or "",
        "recipient_email": data.get("recipient_email") or "",
        "min_severity": data.get("min_severity") or "high",
    }


def _with_run_id(df: pd.DataFrame, run_id: str) -> pd.DataFrame:
    out = df.copy()
    out.insert(0, "run_id", run_id)
    for column in out.columns:
        if pd.api.types.is_datetime64_any_dtype(out[column]):
            out[column] = out[column].astype(str)
    return out


def _append_frame(conn: sqlite3.Connection, table_name: str, df: pd.DataFrame) -> None:
    _ensure_table_columns(conn, table_name, df)
    df.to_sql(table_name, conn, if_exists="append", index=False)


def _ensure_table_columns(conn: sqlite3.Connection, table_name: str, df: pd.DataFrame) -> None:
    existing = {
        row[1]
        for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    }
    if not existing:
        return
    for column in df.columns:
        if column not in existing:
            conn.execute(f'ALTER TABLE "{table_name}" ADD COLUMN "{column}" TEXT')
