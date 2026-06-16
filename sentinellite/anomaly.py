from __future__ import annotations

import pandas as pd

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except Exception:  # pragma: no cover - fallback is for minimal environments.
    IsolationForest = None
    StandardScaler = None


ANOMALY_COLUMNS = [
    "timestamp",
    "entity",
    "anomaly_score",
    "severity",
    "reason",
    "request_count",
    "failed_login_count",
    "error_count",
    "unique_path_count",
    "scanner_user_agent_count",
    "firewall_block_count",
]


def detect_anomalies(logs: pd.DataFrame, contamination: float = 0.15) -> pd.DataFrame:
    if logs.empty:
        return empty_anomalies_frame()

    features = _build_feature_windows(logs)
    if features.empty:
        return empty_anomalies_frame()

    feature_columns = [
        "request_count",
        "failed_login_count",
        "error_count",
        "unique_path_count",
        "post_count",
        "scanner_user_agent_count",
        "firewall_block_count",
    ]

    if len(features) < 4 or IsolationForest is None or StandardScaler is None:
        scored = _fallback_score(features)
    else:
        scaler = StandardScaler()
        matrix = scaler.fit_transform(features[feature_columns])
        model = IsolationForest(n_estimators=150, contamination=contamination, random_state=42)
        predictions = model.fit_predict(matrix)
        decision_scores = model.decision_function(matrix)
        scored = features.copy()
        scored["is_anomaly"] = predictions == -1
        scored["raw_score"] = decision_scores
        max_abs = max(abs(decision_scores.min()), abs(decision_scores.max()), 0.001)
        scored["anomaly_score"] = ((-decision_scores / max_abs) * 50 + 50).clip(0, 100).round(1)

    anomalies = scored[scored["is_anomaly"]].copy()
    if anomalies.empty:
        return empty_anomalies_frame()

    anomalies["severity"] = anomalies["anomaly_score"].apply(_severity_from_score)
    anomalies["reason"] = anomalies.apply(_reason, axis=1)
    return anomalies[
        [
            "timestamp",
            "entity",
            "anomaly_score",
            "severity",
            "reason",
            "request_count",
            "failed_login_count",
            "error_count",
            "unique_path_count",
            "scanner_user_agent_count",
            "firewall_block_count",
        ]
    ].sort_values("anomaly_score", ascending=False).reset_index(drop=True)


def empty_anomalies_frame() -> pd.DataFrame:
    return pd.DataFrame(columns=ANOMALY_COLUMNS)


def _build_feature_windows(logs: pd.DataFrame) -> pd.DataFrame:
    df = logs.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df[df["timestamp"].notna()]
    if df.empty:
        return pd.DataFrame()

    df["source_ip"] = df["source_ip"].replace("", "local-or-unknown")
    df["window"] = df["timestamp"].dt.floor("15min")
    df["is_failed_login"] = df["event_type"].eq("failed_login").astype(int)
    df["is_error"] = df["status_code"].fillna(0).astype(float).between(400, 599).astype(int)
    df["is_post"] = df["method"].eq("POST").astype(int)
    df["is_scanner_ua"] = df["user_agent"].str.contains(
        "sqlmap|nikto|nmap|masscan|curl|python-requests",
        case=False,
        na=False,
        regex=True,
    ).astype(int)
    df["has_destination_port"] = df["raw_message"].str.contains(r"\bDPT=\d{1,5}\b", case=False, na=False, regex=True).astype(int)

    grouped = df.groupby(["source_ip", "window"], dropna=False).agg(
        request_count=("raw_message", "count"),
        failed_login_count=("is_failed_login", "sum"),
        error_count=("is_error", "sum"),
        unique_path_count=("path", lambda values: len({v for v in values if v})),
        post_count=("is_post", "sum"),
        scanner_user_agent_count=("is_scanner_ua", "sum"),
        firewall_block_count=("has_destination_port", "sum"),
    )
    features = grouped.reset_index().rename(columns={"source_ip": "entity", "window": "timestamp"})
    for column in [
        "request_count",
        "failed_login_count",
        "error_count",
        "unique_path_count",
        "post_count",
        "scanner_user_agent_count",
        "firewall_block_count",
    ]:
        features[column] = pd.to_numeric(features[column], errors="coerce").fillna(0)
    return features


def _fallback_score(features: pd.DataFrame) -> pd.DataFrame:
    scored = features.copy()
    scored["anomaly_score"] = (
        scored["request_count"] * 8
        + scored["failed_login_count"] * 18
        + scored["error_count"] * 10
        + scored["unique_path_count"] * 6
        + scored["scanner_user_agent_count"] * 14
        + scored["firewall_block_count"] * 10
    ).clip(0, 100)
    threshold = max(55, scored["anomaly_score"].quantile(0.85))
    scored["is_anomaly"] = scored["anomaly_score"] >= threshold
    return scored


def _severity_from_score(score: float) -> str:
    if score >= 80:
        return "high"
    if score >= 60:
        return "medium"
    return "low"


def _reason(row: pd.Series) -> str:
    reasons = []
    if row["failed_login_count"] >= 3:
        reasons.append(f"{int(row['failed_login_count'])} failed logins")
    if row["error_count"] >= 4:
        reasons.append(f"{int(row['error_count'])} HTTP errors")
    if row["unique_path_count"] >= 6:
        reasons.append(f"{int(row['unique_path_count'])} distinct paths")
    if row.get("scanner_user_agent_count", 0) >= 1:
        reasons.append("scanner-like user agent")
    if row.get("firewall_block_count", 0) >= 5:
        reasons.append(f"{int(row['firewall_block_count'])} firewall blocks")
    if not reasons:
        reasons.append("traffic pattern differs from baseline windows")
    return "; ".join(reasons)
