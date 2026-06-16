from __future__ import annotations

from pathlib import Path

import pandas as pd


EVALUATION_COLUMNS = [
    "alert_name",
    "source_ip",
    "expected_count",
    "actual_count",
    "matched",
    "status",
]


def load_expected_alerts(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame(columns=["alert_name", "source_ip", "expected_count"])
    expected = pd.read_csv(path)
    expected["expected_count"] = pd.to_numeric(expected["expected_count"], errors="coerce").fillna(1).astype(int)
    return expected


def evaluate_alerts(alerts: pd.DataFrame, expected: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    if expected.empty:
        return pd.DataFrame(columns=EVALUATION_COLUMNS), _empty_metrics()

    if alerts.empty:
        actual_groups = pd.DataFrame(columns=["alert_name", "source_ip", "actual_count"])
    else:
        actual_groups = (
            alerts.groupby(["alert_name", "source_ip"], dropna=False)
            .size()
            .reset_index(name="actual_count")
        )

    result = expected.merge(actual_groups, how="left", on=["alert_name", "source_ip"])
    result["actual_count"] = result["actual_count"].fillna(0).astype(int)
    result["matched"] = result[["expected_count", "actual_count"]].min(axis=1)
    result["status"] = result.apply(
        lambda row: "pass" if row["actual_count"] >= row["expected_count"] else "miss",
        axis=1,
    )

    expected_pairs = set(zip(expected["alert_name"], expected["source_ip"]))
    actual_pairs = set(zip(actual_groups["alert_name"], actual_groups["source_ip"]))
    matched_pairs = {
        (row["alert_name"], row["source_ip"])
        for _, row in result.iterrows()
        if row["actual_count"] >= row["expected_count"]
    }

    false_positive_pairs = actual_pairs - expected_pairs
    false_negative_pairs = expected_pairs - matched_pairs
    precision = len(matched_pairs) / len(actual_pairs) if actual_pairs else 0.0
    recall = len(matched_pairs) / len(expected_pairs) if expected_pairs else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0

    metrics = {
        "expected_groups": len(expected_pairs),
        "actual_groups": len(actual_pairs),
        "matched_groups": len(matched_pairs),
        "false_positive_groups": len(false_positive_pairs),
        "false_negative_groups": len(false_negative_pairs),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3),
    }
    return result[EVALUATION_COLUMNS], metrics


def _empty_metrics() -> dict:
    return {
        "expected_groups": 0,
        "actual_groups": 0,
        "matched_groups": 0,
        "false_positive_groups": 0,
        "false_negative_groups": 0,
        "precision": 0.0,
        "recall": 0.0,
        "f1_score": 0.0,
    }
