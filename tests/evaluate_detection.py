from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinellite.evaluation import evaluate_alerts, load_expected_alerts
from sentinellite.parsers import parse_paths
from sentinellite.rules import apply_detection_rules


def main() -> None:
    logs = parse_paths(sorted((ROOT / "sample_logs").glob("*")))
    alerts = apply_detection_rules(logs)
    expected = load_expected_alerts(ROOT / "tests" / "expected_alerts.csv")
    results, metrics = evaluate_alerts(alerts, expected)

    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    results.to_csv(reports / "evaluation_results.csv", index=False)
    (reports / "evaluation_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    assert metrics["recall"] >= 0.95, metrics
    assert metrics["precision"] >= 0.90, metrics
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
