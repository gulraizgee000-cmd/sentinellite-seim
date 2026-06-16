from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinellite.anomaly import detect_anomalies
from sentinellite.evaluation import evaluate_alerts, load_expected_alerts
from sentinellite.parsers import parse_paths
from sentinellite.report import generate_pdf_report
from sentinellite.rules import apply_detection_rules


def main() -> None:
    logs = parse_paths(sorted((ROOT / "sample_logs").glob("*")))
    alerts = apply_detection_rules(logs)
    anomalies = detect_anomalies(logs)

    assert len(logs) >= 49, f"expected sample logs, got {len(logs)}"
    assert len(alerts) >= 15, f"expected rule alerts, got {len(alerts)}"
    assert {
        "SQL injection probe",
        "Authentication brute-force burst",
        "Port scan pattern",
    }.issubset(set(alerts["alert_name"]))
    expected = load_expected_alerts(ROOT / "tests" / "expected_alerts.csv")
    _, metrics = evaluate_alerts(alerts, expected)
    assert metrics["precision"] >= 0.90, metrics
    assert metrics["recall"] >= 0.95, metrics

    report_path = ROOT / "reports" / "smoke_test_report.pdf"
    generate_pdf_report(
        report_path,
        logs,
        alerts,
        anomalies,
        analyst_name="Gulraiz Dilawar",
        course="Information Security (D1)",
        run_id="smoke-test",
    )
    assert report_path.exists(), "PDF report was not generated"
    print(f"logs={len(logs)} alerts={len(alerts)} anomalies={len(anomalies)} report={report_path.name}")


if __name__ == "__main__":
    main()
