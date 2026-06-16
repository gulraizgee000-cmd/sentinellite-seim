# SentinelLite Test Plan

## Test Goals

The testing goal is to prove that SentinelLite can parse multiple log sources, detect known attack patterns, identify abnormal behavior windows, and generate a useful report.

## Test Dataset

The included sample logs use safe documentation IP ranges:

- `192.0.2.0/24` for normal internal-looking activity
- `198.51.100.0/24` for brute-force and probing examples
- `203.0.113.0/24` for web attack and credential attack examples

## Functional Tests

| Test ID | Test Case | Expected Result |
| --- | --- | --- |
| T1 | Parse Apache access log | Log rows include source IP, method, path, status code, bytes, and user agent. |
| T2 | Parse Linux auth log | Failed and successful login events are normalized. |
| T3 | Parse Windows event CSV | Event IDs 4624, 4625, 4688, and 1102 are mapped to event types. |
| T4 | Detect SQL injection probe | Alert name `SQL injection probe` appears with high severity. |
| T5 | Detect path traversal probe | Alert name `Path traversal probe` appears with high severity. |
| T6 | Detect brute-force burst | Multiple failed logins from one source produce a high severity alert. |
| T7 | Detect success after failures | Successful login after repeated failures produces a critical alert. |
| T8 | Detect suspicious PowerShell | Encoded or bypass-style PowerShell command produces a high severity alert. |
| T9 | Detect audit log clearing | Windows Event ID 1102 produces a critical alert. |
| T10 | Detect port scan pattern | Multiple destination ports from one source in a short window produce a high severity alert. |
| T11 | Generate PDF report | Report file is created under the `reports` folder. |
| T12 | Email alert option | SMTP settings can be saved and a severity-filtered alert digest can be sent when credentials are supplied. |

## ML Anomaly Tests

| Test ID | Feature Window | Expected Result |
| --- | --- | --- |
| M1 | Source IP with many 404s and unique paths | Higher anomaly score than normal browsing. |
| M2 | Source IP with multiple failed logins | Anomaly reason includes failed login count. |
| M3 | Normal user activity | Lower anomaly score or not flagged. |

## Smoke Test Command

```powershell
python tests\smoke_test.py
```

Expected output:

```text
logs=49 alerts=15 anomalies=3 report=smoke_test_report.pdf
```

Actual anomaly counts may vary slightly if the ML sensitivity slider is changed in the dashboard.
