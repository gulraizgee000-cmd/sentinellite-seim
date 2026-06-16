# 10-Minute Demo Script

Project: SentinelLite: A Lightweight SIEM with Rule-Based Detection and ML Anomaly Scoring
Presenter: Gulraiz Dilawar (F2023376392)

## 0:00-1:00 - Problem
Explain that small labs have logs but often lack a lightweight SIEM workflow.

## 1:00-2:00 - Architecture
Show `submission_package/figures/architecture.png` and describe ingestion, parsing, rules, ML, SQLite, dashboard, email, and PDF reporting.

## 2:00-4:00 - Live Dashboard
Open http://localhost:8501 and run the sample logs. Show parsed events, rule alerts, anomaly windows, and unique sources.

## 4:00-6:00 - Alert Investigation
Open Alerts. Explain brute force, SQL injection, port scan, suspicious PowerShell, and audit-log-cleared alerts. Show evidence and MITRE mapping.

## 6:00-7:00 - ML Anomaly Detection
Open Anomalies. Explain 15-minute source-IP windows and Isolation Forest features.

## 7:00-8:00 - Log Explorer
Search for `sqlmap`, `DPT=443`, and `Failed password`.

## 8:00-9:00 - Testing Evidence
Open Evaluation. Report precision=1.0, recall=1.0, F1=1.0 on the labeled safe logs.

## 9:00-10:00 - Report and Email
Generate the PDF report and show Email settings. Explain that SMTP password is used only at send time and is not stored.
