# Project Proposal Draft

## Project Title

SentinelLite: A Lightweight SIEM with Rule-Based Detection and ML Anomaly Scoring

## Student Details

- Name: Gulraiz Dilawar
- ID: F2023376392
- Course: Information Security (D1)

## Problem Statement

Small academic labs and small organizations often generate useful security logs from web servers, Linux authentication services, and Windows endpoints, but they do not always have a full SIEM platform because tools such as Splunk, QRadar, or Elastic SIEM can be costly and complex to configure. As a result, attacks such as brute-force login attempts, web scanning, SQL injection probes, path traversal attempts, and suspicious endpoint execution may remain unnoticed. SentinelLite addresses this problem by providing a lightweight dashboard that ingests common log formats, detects known attack patterns through explainable rules, and identifies abnormal traffic windows through machine learning.

## Objectives

1. Build a working log ingestion pipeline for Apache access logs, Linux auth/syslog logs, and Windows event CSV logs.
2. Implement rule-based detection for common attacks such as SQL injection, path traversal, repeated 404 enumeration, suspicious user agents, brute-force login attempts, suspicious PowerShell, and audit-log clearing.
3. Apply unsupervised ML anomaly detection using Isolation Forest on 15-minute source-IP behavior windows.
4. Store logs, alerts, anomalies, and run history in SQLite.
5. Provide a Streamlit dashboard for security monitoring, log search, alert review, anomaly review, and PDF report generation.
6. Add email alert configuration in preview mode so SMTP delivery can be implemented as a future extension.

## Tools And Technologies

- Python: main implementation language.
- Streamlit: dashboard and demo interface.
- Pandas: log normalization, aggregation, and analysis.
- Scikit-learn: Isolation Forest anomaly detection.
- SQLite: local persistence of analysis runs.
- ReportLab: PDF security report generation.

## Expected Output

The final output is a working dashboard where the analyst can load sample or uploaded logs, run SIEM analysis, inspect alerts, review anomaly scores, search raw logs, configure future email alert options, and export a PDF report. The project also includes safe realistic sample logs for demonstration and testing.

## Team Roles

- Gulraiz Dilawar: system design, log parsing, detection rules, anomaly detection, dashboard implementation, testing, and final documentation.

If additional team members are added later, roles can be split into UI/dashboard, detection engineering, testing/reporting, and literature review.

## Risk Analysis

| Risk | Impact | Probability | Mitigation |
| --- | --- | --- | --- |
| Log formats vary between systems | Medium | High | Normalize common fields and keep raw message for fallback analysis. |
| ML anomaly results may produce false positives | Medium | Medium | Combine ML findings with explainable rules and document limitations. |
| Scikit-learn or Streamlit setup issues on lab machine | High | Medium | Keep requirements clear and provide a smoke test. |
| Sample data may be considered unrealistic | Medium | Low | Use realistic log syntax with documentation-only IP ranges. |
| Email alerts not ready for final SMTP sending | Low | Medium | Implement settings and preview now; add delivery later if required. |

## Scope

The project focuses on log-based detection and anomaly scoring. It does not attempt packet capture, real-time endpoint agents, or production-scale distributed SIEM ingestion. Those features are listed as future work.
