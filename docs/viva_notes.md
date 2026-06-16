# Viva Notes

## Why This Project?

SentinelLite solves a practical security monitoring problem for small environments that cannot deploy heavy SIEM tools. It demonstrates log ingestion, detection engineering, anomaly detection, reporting, and incident response thinking.

## Security Mechanisms Used

- Rule-based detection for known attack signatures and behaviors.
- Unsupervised anomaly detection for behavior that differs from baseline windows.
- Risk scoring based on severity.
- MITRE ATT&CK mapping for professional incident classification.
- SQLite persistence for auditability.
- Optional SMTP email alerting for high-priority findings.
- PDF reporting for incident documentation.

## How Isolation Forest Is Used

The system groups events into 15-minute windows per source IP. Each window is converted into numeric features:

- total event count
- failed login count
- HTTP error count
- unique path count
- POST request count
- scanner user-agent count
- firewall block count

Isolation Forest then isolates unusual windows. Windows that are easier to isolate are treated as more anomalous.

## Why Combine Rules And ML?

Rules are precise and explainable for known attack patterns. ML can find unusual behavior even when it does not exactly match a known rule. Combining both reduces the weakness of relying on only one method.

## Expected Questions

### What happens if the ML model is wrong?

The anomaly result is treated as a triage signal, not final proof of compromise. The analyst should confirm it using raw logs and rule-based alerts.

### Why not use a full SIEM like Splunk?

The project targets lightweight academic and small-lab environments. Full SIEM platforms are powerful but expensive and complex. SentinelLite focuses on core SIEM concepts in a simpler deployable form.

### What is the worst-case limitation?

SentinelLite cannot detect attacks that leave no logs, attacks hidden inside encrypted payloads before the web server logs them, or new behaviors that look identical to normal activity.

### What future feature would be added first?

Scheduled scanning and richer MITRE ATT&CK reporting. SMTP email delivery is already implemented as an optional configured action.
