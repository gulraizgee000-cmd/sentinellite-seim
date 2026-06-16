# Requirements Compliance Audit

This checklist is based on the Information Security semester project brief and the selected project:

**Category D - Log Analysis & SIEM Lite with Anomaly Detection**

## Selected Project Requirements

| Requirement from brief | SentinelLite status |
| --- | --- |
| Lightweight SIEM | Fulfilled: Streamlit dashboard, parsers, alerts, anomalies, reports, local persistence. |
| Ingest syslog | Fulfilled: Linux auth/syslog and firewall-style syslog samples are parsed. |
| Ingest Windows Event Log | Fulfilled: Windows Event CSV sample is parsed and mapped by event ID. |
| Ingest Apache access logs | Fulfilled: Apache combined log parser included. |
| Rule-based failed login detection | Fulfilled: brute-force and success-after-failures rules included. |
| Rule-based SQL injection detection | Fulfilled: SQL injection pattern rule included. |
| Rule-based port scan pattern detection | Fulfilled: firewall destination-port burst rule included. |
| Unsupervised ML anomaly detection | Fulfilled: Isolation Forest is used for source-IP time windows. |
| Alert via email or Telegram | Fulfilled for email: SMTP alert digest sending is implemented when SMTP details and password are supplied. |
| SQLite or Elasticsearch | Fulfilled: SQLite run history and settings storage. |
| Kibana-like dashboard | Fulfilled: redesigned Streamlit dashboard with overview, alerts, anomalies, log explorer, evaluation, report, and email options. |
| Bonus: threat scoring | Fulfilled: severity and numeric risk score. |
| Bonus: MITRE ATT&CK mapping | Fulfilled: rules include MITRE techniques. |

## Course Deliverables Status

| Phase | Brief requirement | Current status |
| --- | --- | --- |
| 1 Proposal | 2-page proposal with problem, objectives, tools, roles, output, risk analysis | Fulfilled as draft deliverables: `submission_package/phase1_project_proposal.pdf` and `.docx`. Student must still sign/submit. |
| 2 Literature Review | 5-8 pages, minimum 8 references, gap analysis | Fulfilled as draft deliverables: `submission_package/phase2_literature_review.pdf` is 5 pages and `.docx` is included. |
| 3 Design | Architecture, DFD, threat model, technology justification | Fulfilled as draft deliverable: `submission_package/phase3_design_document.pdf`. |
| 4 Prototype | 50% features functional, test cases, GitHub repo with commit history | Fulfilled: code, tests, dashboard, and GitHub-ready repository package for `https://github.com/gulraizgee000-cmd/sentinellite-seim`. |
| 5 Final Implementation | Full system, source code, 10-minute video, security testing report, dataset | System/source/sample dataset/security testing report fulfilled. Video must still be recorded by student. |
| 6 Final Report | 15-25 page report with required sections and IEEE references | Fulfilled as draft deliverable: `submission_package/phase6_final_technical_report.pdf` is 18 pages. |
| 7 Viva/Presentation | 10-minute presentation, slides, live demo, Q&A | Fulfilled as draft deliverable: `submission_package/phase7_viva_presentation.pptx`; live demo and Q&A must be performed by student. |

## Important Submission Risks

- The brief says GitHub is required and minimum 15 meaningful commits are expected. Verify the pushed repository history before submitting the GitHub URL.
- The brief expects team size 3-4 unless individual work is approved. Current project metadata lists one student only.
- The brief requires academic declaration signatures with the proposal.
- A 10-minute video demo must be recorded by the student. A script is available in `submission_package/demo_video_script.md`.
