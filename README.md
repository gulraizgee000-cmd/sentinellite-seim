# SentinelLite SIEM

SentinelLite is a lightweight Information Security semester project for log analysis, rule-based detection, and anomaly scoring. It is designed for the project brief category:

**Category D - Log Analysis & SIEM Lite with Anomaly Detection**

Student:

- Gulraiz Dilawar
- ID: F2023376392
- Course: Information Security (D1)

## What It Does

- Parses Apache access logs, Linux auth/syslog logs, and Windows event CSV logs.
- Detects explainable security events with rule-based logic.
- Scores abnormal source-IP windows with Isolation Forest anomaly detection.
- Stores analysis runs in SQLite.
- Shows a Streamlit dashboard for alerts, anomalies, logs, and history.
- Generates a PDF security report with summary tables.
- Includes optional SMTP email alert delivery with password/app-password entry at send time.

## Detection Coverage

- SQL injection probes
- Path traversal probes
- Scanner-like user agents
- Repeated 404 enumeration
- Port scan patterns from firewall/syslog events
- SSH/login brute-force bursts
- Successful login after repeated failures
- Suspicious PowerShell execution
- Windows audit log clearing

## Setup

From this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Or run the helper script:

```powershell
.\run_sentinellite.ps1
```

Then open the local dashboard URL shown by Streamlit, usually `http://localhost:8501`.

## Safe Sample Logs

The `sample_logs` folder contains safe, realistic logs using documentation-only IP ranges:

- `192.0.2.0/24`
- `198.51.100.0/24`
- `203.0.113.0/24`

These are reserved for examples and do not identify real systems.

## Smoke Test

```powershell
python tests\smoke_test.py
```

The smoke test parses sample logs, runs detections, generates anomalies, and creates a PDF report.

Accuracy evaluation:

```powershell
python tests\evaluate_detection.py
```

Expected sample result: `precision=1.0`, `recall=1.0`, `f1_score=1.0` on the included labeled safe logs.

## Documentation Drafts

The `docs` folder includes:

- `project_proposal_draft.md`
- `test_plan.md`
- `viva_notes.md`
- `requirements_compliance.md`

The `submission_package` folder includes proposal, literature review, design document, testing report, final technical report, viva slides, demo script, and readiness checklist.

## GitHub Submission Notes

Recommended repository name: `sentinellite-seim` or `sentinellite-siem`.

Suggested evaluator flow:

1. Read this `README.md`.
2. Run the setup commands above.
3. Open the dashboard and analyze the included `sample_logs` folder.
4. Review `docs/requirements_compliance.md`.
5. Review the assignment deliverables inside `submission_package`.

Do not commit `.venv`, local `.env` files, generated SQLite databases, or runtime report exports. The included sample logs are safe and should remain in the repository.

## Suggested Demo Flow

1. Open the dashboard.
2. Run analysis with the included sample logs.
3. Show the overview metrics.
4. Open the Alerts tab and explain two rules.
5. Open the Anomalies tab and explain Isolation Forest scoring.
6. Search logs for `sqlmap`, `powershell`, or `Failed password`.
7. Generate the PDF report.
8. Show Email Options and explain SMTP alert delivery. A password/app password is required only when sending and is not stored.

## Academic Integrity Note

This project uses open-source Python libraries and generated safe sample data. Any final submission should cite Python, Streamlit, Pandas, Scikit-learn, ReportLab, and the course project brief where relevant.
