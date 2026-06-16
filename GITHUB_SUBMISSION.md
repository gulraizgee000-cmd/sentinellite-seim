# GitHub Submission Guide

Project: SentinelLite SIEM  
Course: Information Security (D1)  
Student: Gulraiz Dilawar  
ID: F2023376392

## Repository Contents

- `app.py`: Streamlit dashboard.
- `sentinellite/`: parser, rule engine, anomaly detection, reporting, database, and email modules.
- `sample_logs/`: safe realistic logs for Apache, Linux auth/syslog, firewall, and Windows events.
- `tests/`: smoke test and labeled detection evaluation.
- `docs/`: project planning, test plan, viva notes, and requirements compliance audit.
- `submission_package/`: proposal, literature review, design document, security testing report, final report, viva slides, and demo script.

## Run Commands

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Open the Streamlit URL shown in the terminal, usually:

```text
http://localhost:8501
```

## Validation Commands

```powershell
python tests\smoke_test.py
python tests\evaluate_detection.py
```

Expected result on the included labeled sample logs:

```text
precision=1.0
recall=1.0
f1_score=1.0
```

## Submission Checklist

- GitHub repository contains source code, sample logs, tests, and documentation.
- `submission_package/phase6_final_technical_report.pdf` is included.
- `submission_package/phase7_viva_presentation.pptx` is included.
- Demo video must still be recorded by the student using `submission_package/demo_video_script.md`.
- Academic integrity declaration/signature must be added if required by the instructor.
- Confirm with the instructor if submitting as an individual, because the brief expects teams unless individual approval is granted.
