from __future__ import annotations

from datetime import datetime
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from sentinellite.anomaly import detect_anomalies
from sentinellite.database import load_email_settings, load_runs, save_email_settings, save_run
from sentinellite.email_alerts import build_email_preview, email_delivery_status, send_alert_digest
from sentinellite.evaluation import evaluate_alerts, load_expected_alerts
from sentinellite.parsers import parse_paths, parse_uploaded_file
from sentinellite.report import generate_pdf_report
from sentinellite.rules import apply_detection_rules


ROOT = Path(__file__).resolve().parent
SAMPLE_DIR = ROOT / "sample_logs"
REPORT_DIR = ROOT / "reports"
EXPECTED_ALERTS = ROOT / "tests" / "expected_alerts.csv"
ANALYST = "Gulraiz Dilawar"
STUDENT_ID = "F2023376392"
COURSE = "Information Security (D1)"

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_COLORS = {
    "critical": "#be123c",
    "high": "#dc6b19",
    "medium": "#ca8a04",
    "low": "#0f766e",
}


st.set_page_config(
    page_title="SentinelLite SIEM",
    page_icon="S",
    layout="wide",
)


def main() -> None:
    _style()
    use_samples, uploaded_files, contamination, run_button = _sidebar()

    if "analysis" not in st.session_state or run_button:
        with st.spinner("Parsing logs, applying detection rules, and scoring anomalies..."):
            logs = _load_logs(use_samples, uploaded_files)
            alerts = apply_detection_rules(logs)
            anomalies = detect_anomalies(logs, contamination=contamination)
            run_id = save_run(logs, alerts, anomalies, ANALYST)
            expected = load_expected_alerts(EXPECTED_ALERTS)
            eval_table, eval_metrics = evaluate_alerts(alerts, expected)
            st.session_state.analysis = {
                "logs": logs,
                "alerts": alerts,
                "anomalies": anomalies,
                "run_id": run_id,
                "eval_table": eval_table,
                "eval_metrics": eval_metrics,
                "contamination": contamination,
            }

    analysis = st.session_state.analysis
    logs = analysis["logs"]
    alerts = analysis["alerts"]
    anomalies = analysis["anomalies"]
    eval_table = analysis["eval_table"]
    eval_metrics = analysis["eval_metrics"]
    run_id = analysis["run_id"]

    _header(logs, alerts, anomalies, eval_metrics, run_id)

    overview_tab, alerts_tab, anomaly_tab, logs_tab, eval_tab, report_tab, email_tab = st.tabs(
        ["Overview", "Alerts", "Anomalies", "Log Explorer", "Evaluation", "Report", "Email"]
    )

    with overview_tab:
        _overview(logs, alerts, anomalies)
    with alerts_tab:
        _alerts(alerts, logs)
    with anomaly_tab:
        _anomalies(anomalies)
    with logs_tab:
        _log_explorer(logs)
    with eval_tab:
        _evaluation(eval_table, eval_metrics)
    with report_tab:
        _report(logs, alerts, anomalies, run_id)
    with email_tab:
        _email_options(alerts)


def _sidebar():
    with st.sidebar:
        st.markdown("<div class='side-title'>SentinelLite Console</div>", unsafe_allow_html=True)
        st.markdown(
            f"""
            <div class="identity-card">
              <div class="label">Analyst</div><div class="value">{ANALYST}</div>
              <div class="label">Student ID</div><div class="value">{STUDENT_ID}</div>
              <div class="label">Course</div><div class="value">{COURSE}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("#### Data Source")
        use_samples = st.toggle("Use included safe sample logs", value=True)
        uploaded_files = st.file_uploader(
            "Upload Apache, syslog, or Windows CSV logs",
            type=["log", "txt", "csv"],
            accept_multiple_files=True,
            help="Supports Apache combined logs, Linux auth/syslog-style logs, firewall syslog lines, and Windows Event CSV files.",
        )
        st.markdown("#### Detection")
        contamination = st.slider(
            "ML anomaly sensitivity",
            0.05,
            0.35,
            0.15,
            0.05,
            help="Higher sensitivity flags more source-IP windows as anomalous.",
        )
        run_button = st.button("Run SIEM Analysis", type="primary", width="stretch")
        st.caption("Tip: search the Log Explorer for sqlmap, powershell, DPT=, or Failed password during the demo.")
    return use_samples, uploaded_files, contamination, run_button


def _load_logs(use_samples: bool, uploaded_files) -> pd.DataFrame:
    frames = []
    if use_samples:
        frames.append(parse_paths(sorted(SAMPLE_DIR.glob("*"))))
    for uploaded in uploaded_files or []:
        frames.append(parse_uploaded_file(uploaded.name, uploaded.getvalue()))
    if not frames:
        return parse_paths(sorted(SAMPLE_DIR.glob("*")))
    return pd.concat(frames, ignore_index=True).sort_values("timestamp", na_position="last").reset_index(drop=True)


def _header(logs: pd.DataFrame, alerts: pd.DataFrame, anomalies: pd.DataFrame, metrics: dict, run_id: str) -> None:
    critical = int((alerts["severity"] == "critical").sum()) if not alerts.empty else 0
    high = int((alerts["severity"] == "high").sum()) if not alerts.empty else 0
    risk = "Critical" if critical else "High" if high else "Guarded" if len(alerts) else "Clean"
    risk_class = risk.lower()
    st.markdown(
        f"""
        <section class="hero">
          <div>
            <div class="eyebrow">Security Information and Event Management</div>
            <h1>SentinelLite SIEM</h1>
            <p>Rule-based threat detection, Isolation Forest anomaly scoring, forensic log review, and report-ready evidence for the Information Security project.</p>
          </div>
          <div class="status-card {risk_class}">
            <span>Current Risk</span>
            <strong>{risk}</strong>
            <small>Run {run_id}</small>
          </div>
        </section>
        """,
        unsafe_allow_html=True,
    )
    c1, c2, c3, c4, c5 = st.columns(5)
    _metric_card(c1, "Log Events", len(logs), "Parsed across all sources")
    _metric_card(c2, "Rule Alerts", len(alerts), "Explainable detections")
    _metric_card(c3, "Anomalies", len(anomalies), "ML-scored windows")
    _metric_card(c4, "Unique Sources", logs["source_ip"].replace("", pd.NA).dropna().nunique(), "Distinct source IPs")
    _metric_card(c5, "Eval F1", f"{metrics.get('f1_score', 0):.2f}", "Labeled sample set")


def _metric_card(column, label: str, value, detail: str) -> None:
    column.markdown(
        f"""
        <div class="metric-card">
          <span>{label}</span>
          <strong>{value}</strong>
          <small>{detail}</small>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _overview(logs: pd.DataFrame, alerts: pd.DataFrame, anomalies: pd.DataFrame) -> None:
    left, right = st.columns([1.15, 1])
    with left:
        st.markdown("### Alert Severity Mix")
        severity_counts = (
            alerts["severity"].value_counts().reindex(SEVERITY_ORDER).fillna(0).reset_index()
            if not alerts.empty
            else pd.DataFrame({"severity": SEVERITY_ORDER, "count": [0, 0, 0, 0]})
        )
        severity_counts.columns = ["severity", "count"]
        chart = (
            alt.Chart(severity_counts)
            .mark_bar(cornerRadiusTopLeft=5, cornerRadiusTopRight=5)
            .encode(
                x=alt.X("severity:N", sort=SEVERITY_ORDER, title=None),
                y=alt.Y("count:Q", title="Alerts"),
                color=alt.Color("severity:N", scale=alt.Scale(domain=list(SEVERITY_COLORS), range=list(SEVERITY_COLORS.values())), legend=None),
                tooltip=["severity", "count"],
            )
            .properties(height=285)
        )
        st.altair_chart(chart, width="stretch")

    with right:
        st.markdown("### Top Source IPs")
        source_counts = logs[logs["source_ip"].ne("")]["source_ip"].value_counts().head(8).reset_index()
        source_counts.columns = ["source_ip", "events"]
        chart = (
            alt.Chart(source_counts)
            .mark_bar(cornerRadiusTopRight=5, cornerRadiusBottomRight=5, color="#0f766e")
            .encode(
                y=alt.Y("source_ip:N", sort="-x", title=None),
                x=alt.X("events:Q", title="Events"),
                tooltip=["source_ip", "events"],
            )
            .properties(height=285)
        )
        st.altair_chart(chart, width="stretch")

    lower_left, lower_right = st.columns([1, 1])
    with lower_left:
        st.markdown("### Detection Categories")
        if alerts.empty:
            st.info("No alert categories to display.")
        else:
            category_counts = alerts["category"].value_counts().reset_index()
            category_counts.columns = ["category", "alerts"]
            st.altair_chart(
                alt.Chart(category_counts)
                .mark_arc(innerRadius=64, outerRadius=122)
                .encode(theta="alerts:Q", color=alt.Color("category:N", legend=alt.Legend(title=None)), tooltip=["category", "alerts"])
                .properties(height=300),
                width="stretch",
            )
    with lower_right:
        st.markdown("### Event Timeline")
        timeline = logs.dropna(subset=["timestamp"]).copy()
        timeline["window"] = timeline["timestamp"].dt.floor("5min")
        timeline = timeline.groupby(["window", "log_type"]).size().reset_index(name="events")
        st.altair_chart(
            alt.Chart(timeline)
            .mark_line(point=True)
            .encode(x=alt.X("window:T", title=None), y=alt.Y("events:Q"), color=alt.Color("log_type:N", title=None), tooltip=["window", "log_type", "events"])
            .properties(height=300),
            width="stretch",
        )

    st.markdown("### Recent Analysis Runs")
    runs = load_runs()
    if runs.empty:
        st.caption("No saved run history yet.")
    else:
        st.dataframe(runs.head(8), width="stretch", hide_index=True)


def _alerts(alerts: pd.DataFrame, logs: pd.DataFrame) -> None:
    st.markdown("### Rule-Based Detection Alerts")
    if alerts.empty:
        st.success("No rule-based security alerts were generated.")
        return

    filter_col, phase_col, source_col = st.columns([1, 1, 1])
    severity_filter = filter_col.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER)
    phases = sorted(alerts["attack_phase"].dropna().unique()) if "attack_phase" in alerts else []
    phase_filter = phase_col.multiselect("Attack phase", phases, default=phases)
    sources = sorted(alerts["source_ip"].replace("", pd.NA).dropna().unique())
    source_filter = source_col.multiselect("Source IP", sources, default=sources)

    filtered = alerts.copy()
    if severity_filter:
        filtered = filtered[filtered["severity"].isin(severity_filter)]
    if phase_filter and "attack_phase" in filtered:
        filtered = filtered[filtered["attack_phase"].isin(phase_filter)]
    if source_filter:
        filtered = filtered[filtered["source_ip"].isin(source_filter)]

    st.dataframe(
        filtered[
            [
                "timestamp",
                "severity",
                "risk_score",
                "confidence",
                "attack_phase",
                "alert_name",
                "source_ip",
                "user",
                "evidence",
                "mitre_technique",
                "recommendation",
            ]
        ],
        width="stretch",
        hide_index=True,
        column_config={
            "risk_score": st.column_config.ProgressColumn("risk_score", min_value=0, max_value=100),
            "recommendation": st.column_config.TextColumn("recommendation", width="large"),
            "evidence": st.column_config.TextColumn("evidence", width="large"),
        },
    )

    st.markdown("### Investigation Queue")
    for _, alert in filtered.head(6).iterrows():
        with st.expander(f"{str(alert['severity']).upper()} - {alert['alert_name']} from {alert.get('source_ip', 'unknown')}"):
            st.write(alert.get("evidence", ""))
            c1, c2, c3 = st.columns(3)
            c1.metric("Risk score", int(alert["risk_score"]))
            c2.metric("Confidence", alert.get("confidence", "medium"))
            c3.metric("MITRE", alert.get("mitre_technique", "N/A").split(" - ")[0])
            st.markdown(f"**Recommended response:** {alert.get('recommendation', '')}")
            related = logs[logs["source_ip"].eq(alert.get("source_ip", ""))].tail(8)
            if not related.empty:
                st.dataframe(related[["timestamp", "event_type", "raw_message"]], width="stretch", hide_index=True)


def _anomalies(anomalies: pd.DataFrame) -> None:
    st.markdown("### ML Anomaly Detection")
    st.caption("Isolation Forest scores 15-minute source-IP windows using event volume, failed logins, HTTP errors, unique paths, POST volume, scanner indicators, and firewall blocks.")
    if anomalies.empty:
        st.info("No anomaly windows were generated. Try increasing anomaly sensitivity or adding more varied logs.")
        return
    st.dataframe(
        anomalies,
        width="stretch",
        hide_index=True,
        column_config={"anomaly_score": st.column_config.ProgressColumn("anomaly_score", min_value=0, max_value=100)},
    )
    timeline = anomalies.sort_values("timestamp")
    st.altair_chart(
        alt.Chart(timeline)
        .mark_circle(size=180)
        .encode(
            x=alt.X("timestamp:T", title=None),
            y=alt.Y("anomaly_score:Q", title="Anomaly score"),
            color=alt.Color("severity:N", scale=alt.Scale(domain=["high", "medium", "low"], range=["#be123c", "#ca8a04", "#0f766e"])),
            tooltip=["timestamp", "entity", "anomaly_score", "reason"],
        )
        .properties(height=340),
        width="stretch",
    )


def _log_explorer(logs: pd.DataFrame) -> None:
    st.markdown("### Log Explorer")
    log_types = sorted(logs["log_type"].dropna().unique())
    event_types = sorted(logs["event_type"].dropna().unique())
    c1, c2, c3 = st.columns([1, 1, 1.3])
    selected_types = c1.multiselect("Log type", log_types, default=log_types)
    selected_events = c2.multiselect("Event type", event_types, default=event_types)
    search = c3.text_input("Search raw log text", placeholder="sqlmap, powershell, Failed password, DPT=443")
    filtered = logs[logs["log_type"].isin(selected_types)] if selected_types else logs
    filtered = filtered[filtered["event_type"].isin(selected_events)] if selected_events else filtered
    if search:
        filtered = filtered[filtered["raw_message"].str.contains(search, case=False, na=False)]
    st.dataframe(
        filtered,
        width="stretch",
        hide_index=True,
        column_config={"raw_message": st.column_config.TextColumn("raw_message", width="large")},
    )


def _evaluation(eval_table: pd.DataFrame, metrics: dict) -> None:
    st.markdown("### Detection Accuracy On Labeled Sample Logs")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Precision", f"{metrics.get('precision', 0):.2f}")
    c2.metric("Recall", f"{metrics.get('recall', 0):.2f}")
    c3.metric("F1 score", f"{metrics.get('f1_score', 0):.2f}")
    c4.metric("Matched groups", f"{metrics.get('matched_groups', 0)}/{metrics.get('expected_groups', 0)}")
    st.dataframe(eval_table, width="stretch", hide_index=True)
    st.info("Metrics are group-level for the included safe dataset: alert name plus source IP. This makes the evaluation explainable during viva.")


def _report(logs: pd.DataFrame, alerts: pd.DataFrame, anomalies: pd.DataFrame, run_id: str) -> None:
    st.markdown("### PDF Analysis Report")
    st.write("Generate a concise security report for project evidence, lab demo, or appendix material.")
    if st.button("Generate PDF Report", width="content"):
        output_path = REPORT_DIR / f"sentinellite_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        generate_pdf_report(output_path, logs, alerts, anomalies, ANALYST, COURSE, run_id)
        st.session_state.latest_report = output_path
    report_path = st.session_state.get("latest_report")
    if report_path and Path(report_path).exists():
        st.success(f"Report generated: {Path(report_path).name}")
        st.download_button(
            "Download PDF",
            data=Path(report_path).read_bytes(),
            file_name=Path(report_path).name,
            mime="application/pdf",
        )


def _email_options(alerts: pd.DataFrame) -> None:
    st.markdown("### Email Alerting")
    settings = load_email_settings()
    with st.form("email_settings"):
        enabled = st.toggle("Enable email alerts", value=settings["enabled"])
        min_severity = st.selectbox(
            "Minimum severity",
            SEVERITY_ORDER,
            index=SEVERITY_ORDER.index(settings.get("min_severity", "high")),
        )
        smtp_host = st.text_input("SMTP host", value=settings["smtp_host"], placeholder="smtp.gmail.com")
        smtp_port = st.number_input("SMTP port", value=int(settings["smtp_port"]), min_value=1, max_value=65535)
        sender_email = st.text_input("Sender email", value=settings["sender_email"], placeholder="alerts@example.com")
        recipient_email = st.text_input("Recipient email", value=settings["recipient_email"], placeholder="analyst@example.com")
        saved = st.form_submit_button("Save Email Options")
    if saved:
        save_email_settings(
            {
                "enabled": enabled,
                "smtp_host": smtp_host,
                "smtp_port": smtp_port,
                "sender_email": sender_email,
                "recipient_email": recipient_email,
                "min_severity": min_severity,
            }
        )
        st.success("Email settings saved.")

    st.info(email_delivery_status(enabled))
    left, right = st.columns([1.1, 0.9])
    with left:
        st.markdown("#### Alert Digest Preview")
        st.code(build_email_preview(alerts, min_severity), language="text")
    with right:
        st.markdown("#### Send Test")
        smtp_password = st.text_input(
            "SMTP password/app password",
            type="password",
            help="Used only for this send action. SentinelLite does not store this password.",
        )
        if st.button("Send Alert Digest Now"):
            active_settings = load_email_settings()
            ok, message = send_alert_digest(alerts, active_settings, smtp_password)
            if ok:
                st.success(message)
            else:
                st.warning(message)


def _style() -> None:
    st.markdown(
        """
        <style>
        :root {
          --ink: #172033;
          --muted: #65758b;
          --line: #d8e0e7;
          --panel: #ffffff;
          --bg: #eef3f5;
          --teal: #0f766e;
          --amber: #b7791f;
          --rose: #be123c;
          --blue: #1d4ed8;
        }
        .stApp {
            background: var(--bg);
            color: var(--ink);
        }
        h1, h2, h3 {
            color: var(--ink);
            letter-spacing: 0;
        }
        .block-container {
            padding-top: 1.6rem;
            max-width: 1280px;
        }
        [data-testid="stSidebar"] {
            background: #f6f8fa;
            border-right: 1px solid var(--line);
        }
        [data-testid="stSidebar"] h4 {
            margin-top: 1.1rem;
        }
        .side-title {
            font-weight: 800;
            font-size: 1.15rem;
            color: var(--ink);
            margin: .3rem 0 1rem 0;
        }
        .identity-card {
            background: #ffffff;
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: .85rem;
            margin-bottom: 1rem;
            box-shadow: 0 8px 24px rgba(23, 32, 51, .05);
        }
        .identity-card .label {
            color: var(--muted);
            font-size: .73rem;
            text-transform: uppercase;
            font-weight: 750;
            margin-top: .35rem;
        }
        .identity-card .value {
            color: var(--ink);
            font-weight: 700;
            margin-bottom: .35rem;
        }
        .hero {
            display: flex;
            justify-content: space-between;
            align-items: stretch;
            gap: 1rem;
            padding: 1.15rem 1.2rem;
            background: linear-gradient(135deg, #ffffff 0%, #f9fbfc 100%);
            border: 1px solid var(--line);
            border-radius: 8px;
            box-shadow: 0 12px 32px rgba(23, 32, 51, .06);
            margin-bottom: 1rem;
        }
        .hero h1 {
            margin: .15rem 0 .3rem 0;
            font-size: clamp(2rem, 4vw, 3rem);
            line-height: 1.05;
        }
        .hero p {
            color: var(--muted);
            max-width: 820px;
            margin: 0;
            font-size: 1rem;
        }
        .eyebrow {
            color: var(--teal);
            text-transform: uppercase;
            font-size: .72rem;
            font-weight: 800;
            letter-spacing: .08em;
        }
        .status-card {
            min-width: 180px;
            border-radius: 8px;
            padding: 1rem;
            display: flex;
            flex-direction: column;
            justify-content: center;
            border: 1px solid var(--line);
            background: #f8fafc;
        }
        .status-card span, .status-card small {
            color: var(--muted);
            font-weight: 700;
            font-size: .78rem;
        }
        .status-card strong {
            font-size: 1.65rem;
            line-height: 1.1;
            color: var(--ink);
        }
        .status-card.critical { border-color: #fecdd3; background: #fff1f2; }
        .status-card.high { border-color: #fed7aa; background: #fff7ed; }
        .status-card.guarded { border-color: #bae6fd; background: #eff6ff; }
        .status-card.clean { border-color: #99f6e4; background: #f0fdfa; }
        .metric-card {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: .9rem .95rem;
            min-height: 108px;
            box-shadow: 0 10px 22px rgba(23, 32, 51, .045);
        }
        .metric-card span {
            display: block;
            color: var(--muted);
            font-weight: 800;
            text-transform: uppercase;
            font-size: .72rem;
        }
        .metric-card strong {
            display: block;
            color: var(--ink);
            font-size: 2rem;
            line-height: 1.2;
            margin-top: .35rem;
        }
        .metric-card small {
            color: var(--muted);
            font-size: .78rem;
        }
        div[data-testid="stButton"] > button {
            border-radius: 8px;
            font-weight: 750;
        }
        div[data-testid="stDataFrame"] {
            border: 1px solid var(--line);
            border-radius: 8px;
            overflow: hidden;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: .35rem;
        }
        .stTabs [data-baseweb="tab"] {
            border-radius: 8px 8px 0 0;
            padding: .7rem .85rem;
            font-weight: 700;
        }
        @media (max-width: 900px) {
            .hero { flex-direction: column; }
            .status-card { min-width: 0; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
