"""Streamlit dashboard for processed SOC L1 alert data."""
import json
from pathlib import Path
import pandas as pd
import streamlit as st

st.set_page_config(page_title="SOC L1 Triage", page_icon="🛡️", layout="wide")
st.title("🛡️ SOC L1 Alert Triage & Escalation")
st.caption("Training dashboard — analyst validation is required before escalation.")

data_path = Path("output/processed_alerts.json")
uploaded = st.sidebar.file_uploader("Load processed alerts JSON", type=["json"])
if uploaded:
    records = json.load(uploaded)
elif data_path.exists():
    records = json.loads(data_path.read_text(encoding="utf-8"))
else:
    st.info("No processed alerts found. Run: python -m soc_l1.cli run --input data/sample_alerts.json")
    st.stop()

if not records:
    st.warning("No alerts in the selected dataset.")
    st.stop()

df = pd.DataFrame(records)
for col in ["risk_score", "recommendation", "severity", "urgency", "is_duplicate"]:
    if col not in df:
        df[col] = None

new_df = df[df["is_duplicate"] != True]
escalate = new_df[new_df["recommendation"] == "ESCALATE"]
investigate = new_df[new_df["recommendation"] == "INVESTIGATE"]
monitor = new_df[new_df["recommendation"] == "MONITOR"]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Alerts", len(df))
c2.metric("Escalation candidates", len(escalate))
c3.metric("Investigate", len(investigate))
c4.metric("Duplicates", int((df["is_duplicate"] == True).sum()))

st.subheader("Risk distribution")
st.bar_chart(new_df["recommendation"].value_counts())

st.subheader("Alert queue")
columns = [c for c in ["alert_id", "timestamp", "title", "severity", "urgency", "risk_score", "recommendation", "src_ip", "dest_ip", "user", "host"] if c in df.columns]
st.dataframe(new_df[columns].sort_values("risk_score", ascending=False), use_container_width=True, hide_index=True)

st.subheader("Escalation details")
if len(escalate):
    selected_id = st.selectbox("Select an escalation candidate", escalate["alert_id"].astype(str).tolist())
    selected = next(x for x in records if str(x.get("alert_id")) == selected_id)
    st.write(f"**{selected.get('title')}** — score {selected.get('risk_score')}/100")
    st.write("**Reasons**")
    for reason in selected.get("reasons", []):
        st.write(f"- {reason}")
    st.write("**MITRE ATT&CK:**", selected.get("mitre_technique") or "Not mapped")
    st.write("**Threat intelligence:**", selected.get("threat_intel") or "Not queried")
else:
    st.success("No new escalation candidates in this dataset.")

st.warning("Do not use this dashboard as the sole basis for containment or incident closure.")
