"""CSV, JSON, and analyst-friendly Markdown reporting."""
import csv
import json
from pathlib import Path
from typing import Any

FIELDS = [
    "alert_id", "timestamp", "title", "event_type", "severity", "urgency",
    "risk_score", "recommendation", "is_duplicate", "occurrences",
    "mitre_technique", "src_ip", "dest_ip", "user", "host", "reasons"
]

def write_outputs(results: list[dict[str, Any]], output_dir: str | Path) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "processed_alerts.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    with (out / "triage_queue.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        for item in results:
            row = dict(item)
            row["reasons"] = " ".join(item.get("reasons", [])) if isinstance(item.get("reasons"), list) else item.get("reasons", "")
            writer.writerow(row)
    write_escalation_report(results, out / "escalation_report.md")

def write_escalation_report(results: list[dict[str, Any]], path: str | Path) -> None:
    selected = [x for x in results if x.get("recommendation") == "ESCALATE" and not x.get("is_duplicate")]
    lines = [
        "# SOC L1 to L2 Escalation Handover",
        "",
        f"- Alerts processed: **{len(results)}**",
        f"- New escalation candidates: **{len(selected)}**",
        "",
        "> Analyst review required. This report is a recommendation, not confirmation of compromise.",
        ""
    ]
    if not selected:
        lines.append("No new alerts met the configured escalation threshold.")
    for alert in selected:
        reasons = alert.get("reasons", [])
        if isinstance(reasons, list):
            reasons = "; ".join(reasons)
        ti = alert.get("threat_intel")
        lines += [
            f"## {alert.get('title', 'Untitled')} — {alert.get('alert_id', 'N/A')}",
            f"- Time: {alert.get('timestamp') or 'Unknown'}",
            f"- Risk score: {alert.get('risk_score', 0)}/100",
            f"- Severity / urgency: {alert.get('severity')} / {alert.get('urgency')}",
            f"- User / host: {alert.get('user') or 'Unknown'} / {alert.get('host') or 'Unknown'}",
            f"- Source / destination IP: {alert.get('src_ip') or 'Unknown'} / {alert.get('dest_ip') or 'Unknown'}",
            f"- MITRE ATT&CK: {alert.get('mitre_technique') or 'Not mapped'}",
            f"- Threat intelligence: {json.dumps(ti) if ti else 'Not queried'}",
            f"- Scoring rationale: {reasons}",
            "- L1 checks completed: [Record evidence and checks performed]",
            "- Outstanding questions: [Record unknowns]",
            "- Suggested L2 focus: Validate endpoint/authentication/network telemetry and assess scope.",
            ""
        ]
    Path(path).write_text("\n".join(lines), encoding="utf-8")
