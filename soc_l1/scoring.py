"""Transparent configurable alert scoring."""
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES = ROOT / "config" / "risk_rules.json"

def load_rules(path: str | Path = DEFAULT_RULES) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))

def score_alert(alert: dict[str, Any], rules: dict[str, Any] | None = None) -> dict[str, Any]:
    rules = rules or load_rules()
    disposition = str(alert.get("disposition", "")).strip().lower()
    if disposition in rules["benign_dispositions"]:
        return {
            "risk_score": 0,
            "recommendation": "MONITOR",
            "reasons": ["Analyst disposition is marked benign/known-good; verify evidence and closure procedure."],
        }

    score = 0
    reasons: list[str] = []
    severity = str(alert.get("severity", "")).lower()
    urgency = str(alert.get("urgency", "")).lower()
    event_type = str(alert.get("event_type", "")).lower()

    severity_points = rules["severity_points"].get(severity, 0)
    if severity_points:
        score += severity_points
        reasons.append(f"{severity.title()} severity (+{severity_points}).")

    urgency_points = rules["urgency_points"].get(urgency, 0)
    if urgency_points:
        score += urgency_points
        if urgency in {"high", "critical"}:
            reasons.append(f"{urgency.title()} urgency (+{urgency_points}).")

    event_points = rules["event_type_points"].get(event_type, 0)
    if event_points:
        score += event_points
        reasons.append(f"High-impact event type '{event_type}' (+{event_points}).")

    failed = int(alert.get("failed_login_count", 0) or 0)
    for threshold in sorted(rules["failed_login_thresholds"], key=lambda x: x["count"], reverse=True):
        if failed >= threshold["count"]:
            score += threshold["points"]
            reasons.append(f"{failed} failed login attempts (+{threshold['points']}).")
            break

    if alert.get("privileged_account") is True:
        points = rules["privileged_account_points"]
        score += points
        reasons.append(f"Privileged account context (+{points}).")

    score = min(score, 100)
    thresholds = rules["thresholds"]
    if score >= thresholds["escalate"]:
        recommendation = "ESCALATE"
    elif score >= thresholds["investigate"]:
        recommendation = "INVESTIGATE"
    else:
        recommendation = "MONITOR"

    if not reasons:
        reasons.append("No configured scoring indicators matched; analyst context review is still required.")

    return {"risk_score": score, "recommendation": recommendation, "reasons": reasons}
