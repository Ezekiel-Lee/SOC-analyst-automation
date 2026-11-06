"""Explicitly opt-in Jira Cloud issue creation."""
import os
import requests
from typing import Any

def create_issue(alert: dict[str, Any]) -> dict[str, Any]:
    base = os.getenv("JIRA_BASE_URL", "").rstrip("/")
    email = os.getenv("JIRA_EMAIL", "")
    token = os.getenv("JIRA_API_TOKEN", "")
    project = os.getenv("JIRA_PROJECT_KEY", "")
    issue_type = os.getenv("JIRA_ISSUE_TYPE", "Task")
    if not all((base, email, token, project)):
        raise RuntimeError("Set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, and JIRA_PROJECT_KEY.")
    reasons = alert.get("reasons", [])
    description = (
        f"Training/demo triage recommendation: {alert.get('recommendation')}\n"
        f"Risk score: {alert.get('risk_score')}/100\n"
        f"Severity / urgency: {alert.get('severity')} / {alert.get('urgency')}\n"
        f"Event type: {alert.get('event_type')}\n"
        f"Source / destination: {alert.get('src_ip')} / {alert.get('dest_ip')}\n"
        f"User / host: {alert.get('user')} / {alert.get('host')}\n"
        f"Reasons: {'; '.join(reasons) if isinstance(reasons, list) else reasons}\n\n"
        "Analyst must validate evidence and follow the approved incident response playbook."
    )
    payload = {
        "fields": {
            "project": {"key": project},
            "summary": f"[SOC L1] {alert.get('title', 'Security alert')} ({alert.get('alert_id', 'N/A')})",
            "description": description,
            "issuetype": {"name": issue_type},
            "labels": ["soc-l1", "security-triage", "human-review-required"]
        }
    }
    response = requests.post(
        f"{base}/rest/api/3/issue",
        json=payload,
        auth=(email, token),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()
