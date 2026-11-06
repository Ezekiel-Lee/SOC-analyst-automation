"""Alert ingestion from JSON or Splunk ES saved-search REST export."""
import json
import os
from pathlib import Path
from typing import Any
import requests

def load_json_alerts(path: str | Path) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("alerts", data.get("results", []))
    if not isinstance(data, list):
        raise ValueError("Input JSON must be an array or an object containing an alerts/results array.")
    return [normalise_alert(item) for item in data]

def normalise_alert(raw: dict[str, Any]) -> dict[str, Any]:
    """Map common Splunk ES and generic field names into the project's schema."""
    return {
        "alert_id": raw.get("alert_id") or raw.get("event_id") or raw.get("rule_id") or raw.get("sid") or "UNKNOWN",
        "timestamp": raw.get("timestamp") or raw.get("_time") or raw.get("time") or "",
        "title": raw.get("title") or raw.get("rule_name") or raw.get("search_name") or raw.get("name") or "Untitled alert",
        "event_type": raw.get("event_type") or raw.get("category") or raw.get("security_domain") or "unknown",
        "severity": str(raw.get("severity", "unknown")).lower(),
        "urgency": str(raw.get("urgency", "unknown")).lower(),
        "status": str(raw.get("status", "new")).lower(),
        "disposition": str(raw.get("disposition", "")).lower(),
        "src_ip": raw.get("src_ip") or raw.get("src") or "",
        "dest_ip": raw.get("dest_ip") or raw.get("dest") or "",
        "user": raw.get("user") or raw.get("user_name") or "",
        "host": raw.get("host") or raw.get("dest_nt_host") or "",
        "failed_login_count": int(raw.get("failed_login_count", raw.get("count", 0)) or 0),
        "privileged_account": raw.get("privileged_account", False) in (True, "true", "True", 1, "1"),
        "mitre_technique": raw.get("mitre_technique", ""),
        "description": raw.get("description") or raw.get("orig_sourcetype") or "",
    }

def load_splunk_alerts() -> list[dict[str, Any]]:
    host = os.getenv("SPLUNK_HOST", "").rstrip("/")
    token = os.getenv("SPLUNK_TOKEN", "")
    saved_search = os.getenv("SPLUNK_SAVED_SEARCH", "")
    verify_tls = os.getenv("SPLUNK_VERIFY_TLS", "true").lower() == "true"
    if not all((host, token, saved_search)):
        raise RuntimeError("Set SPLUNK_HOST, SPLUNK_TOKEN, and SPLUNK_SAVED_SEARCH in .env.")
    url = f"{host}/services/search/jobs/export"
    query = f'| savedsearch "{saved_search}"'
    response = requests.post(
        url,
        headers={"Authorization": f"Bearer {token}"},
        data={"search": query, "output_mode": "json"},
        timeout=60,
        verify=verify_tls,
    )
    response.raise_for_status()
    results = []
    for line in response.text.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if "result" in item:
            results.append(normalise_alert(item["result"]))
    return results
