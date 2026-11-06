"""Optional VirusTotal IP reputation lookup. Does not upload files."""
import os
from typing import Any
import requests

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

def enrich_ip(ip: str) -> dict[str, Any] | None:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key or not ip:
        return None
    response = requests.get(
        VT_URL + ip,
        headers={"x-apikey": api_key},
        timeout=20,
    )
    if response.status_code == 404:
        return {"found": False, "note": "IP not present in VirusTotal lookup."}
    response.raise_for_status()
    attrs = response.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "reputation": attrs.get("reputation", 0),
    }

def enrich_alert(alert: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(alert)
    ip = alert.get("src_ip", "")
    try:
        enriched["threat_intel"] = enrich_ip(ip)
    except requests.RequestException as exc:
        enriched["threat_intel"] = {"error": str(exc)}
    return enriched
