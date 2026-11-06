"""Indicative MITRE ATT&CK technique mapping."""
import json
from pathlib import Path
from typing import Any

MAPPING_FILE = Path(__file__).resolve().parents[1] / "config" / "mitre_mapping.json"

def map_technique(event_type: str, custom_technique: str = "") -> dict[str, Any] | None:
    if custom_technique:
        return {"technique": custom_technique, "name": "Provided by source alert", "note": "Validate mapping against observed behaviour."}
    mapping = json.loads(MAPPING_FILE.read_text(encoding="utf-8"))
    return mapping.get(str(event_type).lower())
