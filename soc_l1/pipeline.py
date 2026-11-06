"""Orchestrates ingestion, enrichment, scoring, deduplication and reports."""
from pathlib import Path
from typing import Any
from soc_l1.scoring import score_alert
from soc_l1.mitre import map_technique
from soc_l1.dedup import Deduplicator
from soc_l1.enrichment import enrich_alert
from soc_l1.reporting import write_outputs

def process_alerts(
    alerts: list[dict[str, Any]],
    output_dir: str | Path = "output",
    enrich: bool = False,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    dedup = Deduplicator(db_path or (out / "triage.db"))
    results = []
    for original in alerts:
        alert = enrich_alert(original) if enrich else dict(original)
        scored = score_alert(alert)
        alert.update(scored)
        mapping = map_technique(alert.get("event_type", ""), alert.get("mitre_technique", ""))
        alert["mitre_technique"] = mapping.get("technique") if mapping else ""
        alert["mitre_name"] = mapping.get("name") if mapping else ""
        alert["mitre_note"] = mapping.get("note") if mapping else ""
        dedup_result = dedup.register(alert)
        alert.update(dedup_result)
        results.append(alert)
    results.sort(key=lambda x: (x.get("is_duplicate", False), -x.get("risk_score", 0)))
    write_outputs(results, out)
    return results
