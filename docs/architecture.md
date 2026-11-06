# Architecture and design decisions

## Processing flow

1. Ingest alerts from a local JSON fixture or Splunk ES saved-search REST export.
2. Normalise source-specific field names to a stable internal schema.
3. Optionally enrich the source IP through VirusTotal IP reputation lookup.
4. Apply configurable, explainable scoring rules.
5. Map selected event types to indicative MITRE ATT&CK techniques.
6. Fingerprint and register events in SQLite to identify repeated alerts.
7. Export JSON, CSV, and L2 handover Markdown.
8. Display results in Streamlit.
9. Create a Jira issue only through an explicit command requiring `--confirm`.

## Why human-in-the-loop?

Severity values and risk scores are not proof of compromise. Automated containment can disrupt business operations. This project therefore recommends actions and prepares handovers, but leaves incident decisions and response actions to an authorised analyst.

## Limitations

- Rule scoring is a demo heuristic and not a trained detection model.
- ATT&CK mapping is indicative and event-type based; validate against evidence.
- Deduplication fingerprint is simple and should be tuned for each detection.
- Splunk REST query and result schema need validation against the target deployment.
- VirusTotal sharing may disclose queried indicators to a third party.
- Jira Cloud issue description formatting and project fields may differ by tenant.
