# SOC L1 Alert Triage & Escalation

A lightweight security orchestration and triage tool designed for SOC Level 1 analysts to filter false positives, enrich alerts, score risk transparently, and automate L2 escalation reporting.

## Features

- Reads alerts from a JSON file (a simple stand-in for a Splunk export/API result).
- Applies transparent, configurable risk-scoring rules.
- Produces `ESCALATE`, `INVESTIGATE`, or `MONITOR` recommendations.
- Adds a reason list and an initial MITRE ATT&CK technique mapping where applicable.
- Exports a CSV triage queue and a Markdown L2 escalation report.
- Includes example Splunk SPL searches and unit tests.

## Architecture

```text
Splunk notable events / alert export
              |
              v
        alerts.json
              |
              v
       Python triage engine
       - normalise fields
       - score risk
       - explain decision
       - map technique
              |
       +------+------+
       |             |
       v             v
  triage_queue.csv  escalation_report.md
```

## Requirements

- Python 3.10+
- No third-party Python packages required for the starter version.

## Run

```bash
python -m python.alert_analyzer --input data/sample_alerts.json --out reports
```

Outputs:
- `reports/triage_queue.csv`
- `reports/escalation_report.md`

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Splunk integration

The query examples provided in the splunk/ directory serve as starting points. Field names, indexes, and CIM mappings vary across deployments. Export sanitized test events to JSON for local evaluation. Never commit real customer data, internal IPs, or secrets.

## Risk scoring

The starter rules are intentionally simple and explainable:

- Critical/High severity adds risk.
- High/Critical urgency adds risk.
- Known high-impact behaviours (e.g. malware detection or privilege escalation) add risk.
- Repeated failed logins add risk.
- A confirmed benign/false-positive disposition prevents automatic escalation.

The score is a triage aid, not a probability of compromise. Tune thresholds only with
approved detection engineering / SOC playbooks and test against labelled data.

## Suggested next improvements

1. Integrate threat intelligence APIs (e.g., AbuseIPDB, VirusTotal).
2. Add asset criticality and identity context enrichment.
3. Implement live webhook alerts for Slack / Microsoft Teams.
4. Connect automated Jira ticket creation for high-risk escalations.
