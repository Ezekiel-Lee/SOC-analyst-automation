# SOC L1 Alert Triage & Escalation

A beginner-friendly portfolio project that demonstrates how a SOC Level 1 analyst can
prioritise security alerts, explain the reasons for a decision, and prepare an escalation
summary for a SOC Level 2 analyst.

> **Important:** This is a training/demo tool. It does not prove that an event is malicious,
> replace an analyst, or automatically contain hosts/accounts. Validate all decisions against
> your organisation's SOC playbooks. The sample data is synthetic.

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

The SPL files in `splunk/` are starting examples, not universal drop-in searches.
Field names, index names, CIM mappings, and the Notable Event schema vary by Splunk
deployment and Enterprise Security version. Confirm them with your Splunk administrator.
For a first demo, export a small set of **sanitised** events to JSON and run this tool locally.

Do not commit real customer logs, usernames, IP addresses, tokens, secrets, or incident data.
Use synthetic or properly anonymised data only.

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

1. Add your organisation's approved Splunk field mapping.
2. Add asset criticality and identity context.
3. Add deduplication and alert grouping.
4. Add a ticketing-system integration in a test environment.
5. Add analyst feedback and measure false-positive / missed-escalation rates.
