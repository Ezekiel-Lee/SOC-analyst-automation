"""Command-line interface for the SOC L1 project."""
import argparse
import json
from pathlib import Path
from dotenv import load_dotenv

from soc_l1.ingest import load_json_alerts, load_splunk_alerts
from soc_l1.pipeline import process_alerts
from soc_l1.jira_client import create_issue

def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(prog="soc-l1", description="SOC L1 alert triage and escalation demonstrator")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Ingest and triage alerts")
    run.add_argument("--source", choices=["json", "splunk"], default="json")
    run.add_argument("--input", help="Input JSON file (required for json source)")
    run.add_argument("--output-dir", default="output")
    run.add_argument("--enrich", action="store_true", help="Query VirusTotal for source IPs (requires API key)")

    jira = sub.add_parser("create-jira", help="Create a Jira issue for a selected alert")
    jira.add_argument("--alert-id", required=True)
    jira.add_argument("--input", default="output/processed_alerts.json")
    jira.add_argument("--confirm", action="store_true", help="Required explicit confirmation")

    args = parser.parse_args()
    if args.command == "run":
        if args.source == "json":
            if not args.input:
                parser.error("--input is required when --source json")
            alerts = load_json_alerts(args.input)
        else:
            alerts = load_splunk_alerts()
        results = process_alerts(alerts, args.output_dir, args.enrich)
        print(f"Processed {len(results)} alerts.")
        print(f"New escalation candidates: {sum(x['recommendation'] == 'ESCALATE' and not x['is_duplicate'] for x in results)}")
        print(f"Reports saved in: {Path(args.output_dir).resolve()}")
    elif args.command == "create-jira":
        if not args.confirm:
            parser.error("Ticket creation requires --confirm after an analyst has reviewed the alert.")
        records = json.loads(Path(args.input).read_text(encoding="utf-8"))
        match = next((x for x in records if str(x.get("alert_id")) == args.alert_id), None)
        if not match:
            parser.error(f"Alert ID {args.alert_id} was not found.")
        if match.get("recommendation") != "ESCALATE":
            parser.error("Only alerts recommended for escalation can be sent by this demo command.")
        result = create_issue(match)
        print(f"Jira issue created: {result.get('key', 'created')}")

if __name__ == "__main__":
    main()
