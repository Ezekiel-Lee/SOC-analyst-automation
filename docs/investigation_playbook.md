# SOC L1 investigation playbook (training template)

For every alert, document facts separately from assumptions.

1. Validate alert ID, detection name, timestamp, data source, and status.
2. Identify the affected user, host, asset criticality, source and destination.
3. Review relevant authentication, endpoint, DNS, proxy, and network telemetry.
4. Check change windows, approved scanners, service accounts, and expected activity.
5. Search for related alerts and determine whether activity spans multiple hosts/accounts.
6. Preserve event IDs, timestamps, query details, and relevant evidence according to policy.
7. Decide whether to monitor, investigate further, or escalate using the organisation's playbook.
8. Record what was checked, what was found, what remains unknown, and why escalation is recommended.

Never disable accounts, isolate hosts, block IPs, or delete files solely because this demo tool assigns a high score.
