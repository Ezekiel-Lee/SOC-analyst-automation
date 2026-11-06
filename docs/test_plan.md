# Test plan

| Test | Input | Expected outcome |
|---|---|---|
| Critical credential dumping | Critical + high urgency + mapped event | ESCALATE |
| Repeated failed logins | 10+ failed attempts | Additional risk points |
| Known-good event | Analyst disposition `known_good` | MONITOR, score 0 |
| Low signal | Low severity/urgency, no context | MONITOR |
| Duplicate event | Same fingerprint in database | Duplicate flag and occurrence count |
| Splunk missing credentials | No required environment variables | Clear configuration error |
| Jira without confirmation | CLI called without `--confirm` | No issue created |
