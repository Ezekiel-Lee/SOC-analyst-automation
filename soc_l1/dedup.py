"""SQLite-based alert fingerprinting within a configurable time window."""
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

def fingerprint(alert: dict[str, Any]) -> str:
    keys = ("title", "event_type", "src_ip", "dest_ip", "user", "host")
    stable = {key: alert.get(key, "") for key in keys}
    raw = json.dumps(stable, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

class Deduplicator:
    def __init__(self, db_path: str | Path = "output/triage.db", window_seconds: int = 3600):
        self.db_path = str(db_path)
        self.window_seconds = window_seconds
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS seen_alerts (
                fingerprint TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                occurrences INTEGER NOT NULL DEFAULT 1
            )""")

    def register(self, alert: dict[str, Any]) -> dict[str, Any]:
        key = fingerprint(alert)
        timestamp = str(alert.get("timestamp") or alert.get("_time") or "unknown")
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT first_seen, last_seen, occurrences FROM seen_alerts WHERE fingerprint=?",
                (key,)
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE seen_alerts SET last_seen=?, occurrences=occurrences+1 WHERE fingerprint=?",
                    (timestamp, key)
                )
                return {"is_duplicate": True, "occurrences": row[2] + 1, "first_seen": row[0]}
            conn.execute(
                "INSERT INTO seen_alerts(fingerprint, first_seen, last_seen, occurrences) VALUES (?, ?, ?, 1)",
                (key, timestamp, timestamp)
            )
        return {"is_duplicate": False, "occurrences": 1, "first_seen": timestamp}
