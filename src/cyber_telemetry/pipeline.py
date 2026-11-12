from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

SEVERITIES = {"low", "medium", "high", "critical"}


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def normalize(row: dict) -> dict:
    event = {
        "event_id": str(row["event_id"]),
        "occurred_at": _time(str(row["occurred_at"])).isoformat(),
        "source": str(row["source"]).lower().strip(),
        "principal": str(row.get("principal", "")).strip().lower(),
        "asset": str(row.get("asset", "")).strip().lower(),
        "event_type": str(row["event_type"]).lower().strip(),
        "severity": str(row["severity"]).lower().strip(),
    }
    if not event["principal"] and not event["asset"]:
        raise ValueError("principal or asset is required")
    if event["severity"] not in SEVERITIES:
        raise ValueError("unsupported severity")
    return event


def _schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL, source TEXT NOT NULL,
            principal TEXT NOT NULL, asset TEXT NOT NULL, event_type TEXT NOT NULL,
            severity TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY, correlation_key TEXT NOT NULL,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, event_count INTEGER NOT NULL,
            max_severity TEXT NOT NULL, event_ids_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS rejected_events (
            event_id TEXT, reason TEXT NOT NULL, raw_json TEXT NOT NULL
        );
        """
    )


def _severity_rank(value: str) -> int:
    return ["low", "medium", "high", "critical"].index(value)


def run_pipeline(records: Iterable[dict], database: str | Path) -> dict[str, int]:
    conn = sqlite3.connect(database)
    _schema(conn)
    accepted = rejected = duplicates = 0
    for raw in records:
        try:
            event = normalize(raw)
            cur = conn.execute("INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?, ?, ?)", tuple(event.values()))
            if cur.rowcount:
                accepted += 1
            else:
                duplicates += 1
        except (KeyError, TypeError, ValueError) as exc:
            rejected += 1
            conn.execute("INSERT INTO rejected_events VALUES (?, ?, ?)", (str(raw.get("event_id")), str(exc), json.dumps(raw, sort_keys=True)))
    rows = [dict(zip(("event_id", "occurred_at", "source", "principal", "asset", "event_type", "severity"), row)) for row in conn.execute("SELECT event_id, occurred_at, source, principal, asset, event_type, severity FROM events ORDER BY occurred_at, event_id")]
    groups: dict[str, list[dict]] = {}
    last_seen: dict[str, datetime] = {}
    for row in rows:
        key = f"principal:{row['principal']}" if row["principal"] else f"asset:{row['asset']}"
        when = _time(row["occurred_at"])
        if key not in last_seen or (when - last_seen[key]).total_seconds() > 900:
            groups[f"{key}:{when.isoformat()}"] = []
        group_key = max((candidate for candidate in groups if candidate.startswith(key + ":")), key=lambda candidate: groups[candidate][-1]["occurred_at"] if groups[candidate] else "")
        groups[group_key].append(row)
        last_seen[key] = when
    for group_key, group in groups.items():
        if not group:
            continue
        incident_id = hashlib.sha256(group_key.encode()).hexdigest()[:20]
        severities = [row["severity"] for row in group]
        conn.execute("INSERT OR REPLACE INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?)", (incident_id, group_key.split(":", 1)[1], group[0]["occurred_at"], group[-1]["occurred_at"], len(group), max(severities, key=_severity_rank), json.dumps([row["event_id"] for row in group])))
    conn.commit()
    result = {"accepted": accepted, "rejected": rejected, "duplicates": duplicates, "incidents": len(groups)}
    conn.close()
    return result
