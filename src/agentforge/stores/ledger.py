"""Append-only event ledger (DIRECTION §12 F11).

The Orchestrator's canonical input and the overnight-run reconstruction substrate: every
attempt, verdict, cost, coverage delta, and agent action is appended, never mutated. PHI stays
out — response bodies are summarized to metadata here; the full evidence (with synthetic PHI)
lives only in the access-controlled vuln DB. Least-privilege: each agent appends only its own
event types.
"""

from __future__ import annotations

import json
import sqlite3
import time
from enum import StrEnum
from pathlib import Path
from typing import Any


class EventType(StrEnum):
    CAMPAIGN_STARTED = "campaign_started"
    ATTEMPT_EXECUTED = "attempt_executed"
    VERDICT_RECORDED = "verdict_recorded"
    COST_ACCRUED = "cost_accrued"
    COVERAGE_DELTA = "coverage_delta"
    AGENT_ACTION = "agent_action"
    APPROVAL = "approval"
    HALT = "halt"


# Least-privilege: which agent may append which event types.
_WRITERS: dict[str, set[EventType]] = {
    "orchestrator": {EventType.CAMPAIGN_STARTED, EventType.COVERAGE_DELTA,
                     EventType.AGENT_ACTION, EventType.HALT},
    "redteam": {EventType.ATTEMPT_EXECUTED, EventType.COST_ACCRUED, EventType.AGENT_ACTION},
    "judge": {EventType.VERDICT_RECORDED, EventType.AGENT_ACTION},
    "documentation": {EventType.APPROVAL, EventType.AGENT_ACTION},
}


class WriterNotAuthorized(RuntimeError):
    """An agent tried to append an event type it does not own (least-privilege violation)."""


class EventLedger:
    def __init__(self, db_path: str | Path) -> None:
        self._path = str(db_path)
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS events (
                   seq INTEGER PRIMARY KEY AUTOINCREMENT,
                   ts REAL NOT NULL,
                   run_id TEXT NOT NULL,
                   agent TEXT NOT NULL,
                   event_type TEXT NOT NULL,
                   payload TEXT NOT NULL
               )"""
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS ix_events_run ON events(run_id)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS ix_events_type ON events(event_type)")
        self._conn.commit()

    def append(self, *, agent: str, event_type: EventType, run_id: str,
               payload: dict[str, Any]) -> int:
        allowed = _WRITERS.get(agent, set())
        if event_type not in allowed:
            raise WriterNotAuthorized(
                f"agent {agent!r} may not append {event_type.value!r}"
            )
        cur = self._conn.execute(
            "INSERT INTO events (ts, run_id, agent, event_type, payload) VALUES (?,?,?,?,?)",
            (time.time(), run_id, agent, event_type.value, json.dumps(payload, default=str)),
        )
        self._conn.commit()
        return int(cur.lastrowid or 0)

    def events(self, *, run_id: str | None = None,
               event_type: EventType | None = None) -> list[dict[str, Any]]:
        q = "SELECT seq, ts, run_id, agent, event_type, payload FROM events"
        clauses: list[str] = []
        args: list[Any] = []
        if run_id is not None:
            clauses.append("run_id = ?")
            args.append(run_id)
        if event_type is not None:
            clauses.append("event_type = ?")
            args.append(event_type.value)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY seq"
        rows = self._conn.execute(q, args).fetchall()
        return [
            {"seq": r[0], "ts": r[1], "run_id": r[2], "agent": r[3],
             "event_type": r[4], "payload": json.loads(r[5])}
            for r in rows
        ]

    def close(self) -> None:
        self._conn.close()


def redact(text: str, markers: list[str]) -> str:
    """Scrub PHI-shaped markers before anything reaches the ledger/logs."""
    out = text
    for m in markers:
        if m and m in out:
            out = out.replace(m, "[REDACTED]")
    return out
