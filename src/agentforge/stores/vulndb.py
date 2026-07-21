"""Curated vulnerability DB with a data-quality gate (DIRECTION §12 F11; §6 #13).

Documentation is the *only* writer, and only through ``write()``, which enforces:
  * all required fields present,
  * a valid dual OWASP mapping (not both n/a) — the one mandatory engineering deliverable (F3),
  * unique id, and no duplicate report for the same attack sequence (fingerprint).

A write that fails any check raises ``DataQualityError`` — nothing partial lands.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from agentforge.contracts.models import OwaspLlm, OwaspWeb, VulnReport


class DataQualityError(ValueError):
    """A vuln report failed the data-quality gate; the write is rejected."""


def attack_fingerprint(report: VulnReport) -> str:
    payload = [
        (t.probe.method, t.probe.path, json.dumps(t.probe.json_body or {}, sort_keys=True))
        for t in report.reproduction
    ]
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


def check_quality(report: VulnReport) -> None:
    """Validate a report against the data-quality gate. Raises ``DataQualityError`` on failure."""
    missing = [
        f for f, v in {
            "title": report.title,
            "clinical_impact": report.clinical_impact,
            "observed_behavior": report.observed_behavior,
            "expected_behavior": report.expected_behavior,
            "remediation": report.remediation,
            "target_version": report.target_version,
        }.items()
        if not str(v).strip()
    ]
    if missing:
        raise DataQualityError(f"required fields empty: {missing}")
    if not report.reproduction:
        raise DataQualityError("reproduction sequence is empty — not reproducible")
    # F3: the mandatory dual OWASP mapping must not be n/a on both axes.
    if report.owasp.web == OwaspWeb.NA and report.owasp.llm == OwaspLlm.NA:
        raise DataQualityError("OWASP mapping is n/a on both web and LLM axes")
    if (report.owasp.web == OwaspWeb.NA or report.owasp.llm == OwaspLlm.NA) \
            and not report.owasp.justification.strip():
        raise DataQualityError("an n/a OWASP axis requires a justification")


class VulnDB:
    def __init__(self, db_path: str | Path) -> None:
        self._path = str(db_path)
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._path)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS vulns (
                   id TEXT PRIMARY KEY,
                   fingerprint TEXT NOT NULL UNIQUE,
                   severity TEXT NOT NULL,
                   category TEXT NOT NULL,
                   owasp_web TEXT NOT NULL,
                   owasp_llm TEXT NOT NULL,
                   status TEXT NOT NULL,
                   target_version TEXT NOT NULL,
                   report TEXT NOT NULL
               )"""
        )
        # Indexes on the common query patterns (§6 #16): by severity, category, version.
        for col in ("severity", "category", "target_version", "status"):
            self._conn.execute(f"CREATE INDEX IF NOT EXISTS ix_vulns_{col} ON vulns({col})")
        self._conn.commit()

    def write(self, report: VulnReport) -> str:
        """The only write path. Enforces the data-quality gate before persisting."""
        check_quality(report)
        fp = attack_fingerprint(report)
        existing = self._conn.execute(
            "SELECT id FROM vulns WHERE fingerprint = ?", (fp,)
        ).fetchone()
        if existing:
            raise DataQualityError(
                f"duplicate report for the same attack sequence (existing id {existing[0]})"
            )
        self._conn.execute(
            "INSERT INTO vulns (id, fingerprint, severity, category, owasp_web, owasp_llm, "
            "status, target_version, report) VALUES (?,?,?,?,?,?,?,?,?)",
            (report.id, fp, report.severity.value, report.category.value,
             report.owasp.web.value, report.owasp.llm.value, report.status,
             report.target_version, report.model_dump_json()),
        )
        self._conn.commit()
        return report.id

    def get(self, vuln_id: str) -> VulnReport | None:
        row = self._conn.execute(
            "SELECT report FROM vulns WHERE id = ?", (vuln_id,)
        ).fetchone()
        return VulnReport.model_validate_json(row[0]) if row else None

    def all(self) -> list[VulnReport]:
        rows = self._conn.execute("SELECT report FROM vulns ORDER BY severity").fetchall()
        return [VulnReport.model_validate_json(r[0]) for r in rows]

    def close(self) -> None:
        self._conn.close()
