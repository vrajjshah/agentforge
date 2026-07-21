"""Stores: append-only ledger + least-privilege writers, and the vuln-DB data-quality gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentforge.contracts.models import (
    AttackCategory,
    AttackTurn,
    HttpProbe,
    OwaspLlm,
    OwaspMapping,
    OwaspWeb,
    Severity,
    VulnReport,
)
from agentforge.stores.ledger import EventLedger, EventType, WriterNotAuthorized, redact
from agentforge.stores.vulndb import DataQualityError, VulnDB


def _report(**kw: object) -> VulnReport:
    base: dict[str, object] = dict(
        title="Cross-patient PHI leak",
        severity=Severity.CRITICAL,
        category=AttackCategory.DATA_EXFILTRATION,
        owasp=OwaspMapping(web=OwaspWeb.A01, llm=OwaspLlm.LLM06),
        clinical_impact="A clinician could read another patient's chart.",
        reproduction=[AttackTurn(index=0, probe=HttpProbe(method="GET",
                     path="/week2/documents/2/extraction"))],
        observed_behavior="200 with another patient's birthDate",
        expected_behavior="401/403 with no PHI",
        remediation="Scope reads by patient, not document id.",
        target_version="v1",
    )
    base.update(kw)
    return VulnReport(**base)  # type: ignore[arg-type]


def test_ledger_least_privilege(tmp_path: Path) -> None:
    led = EventLedger(tmp_path / "ledger.db")
    led.append(agent="judge", event_type=EventType.VERDICT_RECORDED, run_id="r1",
               payload={"label": "defended"})
    with pytest.raises(WriterNotAuthorized):
        led.append(agent="judge", event_type=EventType.APPROVAL, run_id="r1", payload={})
    assert len(led.events(run_id="r1")) == 1
    led.close()


def test_ledger_is_append_only_ordered(tmp_path: Path) -> None:
    led = EventLedger(tmp_path / "ledger.db")
    for i in range(3):
        led.append(agent="redteam", event_type=EventType.ATTEMPT_EXECUTED, run_id="r",
                   payload={"i": i})
    seqs = [e["seq"] for e in led.events(run_id="r")]
    assert seqs == sorted(seqs)
    assert not hasattr(led, "update") and not hasattr(led, "delete")
    led.close()


def test_redact_scrubs_markers() -> None:
    assert "[REDACTED]" in redact('{"birthDate":"1950"}', ["1950"])


def test_ledger_masks_phi_on_write(tmp_path: Path) -> None:
    """Every ledger append is PHI-shape masked — a DOB-shaped value never persists raw."""
    led = EventLedger(tmp_path / "ledger.db")
    led.append(agent="judge", event_type=EventType.VERDICT_RECORDED, run_id="r",
               payload={"leak": "patient DOB 1958-03-12", "mrn": "MRN-SYNTH-0002"})
    stored = led.events(run_id="r")[0]["payload"]
    assert "1958-03-12" not in str(stored)
    assert "[REDACTED]" in stored["leak"]
    led.close()


def test_vulndb_accepts_valid_report(tmp_path: Path) -> None:
    db = VulnDB(tmp_path / "vuln.db")
    vid = db.write(_report())
    assert db.get(vid) is not None
    db.close()


def test_vulndb_rejects_missing_fields(tmp_path: Path) -> None:
    db = VulnDB(tmp_path / "vuln.db")
    with pytest.raises(DataQualityError):
        db.write(_report(clinical_impact=""))
    db.close()


def test_vulndb_rejects_both_owasp_na(tmp_path: Path) -> None:
    db = VulnDB(tmp_path / "vuln.db")
    with pytest.raises(DataQualityError):
        db.write(_report(owasp=OwaspMapping(web=OwaspWeb.NA, llm=OwaspLlm.NA)))
    db.close()


def test_vulndb_rejects_duplicate_attack_sequence(tmp_path: Path) -> None:
    db = VulnDB(tmp_path / "vuln.db")
    db.write(_report())
    with pytest.raises(DataQualityError):
        db.write(_report(title="different title, same attack"))
    db.close()
