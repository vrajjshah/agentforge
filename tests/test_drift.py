"""Judge drift gate on frozen fixtures (F6) + its proof-of-firing.

The gate passes when the Judge still classifies the goldens correctly, and BLOCKS when a golden
is misclassified (drift) or a fixture is tampered with.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

from agentforge.agents.judge import Judge
from agentforge.contracts.models import VerdictLabel
from agentforge.drift import DriftFixture, DriftGate, load_fixtures

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "drift"


def _fixtures() -> list[DriftFixture]:
    return load_fixtures(_FIXTURES)


async def test_gate_passes_on_golden_fixtures() -> None:
    fixtures = _fixtures()
    assert len(fixtures) >= 4, "expected the frozen vulnerable+fixed goldens"
    blocked, results = await DriftGate().check(Judge(), fixtures)
    assert blocked is False, [r for r in results if r.drifted or r.tampered]
    assert all(not r.tampered for r in results)


async def test_gate_blocks_on_drift_flipped_label() -> None:
    """Flip a golden's label → the Judge now 'disagrees' → drift caught (proof-of-firing)."""
    fixtures = _fixtures()
    # flip the first EXPLOITED golden to DEFENDED — the Judge will still say EXPLOITED → drift
    flipped = [
        dataclasses.replace(f, expected_label=VerdictLabel.DEFENDED)
        if f.expected_label == VerdictLabel.EXPLOITED else f
        for f in fixtures
    ]
    blocked, results = await DriftGate().check(Judge(), flipped)
    assert blocked is True
    assert any(r.drifted for r in results)


async def test_gate_blocks_on_tampered_fixture() -> None:
    """A fixture whose attempt no longer matches its signature is caught (integrity)."""
    fixtures = _fixtures()
    target = fixtures[0]
    tampered_attempt = target.attempt.model_copy(update={"subcategory": "TAMPERED"})
    tampered = [dataclasses.replace(target, attempt=tampered_attempt), *fixtures[1:]]
    blocked, results = await DriftGate().check(Judge(), tampered)
    assert blocked is True
    assert results[0].tampered is True
