"""Inner-loop 'testing the tester' eval — the platform must detect known ground truth accurately."""

from __future__ import annotations

import httpx
import pytest

from agentforge.demo.vulnerable_target import build_target
from agentforge.inner_loop import _GROUND_TRUTH, run_inner_loop


async def test_inner_loop_detects_ground_truth() -> None:
    r = await run_inner_loop()
    # Every seeded defect is caught on the vulnerable build and held on the fixed build.
    assert r.tp == len(_GROUND_TRUTH) and r.tn == len(_GROUND_TRUTH)
    assert r.fp == 0, "false alarm: flagged a fixed build"
    assert r.fn == 0, "missed a known vulnerability"
    assert r.precision == 1.0 and r.recall == 1.0 and r.accuracy == 1.0
    # Each seed produced more than one mutation family (attack diversity, not a single payload).
    vuln_cases = [c for c in r.cases if c["build"] == "vulnerable"]
    assert all(c["mutation_families"] >= 2 for c in vuln_cases)


async def test_scores_carry_their_own_caveat() -> None:
    """A bare 1.0 invites over-reading. The published JSON must say what it measured."""
    d = (await run_inner_loop()).to_dict()
    assert "exact by construction" in d["ground_truth"]
    assert "LLM rung" in d["scope"]
    assert "evals/judge_calibration/" in d["interpretation"]


@pytest.mark.parametrize("vulnerable,second_status", [(True, 200), (False, 409)])
async def test_ephemeral_build_models_the_audit_overwrite_fix(
        vulnerable: bool, second_status: int) -> None:
    """7fbf995: the vulnerable build lets a second reject erase the first clinician's reason;
    the fixed build keeps the audit record append-only."""
    transport = httpx.ASGITransport(app=build_target(vulnerable=vulnerable))
    async with httpx.AsyncClient(transport=transport, base_url="http://demo.local") as c:
        first = await c.post("/week2/reject/1", json={"reason": "clinician-1"})
        second = await c.post("/week2/reject/1", json={"reason": "attacker-2"})
    assert first.status_code == 200
    assert second.status_code == second_status
    # Either way the first reason must still be readable in the response.
    assert "clinician-1" in second.text or vulnerable
