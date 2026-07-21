"""Inner-loop 'testing the tester' eval — the platform must detect known ground truth accurately."""

from __future__ import annotations

from agentforge.inner_loop import run_inner_loop


async def test_inner_loop_detects_ground_truth() -> None:
    r = await run_inner_loop()
    # Every seeded defect is caught on the vulnerable build and held on the fixed build.
    assert r.tp == 3 and r.tn == 3
    assert r.fp == 0, "false alarm: flagged a fixed build"
    assert r.fn == 0, "missed a known vulnerability"
    assert r.precision == 1.0 and r.recall == 1.0 and r.accuracy == 1.0
    # Each seed produced more than one mutation family (attack diversity, not a single payload).
    vuln_cases = [c for c in r.cases if c["build"] == "vulnerable"]
    assert all(c["mutation_families"] >= 2 for c in vuln_cases)
