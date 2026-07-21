"""The LLM rung's calibration set — the honesty check on the honesty check.

These tests never call a model. They pin the *scoring* and the *quality of the labelled set*: a
calibration set that is all easy cases produces a flattering number that means nothing, so the set
must carry both labels, enough ambiguous cases, and the specific traps that break naive scoring.
"""

from __future__ import annotations

from agentforge.judge_calibration import CalibrationResult, load_cases, run_calibration

_MIN_CASES = 10


def test_labelled_set_is_balanced_and_hard() -> None:
    cases = load_cases()
    assert len(cases) >= _MIN_CASES
    complied = [c for c in cases if c.complied]
    refused = [c for c in cases if not c.complied]
    # Neither label may dominate: a lopsided set lets "always say no" score well.
    assert min(len(complied), len(refused)) >= len(cases) // 3
    ambiguous = [c for c in cases if c.difficulty == "ambiguous"]
    assert len(ambiguous) >= len(cases) // 2, "an easy set produces a meaningless agreement number"
    # Both directions of naive-scoring failure are represented.
    traps = {c.trap for c in cases}
    assert "refusal-echoes-phi-vocabulary" in traps      # false positive on a safe refusal
    assert "refusal-preamble-then-compliance" in traps   # false negative on a real leak
    assert "legitimate-in-scope-answer" in traps         # a healthy 200 must not be a finding


def test_evidence_matches_the_production_format() -> None:
    """Calibrating on a different prompt shape than production measures the wrong thing."""
    for case in load_cases():
        assert case.evidence.startswith("<<UNTRUSTED_TARGET_RESPONSE status=")
        assert case.evidence.rstrip().endswith("<<END>>")


def test_case_ids_are_unique() -> None:
    ids = [c.id for c in load_cases()]
    assert len(ids) == len(set(ids))


async def test_scoring_against_a_perfect_rung() -> None:
    labels = {c.evidence: c.complied for c in load_cases()}

    async def oracle(evidence: str) -> bool:
        return labels[evidence]

    r = await run_calibration(oracle, model="stub")
    assert r.agreement == 1.0 and r.precision == 1.0 and r.recall == 1.0
    assert r.fp == 0 and r.fn == 0
    assert r.disagreements == []


async def test_scoring_against_an_always_no_rung() -> None:
    """The degenerate 'never flags anything' judge must score badly, not perfectly."""

    async def always_no(_evidence: str) -> bool:
        return False

    r = await run_calibration(always_no, model="stub")
    assert r.recall == 0.0
    assert r.agreement < 1.0
    assert r.fn == len([c for c in load_cases() if c.complied])
    # Every disagreement is a missed compliance, and each carries its human rationale.
    assert all(d["human"] is True and d["rationale"] for d in r.disagreements)


def test_empty_result_reports_zero_not_one() -> None:
    """An uncalibrated rung must never read as a perfect score."""
    empty = CalibrationResult()
    assert empty.agreement == 0.0 and empty.precision == 0.0 and empty.recall == 0.0
