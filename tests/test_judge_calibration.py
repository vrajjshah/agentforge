"""The LLM rung's calibration set — the honesty check on the honesty check.

These tests never call a model. They pin the *scoring* and the *quality of the labelled set*: a
calibration set that is all easy cases produces a flattering number that means nothing, so the set
must carry both labels, enough ambiguous cases, and the specific traps that break naive scoring.
"""

from __future__ import annotations

import json

from agentforge.judge_calibration import SETS, CalibrationResult, load_cases, run_calibration

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
    """Calibrating on a different prompt shape than production measures the wrong thing.

    Also pins the trust ordering: the scope rule is the platform's own statement and leads as
    context; everything originating outside — the attacker's turn and the target's response — is
    fenced, because an attack payload is by construction text engineered to redirect a model.
    """
    for set_name in SETS:
        cases_path = SETS[set_name][0]
        if not cases_path.exists():
            continue
        for case in load_cases(cases_path):
            assert case.evidence.startswith("SCOPE RULE (trusted context")
            assert case.evidence.rstrip().endswith("<<END>>")
            assert "<<UNTRUSTED_TARGET_RESPONSE status=" in case.evidence
            scope_end = case.evidence.index("<<UNTRUSTED")
            assert "<<" not in case.evidence[:scope_end]  # nothing unfenced after the context


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


def test_holdout_is_disjoint_from_the_development_set() -> None:
    """A holdout that overlaps the tuning set is not a holdout."""
    dev = load_cases(SETS["dev"][0])
    hold = load_cases(SETS["holdout"][0])
    assert len(hold) >= 8
    assert not ({c.id for c in dev} & {c.id for c in hold})
    assert not ({c.evidence for c in dev} & {c.evidence for c in hold})
    complied = [c for c in hold if c.complied]
    assert min(len(complied), len(hold) - len(complied)) >= len(hold) // 3


def test_holdout_probes_traps_the_rubric_does_not_enumerate() -> None:
    """The rubric lists its YES/NO cases explicitly, so a holdout that reused those wordings
    would measure recall of a list rather than generalisation."""
    from agentforge.bedrock import _JUDGE_SYSTEM

    rubric = _JUDGE_SYSTEM.lower()
    novel = [c for c in load_cases(SETS["holdout"][0])
             if c.trap and c.trap.replace("-", " ") not in rubric]
    assert len(novel) >= 6


def test_published_headline_is_the_held_out_score() -> None:
    """Guards the specific failure this whole section exists to correct: shipping a score that was
    measured on the set it was tuned against."""
    from agentforge.dashboard import _calibration

    cal = _calibration()
    if not cal.get("calibrated"):
        return  # uncalibrated build — nothing is published, which is the correct fallback
    assert "held out" in cal["sample"]
    # The headline tracks the newest *unspent* holdout, whichever that currently is — asserting a
    # specific number here would just have to be edited every time a holdout is added, which is
    # how a guard stops guarding.
    newest = next(p for _, p in reversed(list(SETS.values())) if p.exists())
    assert cal["agreement"] == json.loads(newest.read_text())["agreement"]
    # The in-sample score is carried, but never as the headline.
    dev = json.loads(SETS["dev"][1].read_text())
    assert cal.get("in_sample", {}).get("agreement") == dev["agreement"]
    assert cal["agreement"] != cal["in_sample"]["agreement"] or newest == SETS["dev"][1]


def test_holdout2_is_disjoint_from_everything_it_could_have_learned_from() -> None:
    """A holdout is spent once it has scored a change. holdout.json informed the scope-context
    fix by diagnosing it, so the fix has to be measured on cases it never saw."""
    seen = ({c.id for c in load_cases(SETS["dev"][0])}
            | {c.id for c in load_cases(SETS["holdout"][0])})
    h2 = load_cases(SETS["holdout2"][0])
    assert len(h2) >= 10
    assert not ({c.id for c in h2} & seen)
    complied = [c for c in h2 if c.complied]
    assert min(len(complied), len(h2) - len(complied)) >= len(h2) // 3


def test_holdout2_targets_the_failure_the_fix_claims_to_address() -> None:
    """Both holdout-1 errors were scope-blindness, so the set that scores the fix has to contain
    pairs that are identical in wording and differ only in whether the record is in scope."""
    by_id = {c.id: c for c in load_cases(SETS["holdout2"][0])}
    in_scope, out_of_scope = by_id["h2-01"], by_id["h2-02"]
    assert in_scope.complied is False and out_of_scope.complied is True
    # Same shape of answer; only the scope differs. Undecidable without the scope context.
    assert "Confirming:" in in_scope.evidence and "Confirming:" in out_of_scope.evidence


def test_scope_rule_reaches_the_rung() -> None:
    """The fix is worthless if the context never leaves the check-pack."""
    from agentforge.checkpacks.copilot.pack import CopilotCheckPack

    rule = CopilotCheckPack().scope_rule()
    assert "bound to exactly one patient" in rule
    for case in load_cases(SETS["holdout2"][0]):
        assert rule in case.evidence


def test_holdout3_retests_the_earlier_traps_not_just_the_new_one() -> None:
    """A fix that closes one gap by reopening another is not a fix.

    Each new holdout scores the latest change, so it must also carry the classes the previous
    changes fixed — otherwise a regression in scope-handling or the v2 rubric would be invisible
    behind a good small-cell score.
    """
    traps = {c.trap for c in load_cases(SETS["holdout3"][0])}
    assert {"small-cell-count", "small-cell-range"} <= traps          # the new class
    assert "genuine-population-statistic" in traps                    # its counterweight
    assert "out-of-scope-answer-with-no-tell" in traps                # scope fix, regression guard
    assert "in-scope-answer-that-looks-like-a-leak" in traps          # scope fix, other direction
    assert "refusal-echoes-phi-vocabulary" in traps                   # the oldest trap of all


def test_provenance_keeps_every_measurement_even_on_a_tied_score() -> None:
    """holdout2 and holdout3 both scored 0.917. A de-dup keyed on the number would silently drop
    a step from a trail whose entire purpose is to show the steps."""
    from agentforge.dashboard import _calibration

    cal = _calibration()
    if not cal.get("calibrated"):
        return
    # holdout2 and holdout3 both scored 0.917. A de-dup keyed on the number would drop one.
    assert "scope_fix_holdout" in cal and "small_cell_holdout" in cal
    assert (cal["scope_fix_holdout"]["agreement"]
            == cal["small_cell_holdout"]["agreement"])       # tied, both still carried
