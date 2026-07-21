"""Load test — the harness itself must be trustworthy before its numbers are.

Runs a small burst (the committed baseline is 100; the suite stays fast) and pins the two things a
performance harness can quietly get wrong: measuring the wrong thing, and pointing at the wrong
bottleneck. No model calls — `--judge-samples` is opt-in and paid.
"""

from __future__ import annotations

import statistics
from pathlib import Path

from agentforge.loadtest import LoadTestResult, Phase, render_report, run_loadtest


async def test_loadtest_times_every_phase(tmp_path: Path) -> None:
    r = await run_loadtest(attacks=8, data_dir=tmp_path)
    assert r.attacks == 8
    for phase in ("generate", "execute", "judge", "persist"):
        assert r.phases[phase].stats()["n"] == 8, f"{phase} was not timed"
    assert r.ledger_events == 16          # two append-only events per attack
    assert r.throughput > 0
    assert sum(r.verdicts.values()) == 8


async def test_loadtest_never_touches_the_live_target(tmp_path: Path) -> None:
    """The guard that matters: a burst at a single-worker clinical deployment IS the DoS attack
    this platform tests for. Execution goes through an in-process ASGI transport, so a run cannot
    reach the network even if the configured target URL is real."""
    r = await run_loadtest(attacks=4, data_dir=tmp_path)
    assert r.to_dict()["target"].startswith("ephemeral in-process build")
    assert r.phases["execute"].stats()["max"] < 200  # in-process, not a network round-trip


async def test_bottleneck_is_the_llm_rung_once_it_is_sampled(tmp_path: Path) -> None:
    """With a rung latency in the seconds and a deterministic pipeline in the microseconds, the
    report must say so — and must not let the deterministic sub-analysis bury it.

    Asserts the *relationship*, not a threshold. An earlier version required
    `llm_share_of_time_pct > 90`, which passed on a laptop and failed at 89.4% inside a CI
    container — the deterministic phases are slower there, so the same true statement produced a
    different number. A performance test that encodes the author's hardware is a test that reports
    the machine it ran on, not the property it claims to check.
    """
    r = await run_loadtest(attacks=6, data_dir=tmp_path)
    r.llm_rung_ms = [1200.0, 1300.0, 1400.0]
    b = r.bottleneck()
    assert b["with_llm_rung"]["phase"] == "judge (LLM rung)"
    at10 = b["with_llm_rung"]["at_10pct_of_attacks"]
    # The rung dominates: firing it on one attack in ten already costs more wall-clock than the
    # entire deterministic pipeline. True on any host where a network round-trip beats local CPU.
    assert at10["llm_share_of_time_pct"] > 50
    # And the share must rise with the firing rate — the shape of the finding, not its magnitude.
    shares = [b["with_llm_rung"][k]["llm_share_of_time_pct"]
              for k in ("at_10pct_of_attacks", "at_25pct_of_attacks", "at_100pct_of_attacks")]
    assert shares == sorted(shares)
    assert at10["attacks_per_second"] < r.throughput
    doc = render_report(r)
    assert "bottleneck is the Judge's LLM rung" in doc
    assert doc.index("LLM rung") < doc.index("deterministic pipeline")


async def test_report_states_when_the_rung_was_not_measured(tmp_path: Path) -> None:
    """An unmeasured phase is reported as unmeasured, never omitted into looking fast."""
    r = await run_loadtest(attacks=4, data_dir=tmp_path)
    assert r.to_dict()["llm_rung_ms"]["sampled"] == 0
    assert "Re-run with `--judge-samples N`" in render_report(r)


def test_percentiles_are_computed_not_approximated() -> None:
    p = Phase(samples=[float(x) for x in range(1, 101)])
    s = p.stats()
    assert s["p50"] == statistics.median(range(1, 101))
    assert s["p95"] == 96.0
    assert s["max"] == 100.0


def test_empty_result_is_not_infinitely_fast() -> None:
    empty = LoadTestResult()
    assert empty.throughput == 0.0
    assert empty.to_dict()["storage"]["events_per_second"] == 0.0
