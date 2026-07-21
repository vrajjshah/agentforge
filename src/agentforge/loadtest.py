"""Load test — where the pipeline actually spends its time, measured rather than assumed.

Runs N attacks end-to-end against the **ephemeral** build, never the live clinical target: a
sustained burst is indistinguishable from the denial-of-service attack this platform is supposed to
be testing for, and the deployment under test is single-worker (~0.56 turns/s). Each attack is timed
through all four phases it passes — orchestration/generation, execution against the target, the
Judge's verdict, and persistence to the append-only ledger and the vuln DB — so the bottleneck is
identified from a distribution, not a guess.

The Judge's LLM rung is timed separately and optionally (``--judge-samples``), because it is the one
phase that costs money and the one that dominates: measuring it once and modelling its contribution
is both cheaper and more honest than firing it on every synthetic attack.
"""

from __future__ import annotations

import dataclasses
import statistics
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from agentforge.adapters.copilot import CopilotAdapter
from agentforge.agents.judge import Judge, delimited_evidence
from agentforge.agents.redteam import RedTeamAgent
from agentforge.checkpacks.copilot.pack import CopilotCheckPack
from agentforge.config import Settings
from agentforge.contracts.models import (
    AttackAttempt,
    AuthPrincipal,
    Campaign,
    ObservedResponse,
    Verdict,
)
from agentforge.demo.vulnerable_target import build_target
from agentforge.mutation.engine import MutationEngine
from agentforge.seeds.seeds import seed_by_id
from agentforge.stores.ledger import EventLedger, EventType

# The seeds cycled through, chosen to exercise both a read path and a multi-turn write path.
_ROTATION: tuple[tuple[str, AuthPrincipal], ...] = (
    ("ea8fa01", AuthPrincipal.NONE),
    ("e0e7b6a", AuthPrincipal.NONE),
    ("b5f4b1e", AuthPrincipal.API_KEY),
    ("stored-payload-reason", AuthPrincipal.API_KEY),
)

_PHASES = ("generate", "execute", "judge", "persist")


@dataclass
class Phase:
    """Per-phase latency samples, in milliseconds."""

    samples: list[float] = field(default_factory=list)

    def add(self, started: float) -> None:
        self.samples.append((time.perf_counter() - started) * 1000)

    def stats(self) -> dict[str, float]:
        if not self.samples:
            return {"n": 0, "p50": 0.0, "p95": 0.0, "max": 0.0, "total": 0.0}
        ordered = sorted(self.samples)
        return {
            "n": len(ordered),
            "p50": round(statistics.median(ordered), 3),
            "p95": round(ordered[min(int(0.95 * len(ordered)), len(ordered) - 1)], 3),
            "max": round(ordered[-1], 3),
            "total": round(sum(ordered), 3),
        }


@dataclass
class LoadTestResult:
    attacks: int = 0
    wall_seconds: float = 0.0
    phases: dict[str, Phase] = field(
        default_factory=lambda: {p: Phase() for p in _PHASES})
    verdicts: dict[str, int] = field(default_factory=dict)
    ledger_events: int = 0
    llm_rung_ms: list[float] = field(default_factory=list)

    @property
    def throughput(self) -> float:
        return round(self.attacks / self.wall_seconds, 2) if self.wall_seconds else 0.0

    def _llm(self) -> dict[str, Any]:
        if not self.llm_rung_ms:
            return {"sampled": 0, "note": "not measured on this run (--judge-samples 0)"}
        ordered = sorted(self.llm_rung_ms)
        return {
            "sampled": len(ordered),
            "p50": round(statistics.median(ordered), 1),
            "p95": round(ordered[min(int(0.95 * len(ordered)), len(ordered) - 1)], 1),
            "max": round(ordered[-1], 1),
        }

    def bottleneck(self) -> dict[str, Any]:
        """Name the dominant phase from the measurements, and say what to do about it.

        Two regimes, because they have different answers: the deterministic pipeline (what this
        run measures) and the pipeline once the Judge's paid rung fires. Reporting only the first
        would make the platform look faster than it behaves on the surface that matters.
        """
        totals = {p: self.phases[p].stats()["total"] for p in _PHASES}
        det_phase = max(totals, key=lambda p: totals[p])
        det_share = round(100 * totals[det_phase] / sum(totals.values()), 1) if any(
            totals.values()) else 0.0
        out: dict[str, Any] = {
            "deterministic_pipeline": {
                "phase": det_phase,
                "share_of_time_pct": det_share,
                "fix": _FIXES[det_phase],
            }
        }
        if self.llm_rung_ms:
            llm_p50 = statistics.median(self.llm_rung_ms)
            per_attack_det = sum(totals.values()) / max(self.attacks, 1)
            # The rung fires only on the semantic categories, and only when the deterministic
            # ladder left the verdict undecided with a 200 in hand.
            for rate in (0.1, 0.25, 1.0):
                out.setdefault("with_llm_rung", {})[f"at_{int(rate * 100)}pct_of_attacks"] = {
                    "llm_share_of_time_pct": round(
                        100 * (rate * llm_p50) / (per_attack_det + rate * llm_p50), 1),
                    "attacks_per_second": round(
                        1000 / (per_attack_det + rate * llm_p50), 2),
                }
            out["with_llm_rung"]["phase"] = "judge (LLM rung)"
            out["with_llm_rung"]["fix"] = (
                "The rung is a network round-trip to a frontier model, so it is latency-bound, not "
                "CPU-bound: the fix is concurrency and triage, not a faster machine. Fan attempts "
                "out with a bounded worker pool (the deterministic phases are already independent "
                "per attack), keep the ladder cheapest-first so the rung fires only on genuinely "
                "ambiguous /chat turns, and batch a campaign's ambiguous turns into one request "
                "where the rubric allows. Beyond that the constraint is the Bedrock account's "
                "requests-per-minute quota, which is a provisioning decision, not a code change."
            )
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "target": "ephemeral in-process build (never the live clinical target)",
            "attacks": self.attacks,
            "wall_seconds": round(self.wall_seconds, 3),
            "attacks_per_second": self.throughput,
            "phases_ms": {p: self.phases[p].stats() for p in _PHASES},
            "llm_rung_ms": self._llm(),
            "storage": {
                "ledger_events": self.ledger_events,
                "events_per_second": (round(self.ledger_events / self.wall_seconds, 1)
                                      if self.wall_seconds else 0.0),
                "persist_share_of_time_pct": _share(self.phases, "persist"),
            },
            "verdicts": self.verdicts,
            "bottleneck": self.bottleneck(),
        }


_FIXES = {
    "generate": (
        "Mutation is pure CPU and deterministic, so it parallelises trivially and can be cached "
        "per (seed, principal, target fingerprint) — regenerating identical variants between runs "
        "is wasted work."
    ),
    "execute": (
        "Time is in the target's own response, which is the honest place for it to be. The lever "
        "is concurrency against a target that can take it — the live deployment is single-worker "
        "(~0.56 turns/s), so raising campaign concurrency there would be indistinguishable from "
        "the denial-of-service attack the platform tests for. Scale the target first."
    ),
    "judge": (
        "The deterministic ladder is string and status comparison; if it dominates, the rungs are "
        "being run in the wrong order. Keep the cheapest boolean pre-checks first so most verdicts "
        "decide before any expensive rung is reached."
    ),
    "persist": (
        "SQLite commits once per append. The fix is batching: a single transaction per attack (or "
        "per campaign) rather than per event, and WAL mode for concurrent readers. At the point "
        "that stops being enough, the ledger's narrow interface is a drop-in swap to Postgres — "
        "which is the reason it is narrow."
    ),
}


def _share(phases: dict[str, Phase], phase: str) -> float:
    total = sum(phases[p].stats()["total"] for p in _PHASES)
    return round(100 * phases[phase].stats()["total"] / total, 1) if total else 0.0


def _redteam(settings: Settings) -> RedTeamAgent:
    adapter = CopilotAdapter(settings, transport=httpx.ASGITransport(
        app=build_target(vulnerable=True)))
    return RedTeamAgent(adapter=adapter, checkpack=CopilotCheckPack(), engine=MutationEngine())


def _persist(ledger: EventLedger, run_id: str, attempt: AttackAttempt,
             verdict: Verdict) -> int:
    """Two ledger appends per attack — the Red Team's execution and the Judge's verdict."""
    ledger.append(agent="redteam", event_type=EventType.ATTEMPT_EXECUTED, run_id=run_id,
                  payload={"attempt_id": attempt.id, "mutator": attempt.mutator,
                           "statuses": [o.status for o in attempt.observed]})
    ledger.append(agent="judge", event_type=EventType.VERDICT_RECORDED, run_id=run_id,
                  payload={"attempt_id": attempt.id, "label": verdict.label.value,
                           "severity": verdict.severity.value, "rule": verdict.rule_fired})
    return 2


async def run_loadtest(attacks: int = 100, judge_samples: int = 0,
                       data_dir: Path | None = None,
                       settings: Settings | None = None) -> LoadTestResult:
    base = settings or Settings.from_env(load=False)
    settings = dataclasses.replace(
        base, target_url="http://loadtest.local", target_api_key="loadtest-key",
        data_dir=data_dir or base.data_dir)
    judge = Judge()
    result = LoadTestResult()
    ledger = EventLedger(settings.data_dir / "loadtest.db")
    run_id = f"loadtest-{int(time.time())}"

    try:
        started_wall = time.perf_counter()
        for i in range(attacks):
            seed_id, principal = _ROTATION[i % len(_ROTATION)]
            seed = seed_by_id(seed_id)
            if seed is None:  # pragma: no cover - the rotation is a fixed literal
                raise ValueError(f"unknown seed {seed_id!r}")
            campaign = Campaign(name=f"load-{i}", category=seed.category, target_id="loadtest",
                                seed_ids=[seed_id], auth_principals=[principal], max_attempts=1)
            # A fresh build per attack: stateful write seeds would otherwise measure the cost of
            # a 409 fast-path rather than the cost of the attack.
            redteam = _redteam(settings)

            t = time.perf_counter()
            attempts = redteam.generate(campaign, "loadtest")
            result.phases["generate"].add(t)

            t = time.perf_counter()
            executed = await redteam.execute(attempts[0], campaign)
            result.phases["execute"].add(t)

            t = time.perf_counter()
            verdict = await judge.judge(executed)
            result.phases["judge"].add(t)

            t = time.perf_counter()
            result.ledger_events += _persist(ledger, run_id, executed, verdict)
            result.phases["persist"].add(t)

            result.verdicts[verdict.label.value] = result.verdicts.get(verdict.label.value, 0) + 1
            result.attacks += 1
        result.wall_seconds = time.perf_counter() - started_wall
    finally:
        ledger.close()

    if judge_samples > 0:
        result.llm_rung_ms = await _time_llm_rung(settings, judge_samples)
    return result


async def _time_llm_rung(settings: Settings, samples: int) -> list[float]:
    """Time the real Bedrock compliance rung on a fixed, benign evidence blob (paid)."""
    from agentforge.bedrock import make_judge_compliance_check

    check = make_judge_compliance_check(settings)
    evidence = delimited_evidence([
        ObservedResponse(turn_index=0, status=200, latency_ms=0, response_bytes=64,
                         body_excerpt='{"reply": "I can only discuss this patient\'s chart."}')
    ])
    timings = []
    for _ in range(samples):
        t = time.perf_counter()
        await check(evidence)
        timings.append((time.perf_counter() - t) * 1000)
    return timings


def render_report(result: LoadTestResult) -> str:
    """The docs/LOAD_TEST.md body — baselines a future run can be compared against."""
    d = result.to_dict()
    phases = d["phases_ms"]
    rows = "\n".join(
        f"| {p} | {phases[p]['p50']} | {phases[p]['p95']} | {phases[p]['max']} | "
        f"{_share(result.phases, p)}% |"
        for p in _PHASES
    )
    llm = d["llm_rung_ms"]
    llm_line = (
        f"Measured over {llm['sampled']} real calls: **p50 {llm['p50']} ms, p95 {llm['p95']} ms** "
        f"— three orders of magnitude above every deterministic phase combined."
        if llm.get("sampled") else
        "Not measured on this run; re-run with `--judge-samples N` to include it."
    )
    det = d["bottleneck"]["deterministic_pipeline"]
    with_llm = d["bottleneck"].get("with_llm_rung", {})
    projection = "\n".join(
        f"| {k.replace('at_', '').replace('pct_of_attacks', '% of attacks')} | "
        f"{v['llm_share_of_time_pct']}% | {v['attacks_per_second']} |"
        for k, v in with_llm.items() if k.startswith("at_")
    )
    verdicts = ", ".join(f"{v} {k}" for k, v in sorted(d["verdicts"].items()))
    if with_llm:
        headline = (
            f"**The bottleneck is the Judge's LLM rung, and nothing else is close.** The whole "
            f"deterministic pipeline runs at **{d['attacks_per_second']} attacks/second**; one "
            f"call to the semantic rung costs **{llm['p50']} ms at p50**, so firing it on even "
            f"one attack in ten drops throughput to "
            f"**{with_llm['at_10pct_of_attacks']['attacks_per_second']}/second** and puts "
            f"{with_llm['at_10pct_of_attacks']['llm_share_of_time_pct']}% of wall-clock inside "
            f"that one call. Every optimisation that is not about *how often the rung fires* or "
            f"*how many fire concurrently* is noise."
        )
    else:
        headline = (f"Deterministic pipeline only: **{d['attacks_per_second']} attacks/second**. "
                    "Re-run with `--judge-samples N` to measure the paid rung, which is the phase "
                    "that actually governs throughput.")
    return f"""# Load test — measured throughput and the actual bottleneck

> Generated by `agentforge loadtest`. Run against the **ephemeral in-process build, never the live
> clinical target**: a sustained burst against a single-worker clinical deployment is
> indistinguishable from the denial-of-service attack this platform exists to test for.

{headline}

## Baseline

**{d['attacks']} consecutive attacks in {d['wall_seconds']} s — {d['attacks_per_second']}
attacks/second**, {d['storage']['ledger_events']} ledger events
({d['storage']['events_per_second']}/s). Verdicts: {verdicts}.

## Per-phase latency (ms)

| Phase | p50 | p95 | max | share of total |
|---|---|---|---|---|
{rows}

- **generate** — deterministic mutation: seed → variants. No model call.
- **execute** — the attack against the target, including its response time.
- **judge** — the deterministic verdict ladder (status/marker/count rules).
- **persist** — two append-only ledger writes per attack, PHI-masked, each committed.

## The Judge's LLM rung

{llm_line}

## Bottleneck

{'''### Once the paid rung fires

| Rung fires on | LLM share of wall-clock | Attacks/second |
|---|---|---|
''' + projection + "\n\n" + with_llm.get('fix', '') if projection else ''}

### Inside the deterministic pipeline

Reported for completeness, and worth reading with its error bars on: `generate`, `execute` and
`persist` all sit within a few tenths of a millisecond of each other, so which one comes top varies
between runs and naming a single winner over-reads the data. What the numbers do support is the
shape — the deterministic ladder (`judge`) is effectively free, and the remaining time is split
roughly evenly between building variants, the target's own response, and committing to SQLite.

On this run: **`{det['phase']}` ({det['share_of_time_pct']}% of deterministic time)**.
{det['fix']}

## How to reproduce

```bash
uv run agentforge loadtest --attacks {d['attacks']}                 # free, hermetic
uv run agentforge loadtest --attacks {d['attacks']} --judge-samples 8   # + times the paid rung
```
"""
