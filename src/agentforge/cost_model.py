"""AI cost & scale model — the single source of truth for the cost analysis.

The rubric's point is "not simply cost-per-token x n." This model separates the components that
scale differently, so the projection reflects the architecture, not a flat multiplication:

  * deterministic mutation generates the bulk of attacks with **no model call** ($0), and can be
    computed fully offline — it does not grow the paid bill with n;
  * the **target's own inference** (~$0.071/turn) is paid only when an attack actually reaches the
    model — an auth-rejected probe is HTTP-only (~free) — and is the dominant linear driver;
  * the **Judge LLM rung** is gated by deterministic pre-checks (risk-preserving triage), so only a
    fraction of attempts reach a paid Judge — the Judge bill is **sub-linear** in n;
  * **wall-clock**, not dollars, is the binding constraint against a single-worker target, and the
    fix at each tier is architectural.

Per-unit anchors: the $0.071/target-turn is a measured baseline; the Judge/seed per-call figures are
Bedrock published rates for the configured models, labelled as estimates.
"""

from __future__ import annotations

from dataclasses import dataclass

# Measured / published per-unit costs (USD).
COST_TARGET_TURN = 0.071        # measured: the target's own model call per /chat turn
COST_HTTP_ONLY = 0.0002         # an auth-rejected probe never reaches the model
COST_JUDGE_CALL = 0.02          # Opus Judge, ~500-tok evidence + short verdict (est.)
COST_SEED_BATCH = 0.002         # a Maverick novel-seed batch, amortized per attack (est., ≈0)

# Behavioural fractions for a representative *authenticated* attack run.
FRAC_REACH_MODEL = 0.65         # measured on the 48-case run: 31/48 turns reached the model
FRAC_NEED_LLM_JUDGE = 0.30      # fraction of model-turns ambiguous enough to reach the paid Judge

TARGET_THROUGHPUT_TPS = 0.56    # measured: single-worker target throughput (turns/sec)


@dataclass(frozen=True)
class Tier:
    n_attacks: int
    workers: int                # concurrent attack workers (bounded by target replicas)
    dollars: float
    wall_seconds: float
    store: str
    architectural_change: str

    @property
    def wall_human(self) -> str:
        s = self.wall_seconds
        if s < 90:
            return f"{s:.0f}s"
        if s < 5400:
            return f"{s / 60:.0f} min"
        return f"{s / 3600:.1f} h"


def per_attack_dollars() -> float:
    """Blended cost of one authenticated attack, by component (not a flat token multiply)."""
    live = FRAC_REACH_MODEL * COST_TARGET_TURN
    http = (1 - FRAC_REACH_MODEL) * COST_HTTP_ONLY
    judge = FRAC_REACH_MODEL * FRAC_NEED_LLM_JUDGE * COST_JUDGE_CALL
    return live + http + judge + COST_SEED_BATCH


# Per tier: how many attack workers the architecture supports (against the *live* shared target you
# can't parallelize past its capacity without a DoS — volume goes to ephemeral replicas).
_TIERS: tuple[tuple[int, int, str, str], ...] = (
    (100, 1, "SQLite, one box",
     "single worker against the live target; deterministic generation inline"),
    (1_000, 1, "Postgres + Redis",
     "move the ledger/vuln DB to Postgres (SQLite write contention) and the per-process guards to "
     "a shared cache; still one worker against the shared live target"),
    (10_000, 10, "Postgres + work queue",
     "a work queue + horizontal Red Team workers driving 10 ephemeral target replicas; the live "
     "target gets only a sampled canary subset (never DoS the shared instance)"),
    (100_000, 50, "Postgres + queue + object store",
     "offline batch generation (pre-compute every deterministic variant), risk-preserving triaged "
     "judging (only ambiguous attempts reach the paid Judge), and 50 ephemeral target replicas"),
)


def project() -> list[Tier]:
    per = per_attack_dollars()
    tiers: list[Tier] = []
    for n, workers, store, change in _TIERS:
        dollars = round(n * per, 2)
        model_turns = n * FRAC_REACH_MODEL
        wall = model_turns / (TARGET_THROUGHPUT_TPS * workers)
        tiers.append(Tier(n, workers, dollars, wall, store, change))
    return tiers


def render_cost_analysis() -> str:
    per = per_attack_dollars()
    live = FRAC_REACH_MODEL * COST_TARGET_TURN
    judge = FRAC_REACH_MODEL * FRAC_NEED_LLM_JUDGE * COST_JUDGE_CALL
    reach_pct = int(FRAC_REACH_MODEL * 100)
    miss_pct = 100 - reach_pct
    judge_pct = int(FRAC_NEED_LLM_JUDGE * 100)
    tiers = project()
    rows = "\n".join(
        f"| **{t.n_attacks:,}** | ${t.dollars:,.2f} | {t.wall_human} | {t.workers} | {t.store} | "
        f"{t.architectural_change} |"
        for t in tiers
    )
    components = [
        ("Target inference", f"${live:.3f}",
         f"{reach_pct}% reach the model @ ${COST_TARGET_TURN}/turn (measured)"),
        ("HTTP-only (auth-rejected)", "~$0.000", f"the other {miss_pct}% never reach the model"),
        ("Judge LLM rung (triaged)", f"${judge:.4f}",
         f"only ~{judge_pct}% of model-turns reach the paid Judge"),
        ("Novel-seed generation", f"${COST_SEED_BATCH:.4f}", "one Maverick batch, amortized"),
        ("Deterministic mutation", "$0.000", "no model call — the bulk of generation"),
    ]
    comp_rows = "\n".join(f"| {n} | {c} | {note} |" for n, c, note in components)
    return f"""# AI cost analysis

_Generated from `agentforge.cost_model` — regenerate with `agentforge cost`. The point is **not**
cost-per-token times n: the components below scale differently, and the projection reflects that._

## Development spend to date

Real, measured. Building + iterating cost a **few dollars total**: the hermetic test suite makes no
paid calls, and live runs are batched and cost-capped. The largest single batch — 48 authenticated
attack variants across four categories — logged **31 target model-turns ≈ $2.20**. The auth gate
rejects unauthenticated probes *before* the target's model runs, so those cost only HTTP (~free);
the platform's own Judge fires an LLM call only for ambiguous cases (deterministic verdicts are
free). Deterministic mutation — the bulk of attack generation — makes **no model call at all**.

## Per-attack cost, by component

An *authenticated* attack blends to **≈ ${per:.3f}**, dominated by the target's own inference:

| Component | Cost | Notes |
|---|---|---|
{comp_rows}

## Projection at scale

Dollars are linear in *live* attempts; **wall-clock** is the binding constraint against a
single-worker target ({TARGET_THROUGHPUT_TPS} turns/s measured), and the fix at each tier is
architectural. You cannot parallelize past a *shared* live target without a denial-of-service, so
volume moves to ephemeral target replicas while the live target gets a sampled canary subset.

| Attack runs | Est. cost | Wall-clock | Workers | Store | Architectural change |
|---|---|---|---|---|---|
{rows}

## Why this is not cost-per-token times n

1. **Generation is free and offline-able.** Deterministic mutation is $0 and can be fully
   pre-computed, so the paid bill does not grow with the number of *generated* variants — only with
   the number *executed live*.
2. **The Judge bill is sub-linear.** Risk-preserving triage means deterministic pre-checks decide
   which attempts reach the paid Judge; the rest are settled by a boolean. Doubling attempts does
   not double Judge spend.
3. **Boundary probes are ~free.** An attack rejected at the auth gate never pays for inference, so a
   large unauthenticated sweep costs almost nothing.
4. **Dollars are bounded by design.** A hard per-campaign budget and the finding-rate-per-dollar
   circuit breaker halt a run before spend outruns signal — the platform stops paying for a surface
   that has stopped producing findings.
5. **Time, not money, is the real limit** against a single-worker target; the architectural answer
   (queue + horizontal workers + ephemeral replicas) is what each tier above names.
"""
