# AI cost analysis

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

An *authenticated* attack blends to **≈ $0.052**, dominated by the target's own inference:

| Component | Cost | Notes |
|---|---|---|
| Target inference | $0.046 | 65% reach the model @ $0.071/turn (measured) |
| HTTP-only (auth-rejected) | ~$0.000 | the other 35% never reach the model |
| Judge LLM rung (triaged) | $0.0039 | only ~30% of model-turns reach the paid Judge |
| Novel-seed generation | $0.0020 | one Maverick batch, amortized |
| Deterministic mutation | $0.000 | no model call — the bulk of generation |

## Projection at scale

Dollars are linear in *live* attempts; **wall-clock** is the binding constraint against a
single-worker target (0.56 turns/s measured), and the fix at each tier is
architectural. You cannot parallelize past a *shared* live target without a denial-of-service, so
volume moves to ephemeral target replicas while the live target gets a sampled canary subset.

| Attack runs | Est. cost | Wall-clock | Workers | Store | Architectural change |
|---|---|---|---|---|---|
| **100** | $5.21 | 2 min | 1 | SQLite, one box | single worker against the live target; deterministic generation inline |
| **1,000** | $52.12 | 19 min | 1 | Postgres + Redis | move the ledger/vuln DB to Postgres (SQLite write contention) and the per-process guards to a shared cache; still one worker against the shared live target |
| **10,000** | $521.20 | 19 min | 10 | Postgres + work queue | a work queue + horizontal Red Team workers driving 10 ephemeral target replicas; the live target gets only a sampled canary subset (never DoS the shared instance) |
| **100,000** | $5,212.00 | 39 min | 50 | Postgres + queue + object store | offline batch generation (pre-compute every deterministic variant), risk-preserving triaged judging (only ambiguous attempts reach the paid Judge), and 50 ephemeral target replicas |

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
