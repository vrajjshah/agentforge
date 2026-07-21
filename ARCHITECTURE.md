# Architecture — AgentForge

## Summary (~500 words)

AgentForge is a **LangGraph-orchestrated multi-agent system** that autonomously hunts, evaluates,
documents, and regression-guards vulnerabilities in an AI system under test. It is a **system of
agents with a deliberate conflict-of-interest split**, not a pipeline: attack *generation* and
attack *evaluation* are different jobs, so they are different agents with different trust levels
and different model families.

**Four agents.** The **Orchestrator** (strategy) reads the coverage matrix, open findings, and
cost meter from the append-only event ledger and decides the next `Campaign` — which
category/surface to probe, when a cell is covered enough, when to trigger regression (on a
target-version change), and when to **HALT** (cost accruing without new signal — the circuit
breaker as a first-class state). It is read-only on the stores and cannot write findings. The
**Red Team** (offense) turns a `Campaign` into `AttackAttempt`s: a **deterministic mutation
engine** produces the bulk (encoding tricks, framing, IDOR sweeps, forged-identity headers,
token-budget fuzzing, multi-turn splits) with no model call — reproducible and refusal-free — and
an optional **non-Claude Bedrock model** adds novel seeds. It may call the live target but
**cannot judge its own success**. The **Judge** (evaluation) is independent by construction: a
different process, a different model family (**Bedrock Claude**), **tool-less**, and its oracle is
the **check-pack policy — never the Red Team**. It runs a cheapest-first ladder: deterministic
boolean pre-checks (did patient B's DOB appear? a 200 where auth should 401? a latency over
budget?) → hard business rules → a narrow LLM rung (boolean rubric) only for ambiguous semantic
compliance, seeing target output as untrusted, delimited evidence. The **Documentation** agent
converts a confirmed `Verdict` into a `VulnReport` through a data-quality gate, and is the only
writer to the vuln DB; a CRITICAL report needs explicit human approval before filing.

**Coordination.** Agents communicate through **versioned JSON-Schema messages** (`/contracts/v1`):
`Campaign → AttackAttempt → Verdict → VulnReport`, plus five typed errors. LangGraph manages the
state and the loop; the graph's `recursion_limit` is a hard bound on top of the cost breaker. A
**TargetAdapter** is the only path to the system under test (immutable allow-list, build
fingerprint), and all clinical success criteria live in a pluggable **check-pack** — so the engine
is **target-agnostic** and the co-pilot is merely its first customer.

**AI vs deterministic.** The default is deterministic (Aaron's "don't give a node an LLM if a
boolean will do"): mutation, most verdicts, the Orchestrator's routing, and the entire regression
harness are non-AI. Bedrock is used only where judgment is genuinely semantic — novel-seed
generation and the narrow compliance rung — because every live attack also pays the *target's* own
Bedrock inference (~$0.071/turn), so cost discipline is architectural.

**Regression & observability.** Confirmed exploits become deterministic replays that assert the
**security property** (patient B's DOB absent), never a bare 200 — a test that greens because the
model rephrased is worse than no test. Self-hosted Langfuse plus a coverage dashboard answer the
six required questions and feed the Orchestrator. Every gate ships with a **proof-of-firing**
(`docs/GATE_LEDGER.md`): planted failure → block → pass.

## Agent-interaction diagram

![AgentForge agent-interaction diagram](docs/diagrams/architecture.svg)

_Source: `docs/diagrams/architecture.mmd` (mermaid). GitLab does not reliably render mermaid, so
the committed SVG is the rendered artifact._

---

## Agent roster — role, inputs, outputs, trust level

| Agent | Owns | Inputs | Outputs | Trust level |
|---|---|---|---|---|
| **Orchestrator** | attack-gen strategy, coverage, regression triggers, cost/HALT | ledger (coverage, findings, cost), target version | `Campaign`, regression triggers, HALT | read-only on stores; **cannot write findings** |
| **Red Team** | attack generation + live execution | `Campaign` (+ capability grant) | `AttackAttempt` (+ observed evidence) | may call the target; **cannot judge**; cannot write stores |
| **Judge** | success/fail/partial evaluation | `AttackAttempt`, check-pack policy | `Verdict` | tool-less; reads target output as untrusted; **cannot generate attacks** |
| **Documentation** | professional vuln reports | confirmed `Verdict` + `AttackAttempt` | `VulnReport` | **only** writer to the vuln DB, behind quality + human gate |
| _Regression harness_ | deterministic replay of confirmed exploits | vuln DB, target version | pass/fail on the security property | non-AI; replays only |
| _Observability_ | traces, cost, coverage metrics | all agent events | the 6 required metrics | read-only |

## Inter-agent communication (message format)

Versioned JSON Schema in `/contracts/v1` (Pydantic models are the source of truth; a schema-sync
test fails if a model changes without re-export). Each message carries `schema_version`, ids for
correlation, and provenance. Happy-path: `Campaign` (Orchestrator→Red Team) · `AttackAttempt`
(Red Team→Judge) · `Verdict` (Judge→Orchestrator + Documentation) · `VulnReport` (Documentation→DB).
Five typed errors (`AgentError` with a code): `target_unreachable`, `budget_exceeded`,
`judge_timeout`, `no_findings_in_window`, `regression_detected` — each with `retryable`,
`partial_result`, and an `idempotency_key`. `extra="forbid"` means a malformed message is rejected
by the consumer (a contract test proves it).

## How the Orchestrator decides what the Red Team targets next

Deterministic-first: pick the **least-covered** (category × subcategory × auth-mode) cell from the
coverage matrix, weighted toward genuinely unprobed surface (the six fixed defects read "defense
held," so novel surface earns priority). A category is "covered enough" when its subcategories
each have ≥ N attempts with no new signal. Regression is triggered on a **target-version change**
(the adapter fingerprint changes). The one genuinely strategic call — "given these open highs and
this regression, what's the highest-value next campaign" — is where an LLM would earn its place;
it is stubbed deterministically for the MVP.

## How Judge verdicts feed the regression harness

A `Verdict` labelled EXPLOITED with a `seed_id` sets `regression_flag=True`. The confirmed exploit
becomes a versioned regression manifest (F7): the multi-turn sequence, auth principal, patient
fixture, target-version fingerprint, model/prompt versions, the **security-property assertion**
(not a status code), side-effects, and cleanup. The harness re-runs on every target-version change
and detects both **reappearance** of a fixed vuln and **cross-category regression** (fixing A
breaks B).

## Where human approval gates are, and why

1. **Before a CRITICAL report is filed** — an agent that confidently documents a false positive
   wastes engineering time; a human signs off first (`HumanApprovalRequired`).
2. **Before a co-pilot fix is merged to `main`** — the platform proposes a fix branch; a human
   approves the merge. Discover → propose → **human-approve** → validate → regress.
3. **Merging, filing a critical finding, anything irreversible** stays human. Propose, don't dispose.

## Where AI is used vs deterministic tooling (justified)

| Function | Choice | Why |
|---|---|---|
| Attack mutation (bulk) | **deterministic** | reproducible, refusal-free, free; a boolean beats a model |
| Novel-seed generation | **non-Claude Bedrock** | frontier models refuse offensive framing; a permissive model + the BAA fits |
| PHI-leak / DoS / status verdicts | **deterministic** | a static boolean ("did B's DOB appear?") is more reliable than any LLM |
| Semantic compliance ("did it obey the injection?") | **narrow LLM (Bedrock Claude)** | genuinely semantic; boolean rubric, one task, untrusted evidence |
| Orchestration / routing | **deterministic** | least-covered-cell selection is arithmetic |
| Regression harness | **deterministic** | a test must assert the property, not a model mood |

## Cost, rate-limit & model constraints at scale (F8)

Attack *generation* is nearly free (deterministic), but every **live** attack pays the target's
own Bedrock call (~$0.071/turn), so the real driver is *live executions*: 100K single-turn attacks
≈ ~$7.1K and ~50 h on one worker before judging. Handling: **risk-preserving triage** —
deterministic pre-checks decide which attempts reach a paid Judge (never blind sampling); the
Orchestrator's finding-rate-per-dollar circuit breaker; batched offline generation. Scale
inflection points: 100 (single box, SQLite) → 1K (Postgres + Redis seams) → 10K (queue +
horizontal Red Team workers) → 100K (offline batch generation + triaged judging). Backoff/queue/
abort on provider rate limits; the target's single-worker limit is a *target* property, not ours.

## Framework that manages agent state/coordination

**LangGraph** — a `StateGraph` with distinct agent nodes and a typed `CampaignState`, conditional
edges for the HALT branch, and a `recursion_limit` bounding the loop. This is Aaron's supervisor/
orchestrator pattern: the Orchestrator routes to workers that return to it. State is in-process for
the MVP (SQLite ledger for durability); Postgres + a work queue are the documented scale upgrade.

## AI-use disclosure

Every AI-powered decision is followed by deterministic verification or a human gate:
- **Red Team (non-Claude Bedrock)** → its output is *executed against the real target*; success is
  decided by the independent Judge, not the generator. Remaining risk: a novel attack the
  deterministic Judge can't classify → escalates to the LLM rung, then to a human.
- **Judge LLM rung (Bedrock Claude)** → only fires for ambiguous prompt-injection; its input is one
  task with untrusted, delimited evidence; it is tool-less so injected text can't reprogram it.
  Remaining risk: **judge drift** (see below).
- **Documentation** is template-driven (no LLM); a CRITICAL report needs human approval.

### Detecting and correcting a drifting Judge

The Judge's ground truth is a set of **frozen, signed fixtures** (request + response + tool-trace)
from *both* a vulnerable build and the fixed build — not attacks replayed against a moving live
target (which can't separate "judge drifted" from "app changed"). Every session re-runs the
fixtures; **if the Judge misclassifies a golden, it has drifted → alert + block** (the invariant
"the Judge must never approve a confirmed exploit as safe" is a test, not a hope). Drift
proof-of-firing: inject a deliberately wrong verdict against a fixture and watch the gate catch it.
Correction: pin the Judge model version, diff the fixture verdicts across model versions, and
recalibrate the rubric against human labels before promoting a new model (frontier models deprecate
on a ~2.5-year cycle — swapping one silently moves behaviour).
