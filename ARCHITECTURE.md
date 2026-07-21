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

**AI vs deterministic.** The default is deterministic — don't give a node a model if a boolean will
do: mutation, most verdicts, the Orchestrator's routing, and the entire regression
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
becomes a versioned regression manifest: the multi-turn sequence, auth principal, patient
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

The default is **deterministic** — a static boolean is cheaper, faster, more reliable, and never
refuses. A model is used only where the task is genuinely semantic.

| Function | Choice | Why |
|---|---|---|
| Attack mutation (the bulk) | **deterministic** | reproducible, refusal-free, no per-variant cost |
| Novel-seed generation | **LLM (non-Claude)** | needs creative variety; a permissive attacker model |
| PHI-leak / status / idempotency verdicts | **deterministic** | a static boolean ("did patient B's DOB appear?", "did two writes both succeed?") beats any LLM |
| Semantic compliance ("did the model obey the injection?") | **narrow LLM (Claude)** | genuinely semantic; a boolean rubric on one task, over untrusted evidence |
| Orchestration / routing | **deterministic** | least-covered-cell selection is arithmetic |
| Regression harness | **deterministic** | a test must assert the security property, not a model's mood |

## Model roster & selection (AI-use disclosure)

**Every model runs through Amazon Bedrock, in one region, under a single AWS BAA.** Inference stays
inside AWS; AWS does not route prompts or outputs to the model providers and does not train on them.
This is what lets a hospital run the platform against a system holding real PHI without a second
vendor agreement. (In this project the target's data is **synthetic** — no real PHI — but the
platform is built to the same standard.)

| Agent | Model | Client | Rationale |
|---|---|---|---|
| **Red Team (attacker)** | `us.meta.llama4-maverick-17b-instruct` (Meta, US-origin) | Bedrock `converse` | See selection note below |
| **Judge (evaluator)** | `us.anthropic.claude-opus-4-8` (Anthropic) | AnthropicBedrock SDK | Reliability-critical; deterministic-first keeps its call volume low |
| **Orchestrator + Documentation** | `us.anthropic.claude-sonnet-5` (Anthropic) | AnthropicBedrock SDK | Fast, cheaper, strong; these are low-volume strategic calls |
| Attack mutation | — (no model) | — | Deterministic engine — the bulk of generation |

**Attacker selection was by measured refusal behaviour, not vendor preference.** A frontier model
that refuses offensive-security workflows is unusable as a Red Team, so candidates were probed with
the *authorized* red-team prompt on identical infrastructure:

- **Llama 4 Maverick — complied.** Selected. Non-Claude on purpose: a different model family from the
  Judge is the independence control (a generator and judge from the same family share blind spots).
- **OpenAI `gpt-oss` — refused** the authorized prompt.
- **DeepSeek-R1 — refused**, and is non-Western-origin (a provenance consideration for a healthcare
  buyer); available behind an explicit off-by-default flag only, never the default.
- **Claude is never the attacker** — it declines offensive tasks by design; it is the Judge instead.

So the roster is **Western-origin by default**, chosen by evidence, under one BAA — a selection a
security reviewer can audit rather than take on faith.

### Every AI decision is followed by deterministic verification or a human gate

- **Red Team output** is *executed against the real target*; whether it succeeded is decided by the
  independent Judge, never by the generator. A novel attack the deterministic Judge can't classify
  escalates to the LLM rung, then to a human.
- **Judge LLM rung** fires only for ambiguous semantic cases; its input is one task over untrusted,
  delimited evidence, and it is tool-less, so injected text in a response cannot reprogram it.
  Remaining risk — **judge drift** — is guarded below.
- **Documentation** is template-driven (no model authors the report); a CRITICAL finding requires
  explicit human approval before it is filed.

### Detecting and correcting a drifting Judge

The Judge's ground truth is a set of **frozen, content-signed fixtures** (request + observed
response + the known-correct label) captured from *both* a vulnerable and a fixed build — not
attacks replayed against a moving target, which cannot separate "the judge drifted" from "the app
changed." Every run re-judges the fixtures; if the Judge misclassifies one, it has **drifted → the
gate alerts and blocks**, and a tampered fixture (signature mismatch) is caught too. Correction: pin
the Judge model version, diff the fixture verdicts across versions, and recalibrate against
human-labelled cases before promoting a new model — frontier models are deprecated on a multi-year
cycle, and swapping one silently moves behaviour.

## Cost, rate-limits & model constraints at scale

Attack *generation* is nearly free (deterministic), but every **live** attack pays the target's own
model call (about $0.07/turn here), so the real cost driver is *live executions*, not our
generation: ~100K single-turn attacks ≈ ~$7K and tens of hours against a single-worker target
before judging. The platform handles this with **risk-preserving triage** — deterministic
pre-checks decide which attempts reach a paid Judge, never blind sampling — plus a
finding-rate-per-dollar circuit breaker, a hard per-campaign budget, and batched offline generation.
Scale inflection points, each naming the architectural change: 100 (single box, SQLite) → 1K
(Postgres + a shared cache/queue for the per-process guards) → 10K (work queue + horizontal Red Team
workers) → 100K (offline batch generation + triaged judging). Provider rate limits are handled with
backoff/queue/abort.

## Framework that manages agent state/coordination

**LangGraph** — a `StateGraph` with distinct agent nodes, a typed `CampaignState`, conditional edges
for the halt branch, and a `recursion_limit` bounding the loop (a supervisor/orchestrator pattern:
the Orchestrator routes to workers that return to it). State is in-process, backed by a SQLite event
ledger for durability; Postgres + a work queue are the documented scale upgrade.
