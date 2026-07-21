# AgentForge

**An autonomous multi-agent platform that continuously red-teams an AI system — hunting,
evaluating, documenting, and regression-guarding vulnerabilities without a human in the loop for
every step.** Its first target is an AI **Clinical Co-Pilot** (a chat agent built on an OpenEMR
fork), but the engine is target-agnostic: a system under test plugs in through a `TargetAdapter`,
and all domain-specific success criteria live in a pluggable **check-pack** — never hardcoded.

- **Live dashboard:** https://agentforge-web-production-c891.up.railway.app — a self-contained
  security-ops view of coverage, findings, cost, and agent activity against the live target.
- **Target under test:** https://45-55-53-165.sslip.io/copilot — content-fingerprinted on every
  run (the platform never assumes the target is static).

## Why a multi-agent system (not a static test suite)

Generating an attack and judging whether it worked are different jobs with a built-in conflict of
interest, so they are **separate agents with separate trust levels and different model families**:

| Agent | Role | Trust level | Model |
|---|---|---|---|
| **Orchestrator** | Strategy: picks the next campaign, triggers regression, halts on no signal / over budget | read-only on stores; cannot write findings | deterministic (+ Claude Sonnet-5 for the strategic call) |
| **Red Team** | Offense: deterministic mutation engine + a novel-seed model; fires against the live target | may call the target; cannot judge itself | Llama 4 Maverick + deterministic |
| **Judge** | Evaluation: deterministic-first ladder; the safety oracle comes from the check-pack, never the attacker | tool-less; reads attacker/target text as untrusted evidence | Claude Opus 4.8 (independent family) |
| **Documentation** | Reporting: confirmed verdicts → structured vulnerability reports | the only writer to the vuln DB, behind a human gate | template-driven (+ Claude Sonnet-5) |

Every model runs through **Amazon Bedrock under a single AWS BAA**. The attacker was selected by
**measured refusal behaviour** — see the AI-use disclosure in [ARCHITECTURE.md](ARCHITECTURE.md).

## Quick start (from a cold clone)

Requires [`uv`](https://docs.astral.sh/uv/) and Python 3.12.

```bash
git clone https://labs.gauntletai.com/vrajshah/agentforge.git && cd agentforge
uv venv --python 3.12
uv pip install -e . && uv pip install pytest pytest-asyncio ruff mypy bandit pip-audit respx

uv run pytest                    # hermetic suite — stubs the target + Bedrock, no network/cost
uv run agentforge demo           # one-command end-to-end demo (below) — no network/cost
```

To run against the live target and Bedrock, copy the env template and fill it in:

```bash
cp .env.example .env             # then set AWS_BEARER_TOKEN_BEDROCK + (optionally) the target API key
uv run agentforge health         # is the target up? print its content fingerprint
uv run agentforge probe-bedrock  # Judge (Claude) + attacker (Llama) reachability + refusal check
```

Live commands (`--live`) hit the real deployed target and Bedrock and cost real money and time;
they are opt-in and meant to be run in batches, never in the default test suite.

## Running attacks against the live target

```bash
# Authenticated /chat + reads, novel seeds from the attacker model, semantic Judge, cost-capped,
# and non-destructive (no chart writes reach the live deployment):
uv run agentforge evals --live --principals api_key \
  --categories data_exfiltration,prompt_injection,tool_misuse,denial_of_service \
  --llm-judge --novel --safe-live --max 12 --budget 15
```

**Result: the hardened Co-Pilot held across 48 authenticated attack variants** (direct, encoded,
model-generated, and multi-turn — including the newest surface, such as conversation-id hijack) — an
honest *defense held*, with the LLM Judge correctly distinguishing a refusal from compliance.

The verdicts are trustworthy *because* the platform was caught over-flagging and corrected: the
first authenticated run reported false positives (a normal `200` from `/chat` read as "forbidden
status"; the word "MRN" inside a refusal tripping a naive marker). Both were root-caused and fixed —
`/chat` is now judged semantically, and field-name markers are kept only for structured reads — with
regression tests so neither recurs. Catching a judge that agrees with everything **is** the value of
an evaluation platform.

## Vulnerability reports

```bash
uv run agentforge reports        # writes reports/ — no network/cost
```

Generates three professional, reproducible reports, each **drafted by the Documentation agent from a
confirmed Judge verdict and fix-validated by the regression harness** (the exact attack re-run
against the patched build): a cross-patient PHI leak (CRITICAL), an attribution-forgery write (HIGH),
and a duplicate-write race / TOCTOU (MEDIUM). Because the live target is hardened, these are
demonstrated on an ephemeral, isolated vulnerable build. See [reports/](reports/).

## One-command demo (`agentforge demo`)

Spins up an **ephemeral, isolated vulnerable build** of the target (a known cross-patient PHI leak,
reverted) — never a toggle on the live system — and runs the full loop end to end: the Red Team
re-discovers the leak, the Judge flags it **CRITICAL / must-fix**, the Documentation agent drafts a
report, and the **regression harness goes red on the vulnerable build and green on the fixed one**,
asserting the security property (another patient's date of birth is absent), not a status code. This
is the spine of the demo video.

## Observability & analysis

```bash
uv run agentforge dashboard   # rebuild the dashboard data (coverage, findings, cost, activity)
uv run agentforge inner-loop  # testing-the-tester: precision/recall/accuracy vs known ground truth
uv run agentforge cost        # regenerate docs/COST_ANALYSIS.md (scaling model, not cost x n)
```

- **Dashboard** — the six observability questions on one self-contained page (above).
- **Langfuse tracing** — each campaign is a trace with a nested span per agent hop; PHI-shaped
  values are masked before sending. Optional (no-op without keys). Cloud is used here for synthetic
  data; real PHI would self-host Langfuse under the same BAA (see [ARCHITECTURE.md](ARCHITECTURE.md)).
- **Inner-loop eval** — scores the platform's *own* verdicts against ground truth
  (vulnerable vs fixed builds): currently precision 1.0 / recall 1.0 / accuracy 1.0 on the seeded
  defects, so a "defense held" result is trustworthy, not an artifact of a lazy judge.
- **Cost analysis** — real per-unit spend projected to 100 / 1K / 10K / 100K runs, with the
  architectural change at each tier: [docs/COST_ANALYSIS.md](docs/COST_ANALYSIS.md).

## Access control (Login with OpenEMR)

The dashboard supports **SSO against the OpenEMR authorization server** (OIDC authorization-code +
PKCE, RS256 id_token verification against the issuer's JWKS, CSRF/state protection, and deny-by-
default RBAC to security-operator identities/roles). Register the client once
(`agentforge sso-register --redirect-uri <dashboard>/callback`) and set the returned credentials.
Enforcement is configurable: the public demo leaves the read view open for review while every
mutating action is SSO+RBAC gated; production sets `AGENTFORGE_SSO_REQUIRE=1`. See
[ARCHITECTURE.md](ARCHITECTURE.md#platform-access-control--login-with-openemr-sso).

## Architecture

Four agents coordinate through versioned JSON-Schema messages, orchestrated by a LangGraph state
machine, observed by the dashboard. Full write-up in [ARCHITECTURE.md](ARCHITECTURE.md); threat
model in [THREAT_MODEL.md](THREAT_MODEL.md); users and the automation case in [USERS.md](USERS.md).

![AgentForge agent-interaction diagram](docs/diagrams/architecture.svg)

```
src/agentforge/
  adapters/            TargetAdapter boundary + the Co-Pilot adapter (hits the live target)
  checkpacks/copilot/  domain success criteria + PHI ground truth (behind the adapter)
  mutation/            deterministic attack-mutation engine (no model call)
  agents/              redteam · judge · orchestrator · documentation
  contracts/           Pydantic models = source of truth for the versioned JSON Schema
  stores/              append-only event ledger + curated vulnerability DB
  seeds/               the eight real, test-pinned target defects, as attack seeds
  bedrock.py           model access (Anthropic SDK for Claude, Bedrock converse for the attacker)
  graph.py             the LangGraph campaign loop  ·  web.py  the dashboard service
contracts/v1/          exported, versioned JSON Schema  ·  evals/  the reproducible eval dataset
reports/               generated vulnerability reports  ·  docs/  gate & exploit ledgers, diagrams
fixtures/drift/        frozen, signed goldens for Judge drift detection
```

## Submission URLs

1. **Platform repository:** https://labs.gauntletai.com/vrajshah/agentforge
2. **Deployed platform (dashboard):** https://agentforge-web-production-c891.up.railway.app
3. **Target application repository:** the OpenEMR fork hosting the Clinical Co-Pilot.

## Scope, safety & data

Authorized security testing of **our own** application, run in an **isolated sandbox** seeded with
**synthetic patients only** — no real PHI, no real patients, no production database, no third party.
The target URL is an immutable allow-list, so the platform can attack nothing else; live runs are
cost-capped and, with `--safe-live`, send no state-changing writes to the deployed target. All
models run inside AWS under one BAA. Secrets live only in a git-ignored `.env`.
