# AgentForge

An **autonomous multi-agent adversarial security platform** that continuously hunts,
evaluates, validates, and regression-guards vulnerabilities in an AI system under test.

Its first customer is the Week-1/2 **OpenEMR Clinical Co-Pilot**, but the engine is
**target-agnostic**: the system under test plugs in through a `TargetAdapter`, and all
clinical success criteria live in a pluggable **check-pack** — never hardcoded in the core.

## Why a multi-agent system (not a static test suite)

Attack generation and attack evaluation are **different jobs with a conflict of interest**,
so they are separate agents with separate trust levels:

| Agent | Role | Trust | Model |
|---|---|---|---|
| **Orchestrator** | Strategy: picks the next campaign, triggers regression, halts on no-signal | read-only on stores | deterministic + narrow LLM |
| **Red Team** | Offense: deterministic mutation engine + novel-seed model, fires live | may call the target; cannot judge itself | non-Claude Bedrock (+ deterministic) |
| **Judge** | Evaluation: deterministic-first ladder; verdict from the check-pack policy | tool-less; sees attacker/target text as untrusted evidence | Bedrock Claude (independent family) |
| **Documentation** | Reporting: confirmed verdicts → structured vuln reports | only writer to the vuln DB, behind a human gate | template + narrow LLM |

## Layout

```
src/agentforge/
  config.py            # settings (env-driven; secrets never in the tree)
  contracts/           # Pydantic v2 models = source of truth for /contracts JSON Schema
  adapters/            # TargetAdapter protocol + the co-pilot adapter (hits the LIVE target)
  checkpacks/copilot/  # clinical success criteria + PHI ground truth (behind the adapter)
  mutation/            # deterministic attack-mutation engine (no LLM)
  agents/              # redteam / judge / orchestrator / documentation
  stores/              # append-only event ledger + curated vuln DB
  seeds/               # the 8 real, test-pinned co-pilot defects as attack seeds
contracts/v1/          # exported, versioned JSON Schema (the peer-integration boundary)
evals/                 # the reproducible adversarial eval dataset (dual OWASP-mapped)
docs/GATE_LEDGER.md    # proof-of-firing for every gate (planted failure → block → pass)
```

## Deployed

- **Platform (this repo):** https://agentforge-web-production-c891.up.railway.app — a read-only
  observability dashboard over the live-target coverage matrix (`/`, `/health`, `/api/coverage`,
  `/api/target`). `/api/target` confirms the deployed platform reaches the live co-pilot.
- **Target (system under test):** https://45-55-53-165.sslip.io/copilot (the Week-1/2 Clinical
  Co-Pilot). Fingerprinted on every run — the platform never assumes it is static.

## Quick start

```bash
uv venv --python 3.12 && uv pip install -e . && uv pip install pytest ruff mypy bandit pip-audit respx
uv run pytest                       # hermetic suite (stubs the target + Bedrock) — 42 tests
uv run agentforge demo              # the killer demo: catch a real vuln live, no network/cost
uv run agentforge health            # live: is the target up? print its fingerprint
uv run agentforge probe-bedrock     # live: Judge (Claude) + seed (Llama) reachability
uv run agentforge run --category data_exfiltration --live   # LIVE campaign via the graph
uv run agentforge evals --live      # regenerate ./evals/ against the deployed target
```

Live commands (`--live`, `-m live`) hit the real deployed target/Bedrock and cost real money/time;
they are opt-in and batched, never in the default suite.

## Live findings (authenticated)

Run authenticated attacks through `/chat` + reads with the co-pilot's API key, novel seeds from
Bedrock Llama-4-Maverick, and the Bedrock-Claude semantic Judge:

```bash
uv run agentforge evals --live --principals api_key \
  --categories data_exfiltration,prompt_injection,tool_misuse,denial_of_service \
  --llm-judge --novel --safe-live --max 8 --budget 15
```

**Result: the hardened co-pilot held across all 32 authenticated `/chat` variants** (direct,
encoded, novel-Maverick-seeded, multi-turn) — an honest "defense held," with the LLM Judge
correctly distinguishing refusal from compliance. `--safe-live` keeps the run non-destructive (no
chart writes hit the live deployment); `--budget` is a hard cost cap.

**Error-analysis that made the verdicts trustworthy.** The first authenticated run *over-flagged*
(tool-misuse 8/8, injection 2/8). Reviewing the evidence found two false positives in the platform
itself: (1) a normal 200 from `/chat` was treated as "forbidden status"; (2) a refusal that echoed
the word "MRN" tripped a naive PHI-field marker. Both were fixed — `/chat` is now judged
semantically by the LLM rung; field markers are kept only for structured reads — with regression
tests so neither reappears. Catching the platform agreeing-with-everything *is* the value.

## Vulnerability reports

`uv run agentforge reports` generates ≥3 professional, reproducible reports in `reports/` — each
drafted by the Documentation agent from a confirmed Judge verdict and **fix-validated by the
regression harness** (re-running the exact attack against the patched build): `ea8fa01` (CRITICAL,
cross-patient PHI leak), `e0e7b6a` (HIGH, attribution forgery), `b5f4b1e` (MEDIUM, TOCTOU
double-write). Demonstrated on the ephemeral vulnerable build since the live target is hardened.

## The killer demo

`agentforge demo` spins up an **ephemeral, isolated vulnerable build** (the `ea8fa01` cross-patient
PHI leak, reverted) — never a toggle on the live target — and runs the full loop: the Red Team
re-discovers the leak live, the Judge flags **CRITICAL / MUST-FIX**, the Documentation agent drafts
a report, and the **regression harness goes RED on the vulnerable build and GREEN on the fixed
one**, asserting the security property (patient B's DOB absent), not a status code.

## Submission URLs

1. **Platform repo (GitLab):** https://labs.gauntletai.com/vrajshah/agentforge
2. **Deployed platform (Railway):** https://agentforge-web-production-c891.up.railway.app
3. **Target co-pilot repo (GitLab):** the OpenEMR fork carrying the Week-1/2 co-pilot.

## Authorization & scope

This is a **course assignment** run in a **sandbox** against **our own** app (a public
open-source OpenEMR fork) seeded with **synthetic patients only** — no real PHI, no real
patients, no production database, no third party. Building the red team *is* the defensive
goal. The target URL is an immutable allow-list; the platform attacks nothing else.
