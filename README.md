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

## Quick start

```bash
uv venv --python 3.12 && uv pip install -e . --group dev
cp .env.example .env         # then fill in Bedrock + target details (see .env.example)
uv run pytest                # hermetic suite (stubs the target + Bedrock)
uv run agentforge run --campaign access-control   # LIVE probe against the deployed target
uv run agentforge evals      # regenerate ./evals/ from the seed set
```

Live tests (`-m live`) hit the real deployed target and cost real money/time; they are
opt-in and batched, never in the default suite.

## Authorization & scope

This is a **course assignment** run in a **sandbox** against **our own** app (a public
open-source OpenEMR fork) seeded with **synthetic patients only** — no real PHI, no real
patients, no production database, no third party. Building the red team *is* the defensive
goal. The target URL is an immutable allow-list; the platform attacks nothing else.
