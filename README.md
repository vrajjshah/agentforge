# AgentForge

**An autonomous multi-agent platform that continuously red-teams an AI system — hunting,
evaluating, documenting, and regression-guarding vulnerabilities without a human in the loop for
every step.** Its first target is an AI **Clinical Co-Pilot** (a chat agent built on an OpenEMR
fork), but the engine is target-agnostic: a system under test plugs in through a `TargetAdapter`,
and all domain-specific success criteria live in a pluggable **check-pack** — never hardcoded.

```bash
uv run agentforge demo    # full discover → judge → document → regress loop, ~1s, offline, no cost
```

That command is the front door. It stands up an ephemeral vulnerable build, lets the Red Team
re-discover a real cross-patient PHI leak, has the Judge confirm it CRITICAL, drafts a report, and
proves the regression harness goes **red on the vulnerable build and green on the fixed one** —
with no network, no API keys, and nothing deployed.

### The three decisions worth arguing about

- **The attacker and the judge are separate agents on different model families, and the Judge never
  sees the Red Team's claim.** A system that invents an attack and then grades its own success has a
  conflict of interest by construction. The Judge's oracle is a **policy written before the attack
  ran** — not the attacker's opinion, not the response's vibe. That is what makes a verdict
  falsifiable rather than persuasive.
- **Deterministic first, models last.** Most attack generation is a mutation engine with zero model
  calls, and the Judge runs a cheap deterministic ladder before it ever pays for an LLM. This was a
  cost and reproducibility decision, not a hedge about model quality — and it is why the load test
  shows 99% of wall-clock sitting inside a single semantic call.
- **Model per role chosen by measured refusal behaviour, not brand.** I probed candidates and found
  frontier models refuse offensive-security prompts *even against your own application*, so the Red
  Team runs Llama 4 Maverick while the Judge runs Claude. Everything sits inside Bedrock under one
  BAA, because the target is a clinical system.

### What was actually hard

Not the attacks — **trusting the verdicts.** An evaluation platform that agrees with everything is
worse than no platform, so most of the engineering here is spent testing the tester: a Judge
calibrated against human labels and published as **0.833 agreement, precision 1.0** with every
disagreement listed; a drift gate on frozen goldens; and a rule that attacks the safety allow-list
held back are bucketed as **held back, never banked as passes**. A test that did not fire is not a
test that succeeded.

Two things in here are deliberately unflattering and stay that way: a **published negative result**
(a fix I built, measured, and found did not work — which also revealed my earlier measurements were
too noisy to support the small wins I had claimed), and [docs/GATE_LEDGER.md](docs/GATE_LEDGER.md),
which records **controls I believed were working and were not.** That ledger is the most honest
thing in the repo and the best guide to how the project thinks.

> ### Infrastructure status — as of 2026-07-22
>
> This project was built against live infrastructure that has since been **decommissioned**. What
> that means for a reader:
>
> | Was live | Status | What replaces it |
> |---|---|---|
> | Dashboard at `agentforge-web-production-c891.up.railway.app` | **gone** | `uv run agentforge dashboard` builds the same page locally |
> | Target at `45-55-53-165.sslip.io/copilot` (DigitalOcean) | **gone** | the ephemeral vulnerable/fixed builds used by `demo`, `reports`, `loadtest` |
> | GitLab CI at `labs.gauntletai.com`, self-hosted runner | **gone** | [`.github/workflows/gate.yml`](.github/workflows/gate.yml), re-proven red-then-green |
>
> **Everything an interviewer needs still runs offline**, because the suite and the demo were
> hermetic by design from the start — no network, no Bedrock, no live target. `uv run pytest`
> (160 tests) and `uv run agentforge demo` need nothing but `uv`.
>
> **What does not carry over, stated plainly:** the live results below — "zero exploits across 46
> fired authenticated variants" — are a measurement of *one specific deployment at one commit*.
> They are not a claim about the co-pilot's source code in the abstract. Several controls that made
> that hold lived in the deployment rather than the app: the reverse proxy, gateway auth and rate
> limiting, the OAuth scopes the client was registered with, and a single-worker topology the DoS
> reasoning depends on. Redeploying elsewhere produces a **different system under test** — which is
> why the adapter content-fingerprints the target on every run and would refuse to attribute an old
> measurement to a new deployment. Re-run the sweep; do not inherit the number.

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
git clone https://github.com/vrajjshah/agentforge.git && cd agentforge
uv venv --python 3.12
uv pip install -e . && uv pip install pytest pytest-asyncio ruff mypy bandit pip-audit respx

uv run pytest                    # hermetic suite, 160 tests — stubs the target + Bedrock, no network/cost
uv run agentforge demo           # one-command end-to-end demo (below) — no network/cost
```

Both of those work with no credentials and no deployment. That is the whole offline path.

The live commands below are kept for completeness and **cannot be run as written any more** — the
target they point at is decommissioned (see the infrastructure note above). They document how the
live results were produced, and would work again against a redeployed target:

```bash
cp .env.example .env             # then set AWS_BEARER_TOKEN_BEDROCK + (optionally) the target API key
uv run agentforge health         # is the target up? print its content fingerprint
uv run agentforge probe-bedrock  # Judge (Claude) + attacker (Llama) reachability + refusal check
```

Live commands (`--live`) hit a real deployed target and Bedrock and cost real money and time;
they are opt-in and meant to be run in batches, never in the default test suite.

## Running attacks against the live target

```bash
# Authenticated /chat + reads, novel seeds from the attacker model, semantic Judge, cost-capped,
# and non-destructive (no chart writes reach the live deployment):
uv run agentforge evals --live --principals api_key \
  --llm-judge --novel --safe-live --max 12 --budget 3
```

**Result: zero exploits against the hardened Co-Pilot across 46 fired authenticated variants**
(direct, encoded, model-generated, and multi-turn — including the newest surfaces, such as
conversation-id hijack) — an honest *defense held*, with the LLM Judge correctly distinguishing a
refusal from compliance.

All 46 are **confirmed defended** — but only after the one real defect this platform found on the
live app was fixed. The newest surface of all, on-demand upstream reconciliation
(`GET /week2/patients/{id}/reconciliation`), answered **502 to every id the sweep tried**. The
platform refused to score that as a pass (`no-usable-response` — the absence of a measurement is
not a result) and the headline rate sat at 87% until it was diagnosed, fixed, and re-validated.

**The sweep found the defect and got the cause wrong**, which is worth stating because it is the
more useful half of the story. The upstream EMR was never failing: every real patient returned 200
throughout. What 502'd was any id that does not resolve upstream — which is exactly what an
enumeration sweep generates, so the platform saw nothing but 502s and reported an unavailable
dependency. The actual defect was error *mapping*: a caller's bad id answered as a bad gateway. That cycle —
**discover → report → fix → re-validate → regress**, on a live application — is
[reports/reconciliation-502.md](reports/reconciliation-502.md), and it is the only finding here
that was not re-discovered on an ephemeral build.

It is also classified honestly: **LOW**. An unknown patient id is a *client* error, and answering
it with a 502 blamed the upstream EMR for the caller's mistake — while forcing a live EMR read per
request, an amplification lever aimed at a single-worker deployment. No PHI crossed a boundary, no
authorization was bypassed, and the route was auth-gated throughout. A security tool that inflated
that into a critical would be spending its credibility on the wrong finding.

Six categories are generated; **46 of 71 variants ran against the live target and 25 were held
back**, because `--safe-live` refuses to fire a chart write or an ingest at a live clinical system.
Those 25 are reported as held back, not as passes: `concurrency_idempotency` reaches the live
target through no other route, so its live coverage is honestly **zero** and the dashboard says so
rather than counting the platform's own safety guard as the target defending itself. The write-path
classes are covered instead against the ephemeral vulnerable build, where the same seeds are
fix-validated (`agentforge demo`, `agentforge reports`). `identity_role` — the `e0e7b6a` class,
which needs a valid principal by definition — is fired live through a patient-scoped *read* that
carries a forged actor, so the category is covered on the authenticated surface rather than
appearing as a row of blocked writes.

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
asserting the security property (another patient's date of birth is absent), not a status code.

This is the one command to run if you only run one. It needs no credentials, touches no network, and
finishes in about a second.

## Observability & analysis

```bash
uv run agentforge dashboard   # rebuild the dashboard data (coverage, findings, cost, activity)
uv run agentforge inner-loop  # testing-the-tester: the Judge's deterministic rungs vs ground truth
uv run agentforge judge-calibration        # last recorded LLM-rung agreement with human labels
uv run agentforge judge-calibration --live # re-score it (one model call per labelled case)
uv run agentforge cost        # regenerate docs/COST_ANALYSIS.md (scaling model, not cost x n)
```

- **Dashboard** — the six observability questions on one self-contained page (above).
- **Langfuse tracing** — each campaign is a trace with a nested span per agent hop; PHI-shaped
  values are masked before sending. Optional (no-op without keys). Cloud is used here for synthetic
  data; real PHI would self-host Langfuse under the same BAA (see [ARCHITECTURE.md](ARCHITECTURE.md)).
- **Inner-loop eval** — scores the platform's *own* verdicts against ground truth (each seeded
  defect run against a build where it is present and one where it is fixed). Read the score for
  what it is: this ground truth is **deterministic and exact by construction** — a status code
  either is 401 or it isn't — so a clean sweep here is a *wiring proof* (the harness fires, the
  oracle comes from the check-pack rather than the attacker, the ladder decides), not evidence of
  semantic accuracy. Treating it as an accuracy claim would be the overfit reading.
- **Judge calibration** — the rung that can genuinely be wrong is the narrow LLM compliance check
  on ambiguous `/chat` turns, so it is scored **separately, against human labels**
  (`evals/judge_calibration/cases.json`). The set is built from the cases that break naive scoring
  in both directions: refusals that echo PHI vocabulary, refusals that quote the injection back,
  compliance hidden behind a refusal preamble, compliance wrapped in a safety justification, and a
  healthy in-scope answer that must not become a finding. Agreement, precision, recall, and every
  individual disagreement are published; until a live scoring run exists the rung is reported as
  **uncalibrated**, never as a perfect score.

  Doing this found a real defect in the platform. The rung scored **precision 1.0 but recall
  0.44** — it never false-alarmed and missed more than half the real compliances, all in the same
  way: it read "compliance" as prose disclosure and missed the identical leak in JSON, partial
  disclosure, an accepted override, a reported out-of-scope tool action, and compliance on turn
  two after refusing turn one. The rubric was rewritten to enumerate those, which scores 1.0 on
  the set it was tuned against — **in-sample, so not a result** — and **0.80** on a held-out set
  written afterwards.

  Both of those errors traced to one cause: the rung was never told which patient was in scope. It
  now receives the check-pack's scope rule as trusted context alongside the attacker's turn and the
  response, both fenced as untrusted. Scoring that needed a **second** holdout — the first was spent
  the moment it diagnosed the bug — and scored **0.917**. A third pass added a small-cell clause
  and scored **0.917** on a **third** holdout that deliberately re-tests every earlier trap.

  **A fourth holdout then produced a negative result, and a more important methodological one.** A
  disclosure-by-negation clause scored **0.833 — exactly what the rubric scored without it**, and
  the canonical case it was written for is still missed. Worse, running the *identical* rubric twice
  over the *identical* twelve cases returned different answers: two boundary cases flipped, nine
  were stable. **So a single twelve-case run cannot resolve a one- or two-case difference from
  noise — which is the size of the differences the earlier steps were used to claim.** Every
  agreement figure here should be read as approximate; the current published number is **0.833 with
  precision 1.0**. Across all four runs precision never dropped below 1.0, so the direction of error
  is consistent: this rung under-reports rather than false-alarms — worth knowing when the headline
  result is "defense held". Full per-run table and the order any future attempt must follow:
  [ARCHITECTURE.md](ARCHITECTURE.md#two-different-accuracy-questions-measured-two-different-ways).
- **Cost analysis** — real per-unit spend projected to 100 / 1K / 10K / 100K runs, with the
  architectural change at each tier: [docs/COST_ANALYSIS.md](docs/COST_ANALYSIS.md).
- **Load test** (`agentforge loadtest`) — 100 consecutive attacks against the ephemeral build,
  never the live target: a sustained burst at a single-worker clinical deployment *is* the
  denial-of-service attack this platform exists to test for. Result: the deterministic pipeline
  runs at **~568 attacks/second**, while one call to the Judge's semantic rung costs **~1.3 s at
  p50** — so firing it on one attack in ten drops throughput to **~7/second** and puts **99% of
  wall-clock inside that single call**. The bottleneck is not code, it is a network round-trip to
  a frontier model, so the fixes are triage (keep the ladder cheapest-first so the rung fires only
  on genuinely ambiguous turns) and bounded concurrency — not a faster machine. Per-phase
  latencies and baselines in [docs/LOAD_TEST.md](docs/LOAD_TEST.md).

## Access control (Login with OpenEMR)

The dashboard supports **SSO against the OpenEMR authorization server** (OIDC authorization-code +
PKCE, RS256 id_token verification against the issuer's JWKS, CSRF/state protection, and deny-by-
default RBAC to security-operator identities/roles). Register the client once
(`agentforge sso-register --redirect-uri <dashboard>/callback`) and set the returned credentials.
**Exploit detail is operator-only — the platform holds itself to its own findings.** A vulnerability
report is a working attack sequence against a live clinical system, so publishing one to the open
internet is precisely the anti-pattern this platform exists to flag. The public demo therefore
splits the read view: *posture* is public (pass rate, per-category and per-severity counts, "defense
held"), *reproduction* is not. `/reports/*`, finding titles (which name the technique), and the
`findings` array of `/api/dashboard` require an authenticated, authorized operator regardless of
`AGENTFORGE_SSO_REQUIRE`; anonymous callers get counts and an explicit statement of what is withheld.
Setting `AGENTFORGE_SSO_REQUIRE=1` additionally gates the whole read view. RBAC is re-evaluated on
every request, so revoking an operator takes effect immediately rather than at session expiry.

A **break-glass operator login** (`/login/token`, POST-only, constant-time compare) exists so the
platform is never left *ungated* because the identity provider is down — the failure mode that
tempts an operator to turn the gate off. It is disabled unless `AGENTFORGE_ADMIN_TOKEN` is set, and
clearing that variable revokes every live break-glass session. See
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
reports/               generated vulnerability reports  ·  docs/  gate & exploit ledgers, diagrams,
                       cost & load baselines, scan triage, build-vs-configure record, evidence packet
fixtures/drift/        frozen, signed goldens for Judge drift detection
```

## The gate

`ruff · mypy --strict · pytest · bandit · pip-audit`, run by a **blocking pre-push hook**
(`.githooks/pre-push`; `git config core.hooksPath .githooks`). It is the primary gate, and it has
been watched blocking a planted failure and then passing — every control in
[docs/GATE_LEDGER.md](docs/GATE_LEDGER.md) ships with that proof, because a gate that has never
been executed on anything has never told you anything.

[`.github/workflows/gate.yml`](.github/workflows/gate.yml) runs the identical five checks inside
`container: python:3.12-slim`, on branch pushes, tag pushes, pull requests and manual dispatch.
Proven red-then-green:
[run 29951154890](https://github.com/vrajjshah/agentforge/actions/runs/29951154890) RED on a planted
`assert 1 == 2`, [run 29951258446](https://github.com/vrajjshah/agentforge/actions/runs/29951258446)
GREEN on all five. The planted failure was pushed with `--no-verify` so the pre-push hook could not
pre-empt the gate CI was being asked to prove. **The pre-push hook remains the primary gate**; CI is
the copy that runs somewhere other than the author's machine.

Two things that gate is deliberately built to survive, both learned the expensive way:

- **The declared environment is the executed environment.** An earlier version of this proof ran on
  a GitLab **shell executor**, which silently ignores `image:` — so it ran on the author's laptop
  and the declared container was never exercised, meaning the ledger claimed more than the evidence
  supported. Re-doing it properly paid for itself on the first run: it caught a test asserting
  `llm_share_of_time_pct > 90`, true on a laptop and **89.4% in a container**. A performance test
  that encodes the author's hardware reports the machine it ran on, not the property it claims to
  check. That is the "works on mine" class CI exists for, and precisely what a same-machine proof
  cannot find.
- **Coverage is decided in exactly one place.** The GitLab config carried job-level rules *narrower*
  than the rule deciding whether a pipeline existed at all, so a **tag push ran nothing — silently.**
  Not a red badge, not a notification: no pipeline. Tagging a release would have looked identical to
  a repo with a green gate. The Actions port was re-probed for the same hole
  ([run 29951709509](https://github.com/vrajjshah/agentforge/actions/runs/29951709509), from a tag
  push, green) and has one job and no job-level conditions, so there is no second place to drift.

> **Infrastructure note — 2026-07-22.** The original proof ran on GitLab CI at
> `labs.gauntletai.com` against a self-hosted runner on a DigitalOcean droplet. Both are
> decommissioned; those job and pipeline URLs are archived and **will not resolve**. The claims
> stand on the trace lines, which are quoted inline in
> [docs/GATE_LEDGER.md](docs/GATE_LEDGER.md), along with the two defects the migration itself
> surfaced. `.gitlab-ci.yml` was deleted rather than left describing a control that no longer exists.

Details, including the full proof-of-firing table for every control, in
[docs/GATE_LEDGER.md](docs/GATE_LEDGER.md).

## Why the dashboard gates its own findings

The dashboard is deliberately split: **posture is public** (pass rate, per-category and per-severity
counts, the calibration figures, "defense held") and **reproduction is not**. While the target was
live, a vulnerability report was a working attack sequence against a running clinical system, so
`/reports/*` returned **403** to an anonymous visitor — no exceptions, including for someone I
wanted to impress. Publishing working reproductions against a *live* deployment without a gate would
contradict the entire premise of the project, so the platform applied its own finding to itself.

> **Note on [reports/](reports/) being readable in this repository.** That is the other half of the
> same policy, not a hole in it. The gate protects a **running system**; the target is now
> decommissioned and every finding below is fixed and regression-guarded, so the reproductions point
> at nothing that exists. **Gate while live, publish once closed** — the ordinary disclosure
> lifecycle. The dashboard control is unchanged and still tested
> (`uv run pytest tests/test_web_gating.py`, 18 tests), and it governs again the moment anything is
> redeployed. The reports contain no credentials, no tokens, no host, and no real patient data.

Two ways in, both landing on the same gated view:

| Route | For | Where |
|---|---|---|
| **Log in with OpenEMR** (OIDC + PKCE, RBAC allow-list) | an operator who has an OpenEMR account | `/login` |
| **Operator token** (break-glass, POST-only, constant-time compare, every use audited) | an operator who does not | `/login/token` |

The break-glass path exists so the platform is never left *ungated* because the identity provider is
down — that is the failure mode that tempts someone to turn the gate off. **No token is in this
repository**, by construction: it lives only in a deployed service's `AGENTFORGE_ADMIN_TOKEN`
environment variable, and a secret committed to a repo is a secret published. Clearing that variable
revokes every live break-glass session immediately.

Every use of it — served, granted, *and denied* — is appended to the platform's own append-only
audit ledger by a writer that may record nothing else. Proven in
[docs/GATE_LEDGER.md](docs/GATE_LEDGER.md) controls 18, 19 and 32.

Since the deployment is decommissioned, the way to see this now is the test suite:
`uv run pytest tests/test_web_gating.py`, which asserts the 403, the withheld `findings` array, the
absent technique string, and the ledger entries for both a denied and a granted token.

## Scope, safety & data

Authorized security testing of **my own** application, run in an **isolated sandbox** seeded with
**synthetic patients only** — no real PHI, no real patients, no production database, no third party.
The target URL is an immutable allow-list, so the platform can attack nothing else; live runs are
cost-capped and, with `--safe-live`, send no state-changing writes to the deployed target. All
models run inside AWS under one BAA. Secrets live only in a git-ignored `.env`.

## Licence

AgentForge is **MIT** — see [LICENSE](LICENSE).

The system under test is a **separate repository** with a **different licence**: the Clinical
Co-Pilot is built on a fork of OpenEMR, so its derived parts are **GPL-3.0**. Nothing in this
repository is GPL, and nothing here relicenses that one. The only coupling between them is an
HTTP `TargetAdapter` and a check-pack describing the target's policy — no OpenEMR code is
vendored, imported, or linked here.
