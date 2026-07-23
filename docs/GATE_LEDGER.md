# Gate Ledger — proof-of-firing for every control

> *A gate that is blocking-by-design but executed on nothing is worthless — "a scan that can
> never fail never told you anything."* Every control below ships with a **planted failure that
> was watched blocking, then watched passing.** A control without a proof-of-firing row is not
> done.

Each row: the control, its owner, the planted failure, the expected block, the recovery-to-pass,
and the reproducible evidence command.

| # | Control | Owner | Planted failure | Expected block | Recovery→pass | Evidence (reproduce) |
|---|---|---|---|---|---|---|
| 1 | **Pre-push hard gate** (ruff·mypy·pytest·bandit·pip-audit) | platform | add a failing test | hook exits non-zero, push blocked | remove the test → exit 0 | see "Pre-push" below; raw exit `1`→`0` |
| 2 | **Judge invariant** — never label a confirmed exploit DEFENDED | Judge | feed a known PHI-leak (200 + `birthDate`) labelled by policy as unsafe | verdict ≠ DEFENDED | benign 401 → DEFENDED | `pytest tests/test_judge.py::test_judge_invariant_never_approves_confirmed_exploit` |
| 3 | **Contract test** — consumer rejects a malformed message | contracts | add an unknown field to a `Campaign` | `ValidationError` | valid message validates | `pytest tests/test_contracts.py::test_consumer_rejects_unknown_field` |
| 4 | **Schema-sync gate** — committed JSON Schema matches the models | contracts | change a model without re-export | test fails ("schema is stale") | re-run `export_schemas` | `pytest tests/test_contracts.py::test_exported_schemas_match_models` |
| 5 | **OWASP-completeness / data-quality gate** | Documentation | write a report with both OWASP axes `n/a` | `DataQualityError` | a valid dual-mapped report writes | `pytest tests/test_stores.py::test_vulndb_rejects_both_owasp_na` |
| 6 | **Duplicate-report gate** | Documentation | write two reports for the same attack sequence | `DataQualityError` on the 2nd | distinct sequences both write | `pytest tests/test_stores.py::test_vulndb_rejects_duplicate_attack_sequence` |
| 7 | **Immutable target allow-list** | adapter | resolve an off-origin URL | `AllowListViolation` | on-origin path resolves | `pytest tests/test_adapter.py::test_allow_list_blocks_off_origin` |
| 8 | **Least-privilege ledger writer** | ledger | `judge` appends an `approval` event | `WriterNotAuthorized` | judge appends its own verdict event | `pytest tests/test_stores.py::test_ledger_least_privilege` |
| 9 | **Per-campaign capability grant** | Red Team | send a `GET` when only `POST` is granted | `CapabilityViolation` | granted method executes | `pytest tests/test_redteam.py::test_capability_grant_blocks_ungranted_method` |
| 10 | **Live-target-reachable** (health) | adapter | target unreachable | recorded as `target_unreachable`, run halts, never judges blind | 200 → run proceeds | `pytest tests/test_adapter.py::test_invoke_records_transport_error` |
| 11 | **Cost circuit-breaker** | Orchestrator | feed a no-signal run past the window | `check_halt()` → HALT (`no_findings_in_window`) | a finding resets the window | `pytest tests/test_graph.py::test_circuit_breaker_halts_on_no_signal` |
| 12 | **Regression harness** (asserts the security property) | harness | replay `ea8fa01` against the ephemeral **vulnerable** build | `reproduced=True` → suite RED on the *specific* signal (patient B's `birthDate`), not a 200 | replay against the **fixed** build → GREEN | `pytest tests/test_killer_demo.py` · `agentforge demo` |
| 13 | **Judge invariant on a live-discovered exploit** | Judge | the vulnerable build returns 200 + PHI | verdict EXPLOITED / CRITICAL, never DEFENDED | fixed build → DEFENDED | `pytest tests/test_killer_demo.py` |
| 14 | **Judge-calibration (anti "agrees-with-everything")** | check-pack | a healthy 200 `/chat` turn, and a refusal echoing "MRN" | NOT flagged (semantic LLM rung decides, no naive status/marker) | a real leak → EXPLOITED | `pytest tests/test_checkpack.py::test_tool_misuse_on_chat_is_semantic_not_status` · `::test_chat_injection_has_no_naive_phi_marker` |
| 15 | **Idempotency / TOCTOU (double-write)** | Judge | two 2xx write-successes across confirms (`max_success_2xx=1`) | verdict EXPLOITED (`double-write`) | one 2xx + one 409 → DEFENDED | `pytest tests/test_judge.py::test_double_write_is_exploited_toctou` |
| 16 | **Per-campaign cost cap** | eval runner | a live run exceeding the budget | execution stops before the next billed turn | under budget → runs to completion | `run_category(..., budget_usd=)` halt path |
| 17 | **Judge drift gate on frozen fixtures** | drift gate | flip a golden's expected label / tamper the fixture | gate BLOCKS (drift / tampered) | intact goldens → passes | `pytest tests/test_drift.py` |
| 18 | **Exploit-detail gate** — reproduction is operator-only whenever the gate is engaged (see 35) | web | request `/reports/<id>.md` and `/api/dashboard` anonymously | 403 on the report; `findings: []` + `detail_gated` on the API; the technique string absent from the rendered page | authorized operator (SSO session, break-glass session, or `x-admin-token`) → full report + findings | `pytest tests/test_web_gating.py` |
| 19 | **Break-glass authority expires with its token** | web | clear `AGENTFORGE_ADMIN_TOKEN` while a break-glass session is live | the live session loses detail access on its next request (403) | token set → same session is authorized | `pytest tests/test_web_gating.py::test_break_glass_revoked_when_token_cleared` |
| 20 | **No-false-alarm guard on authorized writes** | check-pack | a legitimate authorized 200 chart write | NOT flagged (the signal is >1 success per record, not the first 200) | two 2xx across a raced/retried sequence → EXPLOITED | `pytest tests/test_checkpack.py::test_authorized_write_is_not_an_exploit_for_succeeding_once` · `tests/test_judge.py::test_double_write_is_exploited_toctou` |
| 21 | **Server-wins identity on the authenticated surface** | check-pack | authenticated read echoes the planted sentinel actor | verdict EXPLOITED / HIGH | same read without the sentinel → DEFENDED | `pytest tests/test_judge.py::test_authenticated_forged_actor_echo_is_exploited` · `::test_authenticated_read_without_the_forged_actor_is_defended` |
| 22 | **Held-back ≠ tested** | evals | a write variant refused by `--safe-live` | recorded as `blocked-live-safety`, excluded from the pass-rate denominator, shown as "+N held back" | a fired variant is judged normally | `pytest tests/test_judge.py::test_blocked_by_live_safety_is_distinguishable_from_a_transport_error` |
| 23 | **Live-safety blocks writes, not reads** | Red Team | `GET /week2/patients/1/provisional` under a `/provisional` block | allowed (a read cannot mutate) | `PATCH /week2/provisional/1` → `CapabilityViolation` | `pytest tests/test_redteam.py::test_live_safety_blocks_writes_but_not_reads_on_a_shared_prefix` |
| 24 | **Judge-calibration headline is the held-out score** | calibration | publish the score measured on the set the rubric was tuned against | the dashboard headline stays the held-out number; the in-sample one is carried but labelled | held-out result present → published | `pytest tests/test_judge_calibration.py::test_published_headline_is_the_held_out_score` · `::test_holdout_is_disjoint_from_the_development_set` |
| 25 | **Load test never fires at the live target** | loadtest | point the burst at a live deployment | execution is bound to an in-process ASGI transport; a run cannot reach the network | the ephemeral build serves all 100 attacks | `pytest tests/test_loadtest.py::test_loadtest_never_touches_the_live_target` |
| 26 | **A 5xx-only response is not a pass** | Judge | every turn returns 5xx (found live on reconciliation — and note the platform got the *cause* wrong: the upstream was healthy, the 502s came from non-resolving ids) | verdict INCONCLUSIVE (`no-usable-response` — states what was seen, not why), excluded from the defended count, pass rate visibly drops | one 5xx among successes → judged normally | `pytest tests/test_judge.py::test_all_5xx_is_inconclusive_not_partial` · `::test_a_single_5xx_among_successes_still_judges_normally` |
| 27 | **A spent holdout is never reused, and provenance is kept by identity** | calibration | score a fix on the set that diagnosed it; or drop a prior measurement because its score coincides with the headline | the headline moves to the newest unspent holdout; every earlier measurement is carried and labelled, matched by path not by value (holdout2 and holdout3 both scored 0.917) | fresh holdout present → published as the headline | `pytest tests/test_judge_calibration.py::test_holdout2_is_disjoint_from_everything_it_could_have_learned_from` | | calibration | score a fix on the set that diagnosed it | the dashboard headline moves to the newest unspent holdout; older scores are relabelled as provenance, not results | fresh holdout present → published as the headline | `pytest tests/test_judge_calibration.py::test_holdout2_is_disjoint_from_everything_it_could_have_learned_from` · `::test_holdout2_targets_the_failure_the_fix_claims_to_address` |
| 28 | **A client error is never a server error** (the live finding) | check-pack + Judge | replay the frozen pre-fix live evidence: three 502s from `/week2/patients/{id}/reconciliation` | verdict EXPLOITED (`forbidden-status`) — a policy that forbids 5xx makes the server error the measurement, not the absence of one | every fixed shape (200, 200+`degraded`, 404) → DEFENDED; live re-run scores DoS 12/12 | `pytest tests/test_regression_reconciliation.py` |
| 29 | **id_token verification survives a JWKS with no `kid`** | OIDC | serve a JWK Set with one RSA `use:sig` key and no `kid` (what OpenEMR actually publishes) | with the fallback removed: `PyJWKClientError: The JWKS endpoint did not contain any signing keys` — the exact live failure | fallback restored → the token verifies; a token signed by another key is still refused; two kid-less keys are refused as ambiguous | `pytest tests/test_sso.py -k "omits_kid or forged_token_is_still_rejected or ambiguous_kidless"` |
| 30 | **Strict CSP + no framing** | web | request any page and inspect headers | `default-src 'none'`, `frame-ancestors 'none'`, `nosniff`, `DENY` present | — (headers are unconditional) | `pytest tests/test_web_gating.py::test_security_headers_are_set` |
| 31 | **Errors never leak internals** | web | raise inside a request handler | generic 500 page; the exception text and traceback stay in the log | normal request → 200 | `pytest tests/test_web_gating.py::test_unhandled_errors_do_not_leak_internals` |
| 32 | **Every break-glass access is on the record** | web | submit a wrong operator token, then the right one | both appear in the ledger as `auth_access` (`denied`, then `granted`), written by the least-privilege `web` writer; the token value appears nowhere | a `web` writer attempting any other event type → `WriterNotAuthorized` | `pytest tests/test_web_gating.py::test_break_glass_use_is_recorded_in_the_ledger` · `::test_ledger_writer_for_auth_is_least_privilege` |
| 33 | **CI pipeline** (same five checks, on a machine that is not the author's, in the image the config declares) | CI | `tests/test_planted_failure.py` with `assert 1 == 2`, pushed with `--no-verify` so the pre-push hook could not pre-empt the CI gate | [run 29951154890](https://github.com/vrajjshah/agentforge/actions/runs/29951154890) RED — `FAILED tests/test_planted_failure.py - assert 1 == 2`, `1 failed, 160 passed` | remove it, push → [run 29951258446](https://github.com/vrajjshah/agentforge/actions/runs/29951258446) GREEN, all five checks | `.github/workflows/gate.yml`, GitHub-hosted runner, `container: python:3.12-slim` |
| 34 | **A tag push runs the gate** (the hole that was silent on GitLab) | CI | push tag `ci-probe-gha` | a run is created and the full gate executes in it | — (the probe *is* the pass: the failure mode being excluded is "no run at all") | [run 29951709509](https://github.com/vrajjshah/agentforge/actions/runs/29951709509) success, `event: push`, ref `ci-probe-gha`; probe tag deleted, run record kept |
| 35 | **Post-disclosure opens reads only** — publishing the findings must never open the mutating run trigger | web | set `AGENTFORGE_PUBLIC_REPORTS=1` and POST `/api/run/<category>` anonymously | 401 — the trigger is unreachable by the disclosure flag on every path | remove the flag → the read gate returns 403 and `detail_gated: true` | `pytest tests/test_web_gating.py -k "public_mode or restores_the_gate"` |

> **Disclosure note — 2026-07-23.** Control 18 is **intentionally not engaged on the public
> deployment.** The gate exists because publishing a working attack sequence against a *live*
> healthcare system is the anti-pattern this platform exists to flag. That system was
> decommissioned on 2026-07-22 and every finding is fixed and regression-guarded, so the reason
> expired and the reports became the evidence — the ordinary disclosure lifecycle: **gate while
> the target is live, publish once it is closed.** The deployment therefore sets
> `AGENTFORGE_PUBLIC_REPORTS=1`.
>
> This is recorded rather than quietly removed, because a ledger that only lists controls
> currently switched on is a marketing page. Three things keep it honest: the control is
> **unchanged in code and still proven** by its planted-failure row (the tests run with the flag
> off, and one of them flips it back to watch 403 return); the flag opens **reads only**, which is
> control 35; and re-gating a redeployment is **removing one environment variable**, not a revert.
> If the co-pilot is redeployed, unset it — the gate resumes with no code change.


## The CI pipeline: what it runs on now, and what re-proving it properly cost

> **Infrastructure note — 2026-07-22.** This gate has been **migrated to GitHub Actions**
> (`.github/workflows/gate.yml`) and re-proven red-then-green there; see controls 33 and 34.
> `.gitlab-ci.yml` was deleted in the same change. The original proof ran on GitLab CI at
> `labs.gauntletai.com` against a self-hosted runner on a DigitalOcean droplet — **both are
> decommissioned, so every `labs.gauntletai.com` link below is archived and will not resolve.**
> The claims those links supported are real, so the decisive trace lines are quoted inline instead
> of being deleted or softened. Raw traces are retained outside this repo in
> a private archive (jobs 55608, 55610, 55744, 55750 + 43 pipeline records).
>
> The lessons in this section are kept in full and carried forward into the comments of
> `.github/workflows/gate.yml`, because the traps are the interesting part, not the vendor.

The gate runs the same five checks as the pre-push hook, in the same order, inside
`container: python:3.12-slim` on a GitHub-hosted runner. If the workflow triggers at all — branch
push, tag push, pull request, or manual dispatch — the whole gate runs in it.

**Archived: the GitLab configuration this replaced.** Runner 192 `agentforge-ci` — project-scoped,
**docker executor**, image `python:3.12-slim`, on an always-on droplet under systemd (`enabled` +
`active`, survives reboot). Decisive lines from the retained traces:

```
job 55744 (RED)    Using Docker executor with image python:3.12-slim ...
                   FAILED tests/test_planted_failure.py::test_planted_failure - assert 1 == 2
                   FAILED tests/test_loadtest.py::test_bottleneck_is_the_llm_rung_once_it_is_sampled
                                                                              - assert 89.4 > 90
                   2 failed, 159 passed, 10 warnings in 10.28s
                   ERROR: Job failed: exit code 1

job 55750 (GREEN)  Using Docker executor with image python:3.12-slim ...
                   $ uv run ruff check src tests   → All checks passed!
                   $ uv run mypy src               → Success: no issues found in 50 source files
                   $ uv run pytest                 → 160 passed, 10 warnings in 8.58s
                   $ uv run bandit -q -r src
                   $ uv run pip-audit              → No known vulnerabilities found
                   Job succeeded
```

Note what the RED trace actually caught: **two** failures, not one. The planted `assert 1 == 2`,
and `assert 89.4 > 90` — a real host-dependent defect the plant had nothing to do with. That second
line is the entire argument for running the gate somewhere other than the author's laptop, and it
is visible in the same trace that proves the gate fires.

The GitHub Actions re-proof reproduced the same shape on the new substrate:

```
run 29951154890 (RED)     ruff → All checks passed!
                          FAILED tests/test_planted_failure.py::test_planted_failure - assert 1 == 2
                          1 failed, 160 passed, 10 warnings in 3.08s
                          bandit and pip-audit never ran — the cheapest-first ladder stops at the
                          first failure, which is the intended behaviour, not a gap in coverage

run 29951258446 (GREEN)   ruff · mypy (50 source files) · 160 passed · bandit · pip-audit
                          No known vulnerabilities found
```

**Two defects the migration itself surfaced, recorded because they were found by running it rather
than reading it — the same rule this ledger applies to everything else.** First, the workflow
declared `UV_CACHE_DIR: /tmp/uv-cache` and the run log showed `setup-uv` overriding it with its own
path: a declared setting that never took effect. Harmless, and precisely the shape of the shell-
executor defect below, one layer down. It was removed rather than left standing. Second, pinning
`astral-sh/setup-uv@v9` — inferred from the latest release's `tag_name` of `v9.0.0` — failed at
`Set up job` with `unable to find version v9`: that action publishes floating major aliases only
through `v7`, while `v8` and `v9` exist as exact releases only. Both actions are now pinned to a
**commit SHA**, which removes the guess and also closes the larger hole, since a floating major tag
is mutable by the action's owner and amounts to a standing grant to run whatever they publish next.

**The first version of this proof was not good enough, and the ledger said more than it had earned.**
That run used a **shell executor**, which silently ignores `image:` — so it executed on the author's
laptop (`arch=arm64 os=darwin`) against a uv-managed venv, and the `python:3.12-slim` the config
declares was never exercised. The gate did fire, and the red-then-green was real, but the claim
"proven red-then-green" implied coverage of the declared environment that the evidence did not
support. The runner was also a throwaway, deleted afterwards, leaving the pipeline dormant.

Re-proving it on the declared executor **immediately found a defect the first proof structurally
could not**: `test_bottleneck_is_the_llm_rung_once_it_is_sampled` asserted
`llm_share_of_time_pct > 90`. True at 99.5% on a laptop; **89.4% inside a container**, because the
deterministic phases are slower there. A performance test that encodes the author's hardware reports
the machine it ran on, not the property it claims to check. It now asserts the relationship — the
rung's share exceeds the entire deterministic pipeline, and rises monotonically with the firing rate
— which is host-independent. That is exactly the "works on mine" class CI exists to catch, and a
same-machine proof can never surface it.

| Check | Result |
|---|---|
| Executor and image actually used | `Using Docker executor with image python:3.12-slim` |
| Runner persistence | systemd `enabled` + `active`; not a laptop |
| Order of operations | `RUN_CI=1` set **only after** the API reported the runner `online` |
| Config produces jobs | branch push created pipeline 16104 with a real job — **on a branch only; see below** |
| Defect found on first real run | one, host-dependent assertion, fixed |

**That row over-claimed, and the row above it is how I know.** "No zero-jobs trap" was tested on a
branch push and written as if it covered the config. It did not. The `gate` job carried
`rules: [if: $CI_COMMIT_BRANCH, if: $CI_MERGE_REQUEST_IID]` — narrower than the `workflow:` rule
that decides whether a pipeline is created at all. A **tag** pipeline sets neither variable.

I predicted that would produce a red "no jobs" pipeline and probed it rather than asserting:
pushing tag `ci-probe-before` created **no pipeline whatsoever**. GitLab does not warn when nothing
matches; it declines to create the pipeline. Tagging a release would have run zero checks, with no
red badge, no notification, and a repo that looked exactly like one with a green gate. Worse than
the failure I expected, because the expected one is visible.

Fixed by deleting the job-level rules so coverage is decided in one place. Re-probed the identical
scenario: tag `ci-probe-after` → **pipeline 16120, 1 job, `gate` success in 106s**. Both probe tags
were deleted; the pipeline records remain as the evidence.

| | before | after |
|---|---|---|
| tag push | **no pipeline created — silent** | pipeline 16120, `gate` success |
| branch push | pipeline 16104, 1 job | pipeline 16119, 1 job |

**Re-probed on GitHub Actions, because a migration is exactly when a closed hole reopens.** The
same scenario on the new gate: pushing tag `ci-probe-gha` created
[run 29951709509](https://github.com/vrajjshah/agentforge/actions/runs/29951709509), `event: push`,
which ran the full gate to **success** (control 34). The probe tag was deleted and the run record
kept, same as before. This is not a formality — the GitLab hole came from coverage being decided in
two places, and porting a config to a system with entirely different trigger semantics is the most
likely moment to reintroduce it. Hence `on:` in `.github/workflows/gate.yml` lists branches, tags,
pull requests and dispatch in one place, with **no job-level `if:` and exactly one job**, so there
is no second place for the two to drift apart.

Found because the sibling OpenEMR repo hit the same root cause from the opposite side: there
`golden-gate` was rule-restricted while `lint` and `security` were not, so a manually-triggered
pipeline ran two of three jobs and reported **success** — a green badge with the test suite missing.
Job rules narrower than workflow rules, failing loud-but-incomplete there and silent-and-total here.

Three controls in this repo have now been believed-working and were not: the shell executor that
ignored `image:`, the runner created unlocked, and this. Every one was found by exercising the
control; none by reading it. That is the platform's own thesis applied to its own scaffolding, and
it keeps holding.

The migration to GitHub Actions added a fourth and a fifth, both minor and both the same species:
a `UV_CACHE_DIR` that was declared and silently overridden, and an action pinned to a floating tag
that did not exist. Neither would have been caught by reading the file — the first looks correct and
the second *is* correct-looking YAML naming a real release. The count is going up rather than down,
which is the honest thing to report about a repo that keeps checking: it is not evidence the
scaffolding is getting worse, it is evidence that a control nobody exercises has an indefinite
half-life of looking fine.

One prediction I made and got wrong, recorded because it was falsifiable: the sibling OpenEMR
pipeline found six CVEs in `pip 25.0.1` bundled in `python:3.12-slim`, and I expected this pipeline
to fail the same way. It did not. `uv sync` builds a venv that does not contain `pip`, so
`uv run pip-audit` audits the project's locked dependency tree rather than the image's system
interpreter. Same image, same tool, different scope — the reason is specific, not luck.

## Pre-push gate — live proof-of-firing (control #1)

```
# plant a failure
echo 'def test_x(): assert 1 == 2' > tests/test_planted_failure.py
bash .githooks/pre-push ; echo "exit: $?"     # → 1 (BLOCKED: "1 failed")
# recover
rm tests/test_planted_failure.py
bash .githooks/pre-push ; echo "exit: $?"     # → 0 ("✓ pre-push gate passed")
```

Observed 2026-07-21: planted-failure exit `1` (blocked), clean exit `0` (passed).

_Proven live 2026-07-21: controls #1–#13, including the **regression harness red-then-green on a
real vuln** (`agentforge demo` / `tests/test_killer_demo.py`) and the **cost circuit-breaker
HALT**._

## Still to prove (Final-ward)

- **PHI masking** end-to-end — `redact()` is unit-proven (`test_redact_scrubs_markers`); wiring it
  on every ledger write path is the Final hardening.
- **Judge calibration against human labels** — the drift gate (#17) guards against *change*; a
  one-time human-labelled calibration set would establish the baseline agreement number.
