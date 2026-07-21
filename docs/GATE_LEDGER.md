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
