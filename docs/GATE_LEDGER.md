# Gate Ledger — proof-of-firing for every control (DIRECTION §12 F12)

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
| 5 | **OWASP-completeness / data-quality gate** (F3) | Documentation | write a report with both OWASP axes `n/a` | `DataQualityError` | a valid dual-mapped report writes | `pytest tests/test_stores.py::test_vulndb_rejects_both_owasp_na` |
| 6 | **Duplicate-report gate** | Documentation | write two reports for the same attack sequence | `DataQualityError` on the 2nd | distinct sequences both write | `pytest tests/test_stores.py::test_vulndb_rejects_duplicate_attack_sequence` |
| 7 | **Immutable target allow-list** (F2) | adapter | resolve an off-origin URL | `AllowListViolation` | on-origin path resolves | `pytest tests/test_adapter.py::test_allow_list_blocks_off_origin` |
| 8 | **Least-privilege ledger writer** (F11) | ledger | `judge` appends an `approval` event | `WriterNotAuthorized` | judge appends its own verdict event | `pytest tests/test_stores.py::test_ledger_least_privilege` |
| 9 | **Per-campaign capability grant** (F2) | Red Team | send a `GET` when only `POST` is granted | `CapabilityViolation` | granted method executes | `pytest tests/test_redteam.py::test_capability_grant_blocks_ungranted_method` |
| 10 | **Live-target-reachable** (health) | adapter | target unreachable | recorded as `target_unreachable`, run halts, never judges blind | 200 → run proceeds | `pytest tests/test_adapter.py::test_invoke_records_transport_error` |

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

## Still to prove (added as each control ships)

- Judge **drift gate** on frozen fixtures (F6) — inject a wrong verdict against a signed
  fixture, watch the drift alarm block.
- **Regression harness** — re-introduce `ea8fa01` on the ephemeral vulnerable build, watch the
  suite go red on the *security property* (patient B's DOB present), not a generic 200.
- **Cost circuit-breaker** — feed a no-signal run, watch the Orchestrator HALT.
- **PHI masking** in the ledger — write an event carrying a PHI marker, watch it redacted.
