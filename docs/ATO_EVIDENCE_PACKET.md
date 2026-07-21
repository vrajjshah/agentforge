# Evidence packet — AgentForge adversarial security platform

> **What this is.** An ATO-style evidence packet: the artifact an authorizing official would read
> before granting a system permission to operate. It states the boundary, the data it touches, the
> controls claimed, the **evidence for each claim**, and — the part that usually goes missing — the
> residual risks the system is being authorized *with*.
>
> **What this is not.** A real Authority to Operate. No authorizing official has reviewed this, no
> independent assessor has tested it, and it is not a FedRAMP or FISMA package. It is structured
> like one because that structure forces every control claim to name its evidence, which is the
> discipline worth borrowing.

**System:** AgentForge — autonomous multi-agent adversarial security testing platform
**Version:** `main` @ this commit · **Prepared:** 2026-07-21
**Categorization (FIPS 199 analogue):** Confidentiality **Moderate**, Integrity **Moderate**,
Availability **Low** — the platform holds vulnerability reproductions for a healthcare system
(confidentiality), its verdicts drive remediation decisions (integrity), and an outage delays
testing without harming patients (availability).

## 1. Authorization boundary

**Inside:** the platform's four agents and orchestration graph, the event ledger and vulnerability
database, the eval datasets and generated reports, and the deployed read-only dashboard
(`agentforge-web-production-c891.up.railway.app`).

**Outside, but connected:**

| External system | Direction | What crosses | Control |
|---|---|---|---|
| Clinical Co-Pilot (target) | outbound HTTP | attack requests, responses | Immutable origin allow-list — the platform can attack nothing else (`AllowListViolation`) |
| AWS Bedrock | outbound HTTPS | attack payloads, delimited response evidence | One AWS BAA, `us-east-1`, bearer-token auth |
| OpenEMR authorization server | outbound HTTPS | OIDC code exchange, JWKS | Endpoints derived from the configured issuer, never a caller-supplied value |
| Langfuse Cloud | outbound HTTPS | trace metadata | PHI-masked before send; no-op without keys |

**Explicitly out of scope:** client-side DOM attacks against the co-pilot's iframe embedding. They
need a browser-driven adapter, and are documented as a limit rather than approximated with an HTTP
probe (`THREAT_MODEL.md`).

## 2. Data

**No real PHI.** Synthetic patients only, in an isolated sandbox. "Jordan Vulnera, DOB 1958-03-11"
is fabricated.

The sensitive data the platform *does* hold is **working exploit reproductions against a live
healthcare system** — which is why the confidentiality categorization is Moderate despite the
absence of PHI, and why reproduction detail is gated (§3, AC-3).

| Store | Contents | Protection |
|---|---|---|
| Event ledger | attempt/verdict/cost/auth metadata | Append-only; least-privilege writers; `mask_phi` on every write path |
| Vulnerability DB | full reproductions incl. synthetic PHI | Access-controlled; data-quality gate on write |
| `reports/` | reproduction steps | Operator-only over HTTP; readable in-repo |
| `evals/` | attack manifests + verdicts | Committed; no PHI (bodies reduced to metadata) |

## 3. Control claims and their evidence

Each row names where the claim is enforced and how it was **proven to fire**. Full proof-of-firing
table: `docs/GATE_LEDGER.md` (27 controls).

| Family | Control | Evidence |
|---|---|---|
| **AC-2/AC-3** Access enforcement | Deny-by-default RBAC; exploit reproduction operator-only even in public-demo mode; mutating run trigger always gated | Gate ledger 18; `tests/test_web_gating.py`; verified live (anonymous `/reports/*` → 403) |
| **AC-6** Least privilege | Each agent may append only its own ledger event types; the web service may append only auth events | Gate ledger 8, 28; `WriterNotAuthorized` |
| **AU-2/AU-3** Audit events | Append-only ledger of every attempt, verdict, cost, and break-glass access, incl. denials | Gate ledger 28; verified in production logs |
| **AU-9** Audit protection | Append-only by construction; PHI masked on write; token values never recorded | `stores/ledger.py`; `test_break_glass_use_is_recorded_in_the_ledger` |
| **CA-2/CA-8** Assessment & pen testing | 71 authenticated variants across 6 OWASP-dual-mapped categories; 3 fix-validated reports | `evals/authenticated/`; `reports/` |
| **CM-3** Change control | Blocking pre-push gate: ruff, mypy --strict, pytest, bandit, pip-audit | Gate ledger 1, watched red-then-green |
| **IA-2/IA-5** Identification & authentication | OIDC auth-code + PKCE, RS256 id_token verified against issuer JWKS (iss/aud/exp/nonce); opaque server-side sessions | `auth/`; `tests/test_sso.py` |
| **RA-5** Vulnerability monitoring | `pip-audit` in the blocking gate; simulated-scan triage discipline | `docs/SCAN_TRIAGE.md` |
| **SA-11** Developer testing | 134 hermetic tests; inner-loop self-test; Judge drift gate on frozen signed fixtures | Gate ledger 17; `evals/inner_loop.json` |
| **SC-8** Transmission | TLS to target, Bedrock, IdP; `Strict-Transport-Security` on the dashboard | `security_headers` middleware |
| **SC-18** Mobile code | Strict CSP: `default-src 'none'`, `frame-ancestors 'none'`; no CDN, no external script | `test_security_headers_are_set` |
| **SI-10** Input validation | Versioned JSON-Schema contracts rejecting unknown fields; path-traversal-safe report serving | Gate ledger 3, 4; `test_report_path_traversal_still_blocked` |
| **SI-11** Error handling | Catch-all handler; provider errors logged, never rendered | `test_unhandled_errors_do_not_leak_internals` |

**Assessment of the assessor.** Unusually for a packet like this, the tool's own accuracy is
measured rather than asserted: the deterministic rungs against exact ground truth
(`evals/inner_loop.json`), and the LLM rung against **human labels on a held-out set** — 0.917
agreement, 1.0 precision, with every disagreement published
(`evals/judge_calibration/`). A scanner whose error rate is unknown cannot support a control claim.

## 4. Residual risks accepted

| # | Risk | Why accepted | Trigger to revisit |
|---|---|---|---|
| R1 | **Concurrency/idempotency has zero live coverage.** Its only route is a chart write, which `--safe-live` refuses to fire at a live clinical system. | Covered against the ephemeral build with fix-validation. Not firing writes at a live clinical system is the correct trade. | A staging target that is safe to write to |
| R2 | **Cross-scope writes by an authorized key holder are not detectable.** Indistinguishable from a legitimate write in an HTTP response. | Stated boundary, not a silent gap (`THREAT_MODEL.md`). The platform asserts only the property it can prove: at most one success per record. | A patient-scope oracle from the target |
| R3 | **The newest surface is untested.** On-demand reconciliation returns 502 on every call — upstream not wired up. | Reported as `target-unavailable`, kept out of the defended count; the pass rate visibly drops to 87% rather than rounding up. | Upstream dependency restored |
| R4 | **Judge LLM rung has a named blind spot.** Accepts an "aggregate" over a cohort of size one (small-cell disclosure). | One case in 12, direction known, precision unaffected. Fix needs a fresh holdout to measure honestly. | Before relying on the rung for automated remediation |
| R5 | **Break-glass is a shared secret.** One token, no per-operator attribution. | Deliberate: the alternative is an ungated console when the IdP is down. Every use is audited, and clearing the variable revokes all sessions instantly. | Once OIDC login works end-to-end |
| R6 | **CI has never executed.** No runner is attached to the project. | Labelled as not a gate rather than counted as one; the pre-push hook is the enforced gate. | A runner attached |
| R7 | **In-process session store.** Sessions do not survive a redeploy and do not share across replicas. | Single replica; a redeploy forcing re-authentication is an acceptable failure mode. | Horizontal scale-out |

## 5. Recommendation

For its stated purpose — **authorized adversarial testing of a first-party application in an
isolated sandbox with synthetic data** — the controls are commensurate with the risk, and the
residual risks in §4 are named with triggers rather than discovered later.

The two things that would have to change before this operated against a system holding **real
patient data**: Langfuse moves self-hosted under the BAA (Cloud is acceptable for synthetic data
only), and R2/R4 close, because a platform whose blind spots are documented is fine for a sandbox
and not fine as the only thing standing between an EMR and a breach.
