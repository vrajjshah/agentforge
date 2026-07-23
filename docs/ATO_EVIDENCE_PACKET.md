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
database, the eval datasets and generated reports, and the read-only dashboard, deployed at
`agentforge-web-production-c891.up.railway.app` (**still live as of 2026-07-23**; it serves
committed run artefacts rather than querying the target, so it outlived the target's teardown, and
`uv run agentforge dashboard` builds the same page locally). The authorization boundary described
below was assessed against that deployment and **is still the one in force there** — verified
2026-07-23: anonymous `/api/dashboard` returns `detail_gated: true` with an empty `findings` array
and a stated refusal, and `/reports/<id>.md` returns 403 (ledger control 18).

**Outside, but connected:**

| External system | Direction | What crosses | Control |
|---|---|---|---|
| Clinical Co-Pilot (target) | outbound HTTP | attack requests, responses | Immutable origin allow-list — the platform can attack nothing else (`AllowListViolation`) |
| AWS Bedrock | outbound HTTPS | attack payloads, delimited response evidence | One AWS BAA, `us-east-1`, bearer-token auth |
| OpenEMR authorization server | outbound HTTPS | OIDC code exchange, JWKS | Endpoints derived from the configured issuer, never a caller-supplied value |
| Langfuse Cloud | outbound HTTPS | trace metadata | PHI-masked before send; no-op without keys |
| GitLab CI runner (id 192, on the target's droplet) | inbound: executes repository code | the branch under test | Docker executor, `privileged = false`, **no Docker socket mounted**, `volumes = ["/cache"]` only, runner locked to this project |

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
(`evals/inner_loop.json`), and the LLM rung against **human labels on held-out sets** — currently
**0.833 agreement, 1.0 precision**, with every disagreement published (`evals/judge_calibration/`).

Two caveats are published with it rather than omitted, because a control claim resting on an
unqualified number is the thing this packet exists to prevent: the most recent rubric clause
**did not work** (same score with and without it), and the measurement carries **run-to-run
variance of about two cases on a twelve-case set** — the same magnitude as the differences earlier
figures were used to claim. The figures are approximate and are labelled as such on the dashboard.
A scanner whose error rate is unknown cannot support a control claim; one whose error rate is known
*and noisy* supports a correspondingly narrower one.

## 4. Residual risks accepted

| # | Risk | Why accepted | Trigger to revisit |
|---|---|---|---|
| R1 | **Concurrency/idempotency has zero live coverage.** Its only route is a chart write, which `--safe-live` refuses to fire at a live clinical system. | Covered against the ephemeral build with fix-validation. Not firing writes at a live clinical system is the correct trade. | A staging target that is safe to write to |
| R2 | **Cross-scope writes by an authorized key holder are not detectable.** Indistinguishable from a legitimate write in an HTTP response. | Stated boundary, not a silent gap (`THREAT_MODEL.md`). The platform asserts only the property it can prove: at most one success per record. | A patient-scope oracle from the target |
| R3 | ~~The newest surface is untested~~ — **closed**. Reconciliation answered 502 to every id the sweep tried. Diagnosed, fixed (`fix/reconciliation-502`), re-validated live. | The platform mis-attributed the cause (reported an unavailable upstream; the upstream was healthy and the 502s came from non-resolving ids). Verdict rule renamed to `no-usable-response` so it states what was observed, not a guess at why. | Re-opens if 5xx returns on that route |
| R4 | **Judge LLM rung has a named blind spot** (disclosure by negation) **and a measured noise floor** of ~2 cases on a 12-case set. | Direction is known and precision is unaffected across all four runs. A clause targeting it was tried and produced no measurable improvement, so it is labelled unproven rather than claimed. | Before relying on the rung for automated remediation. Order: repeat runs + published spread, then a larger set, then a new holdout |
| R5 | **Break-glass is a shared secret.** One token, no per-operator attribution. | Deliberate: the alternative is an ungated console when the IdP is down. Every use is audited, and clearing the variable revokes all sessions instantly. | Once OIDC login works end-to-end |
| R6 | **CI has never executed.** No runner is attached to the project. | Labelled as not a gate rather than counted as one; the pre-push hook is the enforced gate. | A runner attached |
| R7 | **The CI runner shares a host with the live target.** A self-hosted runner executes whatever code is in a branch, on the droplet that serves the demo. | Deliberate: "runs on every PR" cannot depend on a laptop being open, and this is the only always-on host available. Bounded by a non-privileged Docker executor with **no Docker socket mounted** (a socket mount would hand any CI job root-equivalent control of that host — a real exposure found and removed on the sibling runner), `concurrent = 1` so CI cannot starve the demo, and the runner locked to this project. Push access is the trust boundary. | A shared or public fork gaining push access; or any job needing Docker, which would reintroduce the socket question |
| R8 | **In-process session store.** Sessions do not survive a redeploy and do not share across replicas. | Single replica; a redeploy forcing re-authentication is an acceptable failure mode. | Horizontal scale-out |

## 5. Recommendation

For its stated purpose — **authorized adversarial testing of a first-party application in an
isolated sandbox with synthetic data** — the controls are commensurate with the risk, and the
residual risks in §4 are named with triggers rather than discovered later.

The two things that would have to change before this operated against a system holding **real
patient data**: Langfuse moves self-hosted under the BAA (Cloud is acceptable for synthetic data
only), and R2/R4 close, because a platform whose blind spots are documented is fine for a sandbox
and not fine as the only thing standing between an EMR and a breach.
