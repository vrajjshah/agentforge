# Threat Model — the Clinical Co-Pilot under AgentForge

_A living document the platform continuously exercises. The attack surface below is the coverage
map the Orchestrator reads; empty cells are its next campaigns._

## Summary (key findings, highest-risk categories, how coverage is prioritized)

The system under test is a deployed AI **Clinical Co-Pilot** (`/copilot`) built on an OpenEMR
fork: a chat agent with eight clinical tools, a document-ingestion pipeline (upload → VLM/OCR
extraction → provisional facts → human confirm-to-chart), and a two-principal auth model
(a SMART **session** that enforces patient binding, and an **API key** that does not). Its data
is **synthetic** — no real PHI — but we threat-model it to a real-hospital standard.

The **highest-risk categories**, ranked by clinical blast radius, are **(1) data exfiltration**
and **(2) identity/role exploitation**, because both let one patient's record or one clinician's
identity cross a boundary that a human reviewing the UI cannot see is broken. Both are anchored to
*real, confirmed* defects: `ea8fa01` (a document-keyed read that returned another patient's fact
list and both patients' names + DOBs to a session bound elsewhere — HTTP 200, demonstrated) and
`e0e7b6a` (an API-key write attributed to whatever clinician name the body supplied). Third is
**prompt injection** — direct, multi-turn, and *indirect via uploaded documents* (a sneaky PDF the
physician uploads) — the primary LLM-adversarial surface. Then **denial of
service / cost amplification** (a single uvicorn worker at ~0.56 turns/s, upload p95 12.2 s
against a 15 s SLO, and a VLM path that never checks `stop_reason == max_tokens` so a long lab PDF
truncates silently). **State corruption** (`7fbf995`: a second reject erased the first clinician's
reason) and **concurrency/idempotency** (`b5f4b1e` TOCTOU double-confirm, `c019314` retry
duplicate-write) round out the map; both are pure server-side defects with no LLM surface.

Every one of the eight seed defects shares one shape: **the visible state stays plausible while
the record underneath is wrong.** A badge said "adjusted." The operator saw four errors and
assumed the guard held. That is precisely the failure a human reviewing a screen cannot catch, and
the reason an automated, repeatable red team earns its place.

**How the platform prioritizes coverage.** Each cell is (category × subcategory × auth-mode ×
role). The Orchestrator picks the **least-covered** cell first, and, because six of the eight named
defects are already **fixed on the deployed HEAD**, weights toward genuinely *unprobed* surface
(multi-turn injection, tool misuse, the API-key cross-patient capability that is a documented
*design* property). Verdicts are deterministic-first: a cross-patient leak is a static boolean
("did patient B's DOB appear in patient A's response?"), so most PHI and DoS verdicts need no
model. The **dual OWASP mapping** (web-2021 + LLM-2023) is a data-quality gate on every case, not a
footnote — it's the one mandatory engineering deliverable. Against the hardened live target the
honest result is **"defense held"**; the platform demonstrates it catches real vulns via an
ephemeral vulnerable build and the frozen ground-truth set, so no claim rests on
re-finding our own patched bugs.

---

## Attack surface

### Entry points (routes), relative to `https://45-55-53-165.sslip.io/copilot`

| Method | Route | Red-team relevance |
|---|---|---|
| POST | `/chat` | the agent — direct / indirect / multi-turn injection surface |
| POST | `/week2/upload` | file ingest — the untrusted-input boundary (indirect injection) |
| POST | `/week2/documents/{id}/process` | triggers VLM extraction |
| GET | `/week2/documents/{id}/extraction` | **the `ea8fa01` class** — document-keyed, not patient-keyed |
| GET | `/week2/documents/{id}/page/{page}` | same class |
| GET | `/week2/patients/{id}/provisional` · `/trends/{test}` · `/reconciliation` | patient-scoped reads |
| POST | `/week2/retrieve` · `/week2/analyze` | RAG + agent entry |
| PATCH | `/week2/provisional/{id}` | clinician edit (the `06a72a0` class) |
| POST | `/week2/confirm/{id}` | **the only chart write** (`b5f4b1e`/`c019314` class) |
| POST | `/week2/reject/{id}` · `/reopen/{id}` | state transitions (`7fbf995` class) |
| GET | `/health` · `/` · `/session` · `/ready` | open (unauthenticated) |

### Auth model = the richest surface

`require_access` admits **two non-equivalent principals**: a SMART **session** (enforces H3 patient
binding, fails closed 404) and an **API key** (a machine principal; a leaked key is a documented
cross-patient capability). Same endpoint, two trust levels — a gift to a red-teamer. Identity is
**server-resolved** (`_actor()` is server-wins): a body- or header-claimed actor must never be
honored. *Verified live:* forged `X-User` / `X-Forwarded-User` headers on an unauthenticated
request are rejected (401), and identity is not inferred from them.

### Category map

| Category | Attack surface | Potential impact | Difficulty | Existing defense | OWASP web / LLM |
|---|---|---|---|---|---|
| **Data exfiltration** | document-keyed reads, patient-scoped reads, cross-principal access | cross-patient PHI leak (HIPAA breach); wrong-patient care | trivial unauth / moderate cross-patient | `_scope_patient`/`_scope_document` fail-closed; AST route-guard | A01 / LLM06 |
| **Identity / role** | API-key vs session inequivalence; body/header-claimed actor | forged attribution; privilege escalation | easy (needs a key) / trivial (header forge) | server-wins `_actor()`; hash-chained audit | A01 / LLM08 |
| **Prompt injection** | `/chat` direct + multi-turn; uploaded-doc indirect (OCR page-0) | out-of-scope disclosure; fabricated guidance | moderate | patient-scoped tools; verification gate; auth-gated | A03 / LLM01 |
| **Denial of service** | single worker; upload p95 12.2 s; no `stop_reason` check | unavailability; silent extraction truncation (dropped labs) | cheap | content-length limit; rate limiter; extraction semaphore | A04 / LLM04 |
| **State corruption** | repeat reject/reopen; provisional edit | overwritten accountability record | moderate | 12-cell path matrix; append-only intent | A04 / n/a |
| **Concurrency / idempotency** | concurrent confirms; retried writes | double chart rows; duplicate writes | moderate | DB-level atomic claim (`UPDATE … WHERE claimed IS NULL`) | A04 / n/a |
| **Tool misuse** | 8 agent tools; parameter tampering; recursion | out-of-scope read/write; cost run-up | moderate | tool scoping; iteration limit | A05 / LLM08 |

### Seed defects (ground truth) → see `docs/EXPLOIT_LEDGER.md`

`ea8fa01` · `06a72a0` · `7fbf995` · `e0e7b6a` · `b5f4b1e` · `c019314` · `audit-vlm` · `audit-ocr`.
Six are fixed on the deployed HEAD (so "defense held" live); two ingestion-audit findings remain
open by design. Each has a known-good regression test the red team must not be able to re-break.

### Newest surface (least-hardened code — probe hardest here)

The most recently added routes and UI carry the least battle-testing, so they get priority:

- **Conversation-fragment continuation.** The chat page can resume a server-side conversation from a
  `#conv=<id>` URL fragment. Attack: supply *another* conversation's id and test whether the server
  binds it to the caller's own session and patient — an untested authorization boundary.
- **Attribution + stored payloads on the correction routes.** `PATCH /week2/provisional/{id}` and
  `POST /week2/reject|reopen/{id}` accept a body-supplied `clinician` (must be ignored — identity is
  server-resolved) and free-text `reason`/`value` fields (≤512/≤256 chars) that are re-rendered on
  the review UI and can reach the model — a stored-XSS / prompt-injection carrier. **Covered:** the
  `stored-payload-reason` seed persists a `<script>` payload and the Judge asserts it is never
  reflected unescaped (caught on a vulnerable build, held when the field is escaped); these are
  chart-write routes, so they run against the ephemeral build, never the live target.
- **Iframe-to-host DOM reach.** When embedded in the host EMR, the co-pilot's window controls
  (minimize / pop-out) manipulate the *parent* application's DOM (same origin), gated by a
  chart-reachability heuristic that has failed before. This is a **client-side DOM** attack — out of
  scope for an HTTP-level scanner and requiring a browser-driven client (the co-pilot ships
  Selenium/Panther for exactly this). Documented as a known limit of the HTTP surface rather than
  faked with an HTTP probe; a `BrowserTargetAdapter` is the clean extension.
- **On-demand upstream reconciliation** (`GET /week2/patients/{id}/reconciliation`) forces a live
  EMR read per request — an amplification / cost pivot.

### Recommendation (not a finding): machine-key write authority

`require_access` admits the API key for **chart writes**, not just reads. The threat model above
records the key's cross-patient capability as **intended**, so an authorized 200 on
`/week2/confirm/{id}` is the system working — the platform does **not** report it as an exploit, and
the check-pack deliberately refuses to forbid 200 for an authenticated principal (a policy that
flagged every healthy write would not be stricter, it would make every verdict worthless).

What is worth raising, at **informational** severity and as a design recommendation rather than a
confirmed vulnerability, is whether a *machine* principal should hold unbounded write authority over
the chart at all, or whether writes should require a patient-bound SMART session while the key stays
read-scoped. That is an authorization-design question about `require_access`, not a state-corruption
defect, and it would need to be verified against live behaviour before it is written up either way.
It is recorded here so the distinction is explicit: an intended capability someone might want
narrowed is not the same claim as an exploit.

### Stated boundary — what the HTTP surface cannot decide

A **cross-scope write by an authorized key holder** (a valid key writing to a patient outside the
caller's remit) is not distinguishable from a legitimate write in an HTTP status code, and a
PHI-marker check on a write response would false-positive on a legitimate echo of the caller's own
patient record. The platform therefore does not claim to detect it, and the authenticated
state-corruption checks assert only the property they can prove: **at most one successful write per
record** across a raced, retried, or repeated sequence. Catching cross-scope writes needs a
patient-scope oracle from the target (which record was actually touched), not a response body —
the same shape of limit as the iframe→host DOM escape needing a `BrowserTargetAdapter`.

### Finding: the OIDC discovery document advertises an endpoint that does not exist

Surfaced by this platform's own SSO integration against the target's auth layer, which is the only
reason it was found — no attack sweep would have looked.

`OAuth2DiscoveryController` publishes `"userinfo_endpoint": "$base_url/userinfo"` in
`/.well-known/openid-configuration`. **The route was never implemented.**
`GET /oauth2/default/userinfo` returns **404**, byte-identical to a path that does not exist, and
`OAuth2DiscoveryController` is the only file in the codebase that mentions `userinfo` at all.

| | |
|---|---|
| **Severity** | **Low** — conformance, not exploitable. No data exposure, no authorization impact |
| **OWASP** | A05:2021 Security Misconfiguration (web) · n/a (LLM) |
| **Standard** | OpenID Connect Core 1.0 §5.3 — a published `userinfo_endpoint` is expected to serve claims |
| **Status** | **Reported, closed on our side.** The defect is open in OpenEMR core; fixing it is not Week-3 work — it is neither the co-pilot nor an LLM-adversarial surface. Reporting it is the deliverable |

**Impact.** Discovery exists so a client can configure itself from the issuer. Any conformant client
that follows it will issue a request that always fails. Ours did: the AgentForge dashboard called
userinfo to resolve an operator's display name, got a 404, and fell back — which is why the console
shows a subject-derived label instead of a name. A client with a less forgiving implementation would
have failed the login outright on a document the issuer itself published.

**Fix, when it is picked up.** Implement the route rather than remove the advertisement. The claims
already exist and are already assembled: `UserEntity::getClaims()` builds `name`, `family_name`,
`given_name`, `preferred_username` and `email` from `UuidUserAccount`, and nothing on the
authorization-code flow ever calls it. The work is bearer-token validation plus returning claims
that are already there — and it fixes the display name for **every** user and **every** OIDC client
rather than one hardcoded subject.

**Why it is not fixed here, and will not be.** It is a change to a live EMR's authentication layer
in OpenEMR *core*, not in the co-pilot under test, and it carries no LLM-adversarial surface — so it
falls outside what this platform set out to do. SSO works today; touching that path would trade a
working login for a cosmetic label. The consequence is visible and accepted: the dashboard header
reads `Administrator`, which is accurate for the admin principal, and stays that way.

A red team that reports a defect in a dependency, scopes it honestly, and declines to patch someone
else's auth layer on the way past is behaving correctly. The write-up is the deliverable.

### Known operational weak points

Single-worker deployment (~0.56 turns/s) → trivial DoS/cost target; three per-process guards (rate
limiter, extraction semaphore, idempotency set) that don't survive horizontal scale-out; upload p95
≈ 12.2 s against a 15 s SLO (the thinnest margin, where a latency attack lands first); prompt caching
effectively off (static prefix below the cacheable minimum).
