# Triage of a simulated scanner run — 14 findings

> **This scan is simulated.** No commercial scanner was run against the Clinical Co-Pilot. The
> findings below are the ones a generic SAST/DAST pass over a FastAPI + LLM application of this
> shape typically produces, written out so the *triage* is the real artifact: what a security
> engineer does with a wall of scanner output, and how much of it survives contact with the actual
> system. Every disposition is justified against a specific file, route, or committed evidence in
> this repository, so the reasoning is checkable even though the scan is not.

Raw findings: **14**. After triage: **2 real and actionable**, 3 accepted risks with a stated
rationale, 4 false positives, 5 not applicable to this deployment. That ratio — roughly one in
seven worth acting on — is the normal case, and it is the reason the triage matters more than the
scan.

## Disposition summary

| Disposition | Count | Meaning |
|---|---|---|
| **Real — act** | 2 | Genuine, in scope, worth fixing |
| **Accepted risk** | 3 | Genuine, understood, deliberately not fixed now, with a stated reason |
| **False positive** | 4 | Scanner is wrong about the code |
| **Not applicable** | 5 | Correct about a pattern, wrong about this system |

## The findings

| # | Scanner finding | Sev (scanner) | Disposition | Reasoning |
|---|---|---|---|---|
| 1 | Hardcoded password string in `web.py` (B105) | Medium | **False positive** | The flagged constant was `_TOKEN_LOGIN_PAGE`, an HTML template whose *name* contained "TOKEN". Fixed by renaming to `_BREAK_GLASS_PAGE` rather than suppressing — a `nosec` here would have trained us to ignore the next real B105. |
| 2 | Hardcoded secrets in `auth/oidc.py` (B105 ×6) | Medium | **False positive** | OAuth grant-type and parameter *names* (`client_secret`, `authorization_code`). Already carry targeted `# nosec B105` with justification. |
| 3 | Missing rate limiting on `POST /api/run/{category}` | High | **Not applicable** | The route does not execute anything; it validates authorization and returns an instruction to run the CLI. It is also SSO+RBAC gated, so an unauthenticated caller cannot reach the body at all. |
| 4 | No CSRF token on `POST /login/token` | High | **Accepted risk** | The endpoint takes a bearer-equivalent secret in the body, so a cross-site POST cannot forge one without already knowing the token. The session cookie is `SameSite=Lax`, which blocks the cross-site form POST anyway. Revisit if the form ever accepts anything other than the token. |
| 5 | Session fixation — session id not rotated on privilege change | High | **Not applicable** | There is no privilege change to rotate across. Sessions are minted fresh at login (`secrets.token_urlsafe(32)`) and are opaque indexes into a server-side store; there is no unauthenticated session to fixate. |
| 6 | User-controlled path in file read (`/reports/{name}`) — path traversal | **Critical** | **False positive** | `Path(name).name` reduces to a basename before the join, the suffix must be `.md`, and the traversal case is a committed regression test (`test_report_path_traversal_still_blocked`). |
| 7 | Reflected user input rendered without escaping (`/callback` error page) | High | **False positive** | The provider's `error` parameter passes through `html.escape` before rendering, and the identity provider's internal error text is never rendered at all — it goes to the log. |
| 8 | Sensitive data in URL query string (OAuth `code`) | Medium | **Accepted risk** | Inherent to OAuth authorization-code flow; mitigated the way the spec intends — the code is single-use, short-lived, PKCE-bound, and bound to a double-submit `state` cookie. The alternative (form-post response mode) is not offered by this OpenEMR issuer. |
| 9 | SQL string construction in `stores/ledger.py` | High | **False positive** | The only interpolated fragments are internally-generated `WHERE` clause names; every value is bound as a `?` parameter. No caller-controlled string reaches the SQL text. |
| 10 | Dependency `langfuse` pinned below latest major | Low | **Accepted risk** | Pinned `>=3,<4` deliberately: v4 removed `start_as_current_span`, which the tracing facade uses. `pip-audit` reports no known vulnerability in the pinned range, so this is a compatibility pin, not a security debt. |
| 11 | Missing security headers (CSP, X-Frame-Options, HSTS) | Medium | **Real — act** | Genuine and cheap. The dashboard is self-contained with no external assets, so a strict CSP costs nothing and closes clickjacking and injected-script classes outright. **Action: add a CSP + frame-ancestors + nosniff header middleware.** |
| 12 | Verbose error disclosure on 5xx | Medium | **Real — act** | Partly addressed — `/callback` failures now render a clean notice and keep the provider's error server-side. But an unhandled exception anywhere else still returns FastAPI's default 500 body. **Action: add a catch-all exception handler that logs the detail and returns a generic page.** |
| 13 | Unauthenticated information disclosure on `/api/target` | Medium | **Accepted risk** | Returns the target URL, health, and content fingerprint. The target URL is already published in the README as a submission artifact, and the fingerprint is derived from public response content. Deliberately public so a reviewer can confirm what was tested. |
| 14 | No account lockout / brute-force protection on `/login/token` | High | **Not applicable** *(with a caveat)* | There is no account to lock — one shared token of 54 random URL-safe characters. Guessing is not a realistic attack against that keyspace, and every attempt is recorded in the append-only ledger, so a burst is visible. **Caveat:** if the token were ever shortened or made human-chosen, this flips to Real immediately. |

## What this exercise is for

Two of fourteen. The other twelve are not the scanner malfunctioning — they are a scanner doing its
job, which is to flag patterns without knowing the system. Deciding which is which needs the threat
model, the deployment's actual auth model, and the code, and it is the part that does not automate.

The same discipline governs this platform's own output, which is why it reports
`blocked-live-safety`, `target-unavailable`, and `inconclusive` as distinct from `defended`: a
finding you cannot justify is noise, and a pass you cannot justify is worse.

## Actions taken

Findings 11 and 12 are tracked as follow-up work. The rest are recorded here with their reasoning
so the next person does not re-triage them from scratch — and so that if one of the "accepted"
rationales stops holding (see the caveat on 14), the change is visible.
