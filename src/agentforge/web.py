"""AgentForge web service — the deployed observability dashboard (a submission artifact).

One self-contained page answering the six observability questions — categories tested + counts,
pass/fail rate, resilience over target versions, open/in-progress/resolved findings, run cost, and
recent agent activity — plus a testing-the-tester self-test and a cost-at-scale projection. Data
comes from a committed ``evals/dashboard.json`` (rebuilt by ``agentforge dashboard``), so the page
needs no database and makes no live calls to render. All CSS/JS is inlined — a security dashboard
must not phone out to a third-party CDN, and findings data must not leave the platform.
"""

from __future__ import annotations

import html
import json
import logging
import os
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from agentforge.adapters.copilot import CopilotAdapter
from agentforge.auth.config import SsoConfig
from agentforge.auth.oidc import OidcClient, OidcError, claims_to_session
from agentforge.auth.pkce import pkce_pair
from agentforge.auth.rbac import is_authorized
from agentforge.auth.session import AuthFlow, AuthFlowStore, OperatorSession, SessionStore
from agentforge.config import Settings
from agentforge.stores.ledger import EventLedger, EventType

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EVALS = Path(os.environ.get("AGENTFORGE_EVALS_DIR", str(_REPO_ROOT / "evals")))
_REPORTS = Path(os.environ.get("AGENTFORGE_REPORTS_DIR", str(_REPO_ROOT / "reports")))
_log = logging.getLogger("agentforge.web")

app = FastAPI(title="AgentForge", description="Adversarial AI security platform")
_settings = Settings.from_env()

# --- SSO (Login with OpenEMR) ---------------------------------------------------------------
_sso = SsoConfig.from_env()
_oidc = OidcClient(_sso)
_sessions = SessionStore()
_flows = AuthFlowStore()
_SESSION_COOKIE = "af_session"
_STATE_COOKIE = "af_oauth_state"
_BREAK_GLASS_SUB = "break-glass"


def _current_operator(request: Request) -> OperatorSession | None:
    sid = request.cookies.get(_SESSION_COOKIE)
    return _sessions.get(sid) if sid else None


def _break_glass_enabled() -> bool:
    return bool(os.environ.get("AGENTFORGE_ADMIN_TOKEN"))


def _admin_token_ok(supplied: str | None) -> bool:
    """Break-glass principal: a shared operator token, constant-time compared. Disabled unless
    ``AGENTFORGE_ADMIN_TOKEN`` is set, so it is never an accidental open door."""
    admin = os.environ.get("AGENTFORGE_ADMIN_TOKEN", "")
    return bool(admin and supplied and secrets.compare_digest(supplied, admin))


async def _urlencoded_form(request: Request, max_bytes: int = 4096) -> dict[str, str]:
    """Parse a small ``application/x-www-form-urlencoded`` body, size-capped.

    Hand-parsed rather than via ``request.form()`` so the service takes no multipart-parser
    dependency for one login form — less code reachable from an unauthenticated route.
    """
    body = (await request.body())[:max_bytes]
    return {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace")).items() if v}


def _authorized(operator: OperatorSession | None) -> bool:
    """Deny-by-default authorization for a held session. A break-glass session carries no OIDC
    claims to match, so its authority is the continued presence of the token that minted it —
    clearing ``AGENTFORGE_ADMIN_TOKEN`` revokes every break-glass session immediately."""
    if operator is None:
        return False
    if operator.subject == _BREAK_GLASS_SUB:
        return _break_glass_enabled()
    return is_authorized(operator, _sso)


def _may_view_detail(request: Request,
                     x_admin_token: str | None = None) -> bool:
    """Deny-by-default gate for *exploit detail* — reports, finding titles, attack sequences.

    Aggregate posture (pass rate, per-category counts, "defense held") stays public so a reviewer
    can assess the platform; the reproduction steps do not. RBAC is re-evaluated on every request
    rather than trusted from login time, so revoking an operator takes effect immediately.
    """
    if _authorized(_current_operator(request)):
        return True
    return _admin_token_ok(x_admin_token or request.headers.get("x-admin-token"))


def _audit_auth(action: str, outcome: str, request: Request, **extra: Any) -> None:
    """Record a break-glass access on the append-only ledger *and* the service log.

    A shared-token bypass is only defensible if every reach for it is on the record, including the
    failures — an unexplained run of ``denied`` is the signal that someone is guessing. Two sinks
    on purpose: the ledger is the in-platform audit trail with the least-privilege writer, and
    stdout is what survives a container redeploy on an ephemeral filesystem.

    Never fatal. An audit sink that can take the login down with it would be a worse bug than the
    one it is guarding, so a failed append degrades to a logged warning.
    """
    ua = (request.headers.get("user-agent") or "")[:120]
    client = request.client.host if request.client else "unknown"
    _log.warning("auth: %s %s client=%s ua=%r %s", action, outcome, client, ua, extra or "")
    try:
        ledger = EventLedger(_settings.data_dir / "ledger.db")
        try:
            ledger.append(agent="web", event_type=EventType.AUTH_ACCESS, run_id="web-auth",
                          payload={"action": action, "outcome": outcome, "client": client,
                                   "user_agent": ua, **extra})
        finally:
            ledger.close()
    except Exception as exc:  # pragma: no cover - audit must never break the request path
        _log.warning("auth: ledger append failed (%s): %s", type(exc).__name__, exc)


def _safe_return_to(raw: str | None) -> str:
    """Only allow same-site relative paths as post-login redirects (no open redirect)."""
    if raw and raw.startswith("/") and not raw.startswith("//"):
        return raw
    return "/"


def _dashboard_data() -> dict[str, Any]:
    path = _EVALS / "dashboard.json"
    return json.loads(path.read_text()) if path.exists() else {}


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "info"))
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _sanitized(d: dict[str, Any]) -> dict[str, Any]:
    """The anonymous projection: posture without reproduction.

    Everything that describes *how* to exploit the target — finding titles (which name the
    technique), report filenames, and the OWASP-mapped attack chains behind them — is dropped and
    replaced with counts. A security platform that publishes working exploit steps to the open
    internet is the anti-pattern it exists to flag, so the public view is counts-only by default.
    """
    findings = d.get("findings", [])
    public = {k: v for k, v in d.items() if k != "findings"}
    public["findings"] = []
    public["detail_gated"] = True
    public["findings_public"] = {
        "total": len(findings),
        "by_severity": _severity_counts(findings),
        "note": "Finding detail (technique, attack sequence, reproduction) requires an "
                "authenticated, authorized security operator.",
    }
    return public


@app.middleware("http")
async def security_headers(request: Request, call_next: Any) -> Response:
    """Headers the dashboard can afford to set at maximum strictness.

    The page is self-contained by design — no CDN, no external fonts, no third-party scripts — so
    a CSP that forbids every remote origin costs nothing here and closes injected-script and
    clickjacking classes outright. ``frame-ancestors 'none'`` matters more than usual: the target
    under test is an EMR that embeds itself in an iframe, and a security console that can be framed
    is a console that can be clickjacked into triggering a run.
    """
    response: Response = await call_next(request)
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.scheme == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception) -> Response:
    """Never hand a reviewer a stack trace or a framework default 500.

    The detail is logged with the traceback and the response says only that something failed —
    an error body is an information-disclosure surface, and this service's errors can name
    internal paths, the identity provider, and the target.
    """
    _log.exception("unhandled error on %s %s", request.method, request.url.path)
    return HTMLResponse(_auth_notice(
        "Something went wrong handling that request. It has been logged.",
        title="Something went wrong",
        actions="<a class='btn' href='/'>Back to the dashboard</a>"), status_code=500)


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"service": "agentforge", "status": "ok"})


@app.get("/api/dashboard")
async def api_dashboard(request: Request) -> JSONResponse:
    data = _dashboard_data()
    return JSONResponse(data if _may_view_detail(request) else _sanitized(data))


@app.get("/api/coverage")
async def coverage() -> JSONResponse:
    return JSONResponse(_dashboard_data().get("coverage", {}))


@app.get("/api/target")
async def target() -> JSONResponse:
    adapter = CopilotAdapter(_settings)
    ok, detail = await adapter.health()
    version = await adapter.version() if ok else "unreachable"
    return JSONResponse({"target_url": _settings.target_url, "healthy": ok,
                         "detail": detail, "fingerprint": version})


@app.post("/api/run/{category}")
async def run(category: str, request: Request,
              x_admin_token: str | None = Header(default=None)) -> JSONResponse:
    """The attack trigger — a mutating action, so it is always gated. When SSO is configured it
    requires an authenticated, authorized operator (SSO+RBAC); otherwise it falls back to the
    admin-token header. Either way it is never open."""
    operator = _current_operator(request)
    if operator is not None:
        if not _authorized(operator):
            raise HTTPException(status_code=403, detail="not an authorized security-operator")
        return JSONResponse({"accepted": category, "operator": operator.name,
                             "note": "run via CLI; results land in ./evals/"})
    if _sso.enabled and not _break_glass_enabled():
        raise HTTPException(status_code=401, detail="login required (Log in with OpenEMR)")
    admin = os.environ.get("AGENTFORGE_ADMIN_TOKEN", "")
    if not admin:
        raise HTTPException(status_code=403, detail="run trigger disabled (no admin token / no SSO)")
    if not (x_admin_token and secrets.compare_digest(x_admin_token, admin)):
        raise HTTPException(status_code=401, detail="invalid admin token")
    return JSONResponse({"accepted": category, "note": "run via CLI; results land in ./evals/"})


# --- SSO routes: Login with OpenEMR (authorization-code + PKCE + JWKS-verified id_token) -----
@app.get("/login")
async def login(request: Request) -> Response:
    if not _sso.enabled:
        raise HTTPException(status_code=503, detail="SSO not configured")
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)
    _flows.set(state, AuthFlow(code_verifier=verifier, nonce=nonce,
                               redirect_uri=_sso.redirect_uri,
                               return_to=_safe_return_to(request.query_params.get("return_to"))))
    resp = RedirectResponse(_oidc.authorize_redirect(state, challenge, nonce), status_code=302)
    # Double-submit state cookie binds the callback to this browser (login-CSRF defense).
    resp.set_cookie(_STATE_COOKIE, state, max_age=600, httponly=True,
                    secure=_sso.cookie_secure, samesite="lax", path="/")
    return resp


@app.get("/callback")
async def callback(request: Request) -> Response:
    if not _sso.enabled:
        raise HTTPException(status_code=503, detail="SSO not configured")
    if err := request.query_params.get("error"):
        _audit_auth("sso_callback", "idp_error", request, error=str(err)[:120])
        return HTMLResponse(_sso_unavailable(f"OpenEMR returned: {html.escape(err)}"),
                            status_code=400)
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    if not code or not state or state != request.cookies.get(_STATE_COOKIE):
        _log.warning("SSO callback: state check failed (query vs cookie mismatch or missing)")
        return HTMLResponse(_auth_notice(
            "<b>That sign-in link has expired.</b><br><br>Start again from the dashboard — the "
            "one-time login state is single-use, so a refreshed or bookmarked callback URL will "
            "always land here.", title="Sign-in expired", actions=_signin_actions()),
            status_code=400)
    flow = _flows.pop(state)  # single-use — replay refused
    if flow is None:
        _log.warning("SSO callback: no live auth-flow for state (expired or replayed)")
        return HTMLResponse(_auth_notice(
            "<b>That sign-in link has expired.</b><br><br>Start again from the dashboard.",
            title="Sign-in expired", actions=_signin_actions()), status_code=400)
    try:
        tokens = await _oidc.exchange_code(code, flow.code_verifier, flow.redirect_uri)
        claims = _oidc.verify_id_token(tokens["id_token"], flow.nonce)
    except OidcError as exc:
        # The specific reason is logged server-side and never shown to the browser — it describes
        # the identity provider's internals. A token-exchange failure here usually means the
        # OpenEMR OAuth client has not been enabled by an admin yet.
        _log.warning("SSO callback: OIDC failure: %s", exc)
        _audit_auth("sso_callback", "oidc_failure", request, reason=str(exc)[:300])
        return HTMLResponse(_sso_unavailable(), status_code=400)
    operator = claims_to_session(claims)
    if not is_authorized(operator, _sso):
        _audit_auth("sso_callback", "rbac_denied", request, subject=operator.subject[:40])
        return HTMLResponse(_auth_notice(
            f"<b>Signed in as {html.escape(operator.name)}, but not authorized here.</b><br><br>"
            "This platform admits only accounts on its security-operator allow-list. Access is "
            "deny-by-default, so an unconfigured allow-list refuses everyone — including the "
            "right person.", title="Not an authorized operator", actions=_signin_actions()),
            status_code=403)
    sid = secrets.token_urlsafe(32)
    _sessions.set(sid, operator)
    resp = RedirectResponse(flow.return_to, status_code=302)
    resp.set_cookie(_SESSION_COOKIE, sid, max_age=28800, httponly=True,
                    secure=_sso.cookie_secure, samesite="lax", path="/")
    resp.delete_cookie(_STATE_COOKIE, path="/")
    return resp


@app.get("/login/token", response_class=HTMLResponse)
async def login_token_form(request: Request) -> Response:
    """Break-glass operator login — a shared token, for when the OpenEMR IdP is unavailable.

    OIDC is the primary path; this exists so the platform is never *ungated* just because the
    identity provider is down (the failure mode that tempts an operator to turn the gate off).
    Disabled unless ``AGENTFORGE_ADMIN_TOKEN`` is set. POST-only submission — a token must never
    ride in a URL, where it would land in proxy and browser-history logs.
    """
    if not _break_glass_enabled():
        raise HTTPException(status_code=404, detail="break-glass login not enabled")
    _audit_auth("break_glass_form", "served", request)
    return HTMLResponse(
        _BREAK_GLASS_PAGE
        .replace("__SSO__", _SSO_BLOCK if _sso.enabled else "")
        .replace("__RETURN__",
                 html.escape(_safe_return_to(request.query_params.get("return_to")))))


@app.post("/login/token")
async def login_token(request: Request) -> Response:
    if not _break_glass_enabled():
        raise HTTPException(status_code=404, detail="break-glass login not enabled")
    form = await _urlencoded_form(request)
    if not _admin_token_ok(form.get("token")):
        _audit_auth("break_glass_login", "denied", request)
        return HTMLResponse(_auth_notice(
            "<b>That operator token was not accepted.</b><br><br>Check for a stray space or a "
            "truncated paste. This attempt has been recorded in the platform's audit ledger."
        ), status_code=401)
    sid = secrets.token_urlsafe(32)
    _sessions.set(sid, OperatorSession(subject=_BREAK_GLASS_SUB, name="break-glass operator",
                                       email=None, fhir_user=None, roles=("security-operator",)))
    _audit_auth("break_glass_login", "granted", request, session_prefix=sid[:8])
    resp = RedirectResponse(_safe_return_to(form.get("return_to")), status_code=302)
    resp.set_cookie(_SESSION_COOKIE, sid, max_age=28800, httponly=True,
                    secure=_sso.cookie_secure, samesite="lax", path="/")
    return resp


@app.get("/logout")
async def logout(request: Request) -> Response:
    sid = request.cookies.get(_SESSION_COOKIE)
    if sid:
        _sessions.delete(sid)
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie(_SESSION_COOKIE, path="/")
    return resp


@app.get("/reports/{name}", response_class=HTMLResponse)
async def report(name: str, request: Request) -> HTMLResponse:
    """Serve a generated vulnerability report — the full reproduction steps.

    Always gated, including in public-demo mode: this is a working exploit recipe against a live
    healthcare system, so it is operator-only regardless of ``AGENTFORGE_SSO_REQUIRE``.
    Path-traversal-safe (basename only, ``.md`` only).
    """
    if not _may_view_detail(request):
        return HTMLResponse(_auth_notice(
            "This vulnerability report contains a working reproduction sequence against a live "
            "clinical system. It is restricted to authenticated, authorized security operators. "
            "<a href='/login'>Log in with OpenEMR</a> to view it."), status_code=403)
    safe = Path(name).name
    path = _REPORTS / safe
    if not safe.endswith(".md") or not path.exists():
        raise HTTPException(status_code=404, detail="report not found")
    return HTMLResponse(_REPORT_PAGE.replace("__NAME__", html.escape(safe))
                        .replace("__BODY__", html.escape(path.read_text())))


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> Response:
    operator = _current_operator(request)
    # Read-view enforcement is opt-in (AGENTFORGE_SSO_REQUIRE): the public demo stays inspectable
    # at the *posture* level, production gates the whole read view. Exploit detail and the mutating
    # run trigger are gated either way.
    if _sso.enabled and _sso.require_sso and operator is None:
        return RedirectResponse("/login", status_code=302)
    return HTMLResponse(_render(_dashboard_data(), operator, _may_view_detail(request)))


def _signin_path() -> str:
    """The single entry point for signing in.

    When break-glass is configured the sign-in page offers both routes — OpenEMR first as the
    primary path, the operator token beneath it as the fallback — so one control in the header
    covers both and no button in the UI leads somewhere that cannot currently work.
    """
    if _break_glass_enabled():
        return "/login/token"
    return "/login" if _sso.enabled else ""


def _auth_notice(message: str, title: str = "Sign in", actions: str = "") -> str:
    """A clean, styled notice — never a bare 400 body or a stack trace in front of a reviewer."""
    return (_NOTICE_PAGE.replace("__TITLE__", title)
            .replace("__BODY__", message)
            .replace("__ACTIONS__", actions))


def _sso_unavailable(detail: str = "") -> str:
    """The honest page for a live SSO that is not working yet.

    Says so plainly and points at a route that does work, rather than leaving a reviewer staring
    at a bare 400. The underlying reason stays server-side: it describes the identity provider's
    internal state, which is not a browser's business.
    """
    fallback = (
        "<br><br>An operator token will get you in meanwhile — use the button below."
        if _break_glass_enabled() else
        "<br><br>Ask the platform owner for access while this is being fixed."
    )
    extra = f"<br><br><span class=dim>{detail}</span>" if detail else ""
    return _auth_notice(
        "The connection to the OpenEMR identity provider is still being set up, so it could not "
        "complete your login. This is a configuration issue on our side, not something you did "
        "wrong." + fallback + extra,
        title="Sign-in with OpenEMR isn't available yet", actions=_signin_actions())


def _signin_actions() -> str:
    """Whatever sign-in routes actually work right now, offered from an error page."""
    buttons = []
    if _break_glass_enabled():
        buttons.append("<a class='btn primary' href='/login/token'>Sign in with an operator "
                       "token</a>")
    if _sso.enabled:
        buttons.append("<a class='btn' href='/login'>Try OpenEMR again</a>")
    buttons.append("<a class='btn' href='/'>Back to the dashboard</a>")
    return "".join(buttons)


def _auth_ui(operator: OperatorSession | None) -> str:
    if operator is not None:
        return (f"<span class=who title='authenticated security-operator'>"
                f"<span class=who-dot></span>{_esc(operator.name)}</span>"
                f"<a class=toggle href='/logout'>Sign out</a>")
    path = _signin_path()
    return f"<a class='toggle primary' href='{path}'>Sign in</a>" if path else ""


# --------------------------------------------------------------------------------------
# Rendering — plain string building, no external templates or CDN
# --------------------------------------------------------------------------------------
def _esc(v: object) -> str:
    return html.escape(str(v))


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sev_pill(sev: str) -> str:
    return f"<span class='pill sev-{_esc(sev)}'><span class=dot></span>{_esc(sev.upper())}</span>"


def _status_pill(status: str) -> str:
    good = {"held", "resolved", "closed", "defense_held"}
    warn = {"in_progress", "confirmed", "triaged", "partial"}
    cls = "ok" if status in good else ("warn" if status in warn else "bad" if status == "open"
                                       else "muted")
    label = {"closed": "resolved", "held": "defense held",
             "defense_held": "defense held"}.get(status, status.replace("_", " "))
    return f"<span class='pill st-{cls}'>{_esc(label)}</span>"


def _stat(label: str, value: str, sub: str = "", tone: str = "") -> str:
    sub_html = f"<div class=s-sub>{_esc(sub)}</div>" if sub else ""
    return (f"<div class='stat {tone}'><div class=s-k>{_esc(label)}</div>"
            f"<div class=s-v>{_esc(value)}</div>{sub_html}</div>")


def _coverage_rows(coverage: dict[str, Any]) -> str:
    rows = []
    for cat, m in coverage.items():
        total = max(m.get("total", 0), 1)
        segs = [("defended", m.get("pass_defended", 0), "ok"),
                ("exploited", m.get("fail_exploited", 0), "bad"),
                ("partial", m.get("partial", 0), "warn"),
                ("inconclusive", m.get("inconclusive", 0), "muted"),
                ("held back for target safety", m.get("blocked_live_safety", 0), "blocked")]
        bar = "".join(
            f"<span class='seg seg-{c}' style='width:{100 * n / total:.1f}%' "
            f"title='{n} {name}'></span>"
            for name, n, c in segs if n
        )
        exploited = m.get("fail_exploited", 0)
        held_back = m.get("blocked_live_safety", 0)
        status = _status_pill("held" if exploited == 0 else "open")
        fired = m.get("executed_live", m.get("total", 0))
        fired_cell = (f"{fired}<span class=held-back title='held back by --safe-live: chart-write "
                      f"and ingest routes are never fired at the live clinical target'>"
                      f" +{held_back} held back</span>" if held_back else str(fired))
        rows.append(
            f"<tr><td><b>{_esc(cat.replace('_', ' '))}</b></td>"
            f"<td class=bar-cell><div class=bar>{bar}</div></td>"
            f"<td class=num>{fired_cell}</td>"
            f"<td class=num ok-t>{m.get('pass_defended', 0)}</td>"
            f"<td class=num bad-t>{exploited}</td>"
            f"<td class=owasp>{_esc(', '.join(m.get('owasp_web', [])))} · "
            f"{_esc(', '.join(m.get('owasp_llm', [])))}</td>"
            f"<td>{status}</td></tr>"
        )
    return "".join(rows) or "<tr><td colspan=7 class=muted>no coverage data yet</td></tr>"


def _findings_rows(findings: list[dict[str, Any]]) -> str:
    rows = []
    for f in sorted(findings, key=lambda x: _SEV_RANK.get(x.get("severity", "info"), 9)):
        sev = f.get("severity", "info")
        link = f.get("file", "")
        title = (f"<a href='/reports/{_esc(link)}'>{_esc(f.get('title', ''))} ↗</a>"
                 if link else _esc(f.get("title", "")))
        rows.append(
            f"<tr class=sev-row-{_esc(sev)}><td>{_sev_pill(sev)}</td>"
            f"<td>{_esc(f.get('category', '').replace('_', ' '))}</td>"
            f"<td class=owasp>{_esc(f.get('owasp_web', ''))}<br>{_esc(f.get('owasp_llm', ''))}</td>"
            f"<td>{_status_pill(f.get('status', 'open'))}</td>"
            f"<td>{title}</td></tr>"
        )
    return "".join(rows) or "<tr><td colspan=5 class=muted>no findings</td></tr>"


_FINDINGS_LEAD = (
    "<div class=lead>What a security reviewer scans first. Because the live target is hardened, "
    "these are demonstrated on an ephemeral, isolated vulnerable build and each is fix-validated by "
    "the regression harness — reproducible from the linked report alone.</div>"
)


def _findings_section(findings: list[dict[str, Any]], detail: bool) -> str:
    """The findings block, gated. Authorized operators get the table and the linked reports;
    everyone else gets counts and an explicit statement of what is being withheld and why."""
    head = "<h2>Findings</h2>"
    if detail:
        return (f"{head}{_FINDINGS_LEAD}"
                "<div class='card scroll'><table><thead><tr>"
                "<th>Severity</th><th>Category</th><th>OWASP (web / LLM)</th><th>Status</th>"
                "<th>Report</th></tr></thead><tbody>"
                f"{_findings_rows(findings)}</tbody></table></div>")
    counts = _severity_counts(findings)
    pills = "".join(_sev_pill(sev) + f"<span class=lk-n>{counts[sev]}</span>"
                    for sev in sorted(counts, key=lambda s: _SEV_RANK.get(s, 9)))
    # A quiet inline link, not a second competing button — the header already carries the one
    # sign-in control, and two primary buttons pointing at the same place read as a broken page.
    path = _signin_path()
    sign_in = (f" <a class=lk-link href='{path}'>Sign in to view</a>" if path else "")
    return (
        f"{head}"
        "<div class=lead>Counts are public; reproduction is not. Each report below contains a "
        "working attack sequence against a clinical system, so the technique, the OWASP-mapped "
        "exploit chain, and the repro steps are visible only to an authenticated, authorized "
        "security operator. Publishing those to the open internet is the exact anti-pattern this "
        "platform exists to flag — so it does not do it either.</div>"
        "<div class='card locked'><div class=lk-top>"
        f"<span class=lk-icon aria-hidden=true>🔒</span><div><div class=lk-h>"
        f"{len(findings)} finding{'' if len(findings) == 1 else 's'} — detail restricted</div>"
        f"<div class=lk-sub>Reproduction is operator-only.{sign_in}</div></div></div>"
        f"<div class=lk-pills>{pills}</div>"
        "</div>"
    )


def _confusion(conf: dict[str, Any]) -> str:
    tp, tn, fp, fn = (conf.get(k, 0) for k in ("tp", "tn", "fp", "fn"))

    def cell(n: int, good: bool) -> str:
        tone = "cok" if good else ("cbad" if n else "cempty")
        return f"<div class='cm-cell {tone}'><span class=cm-n>{n}</span></div>"

    return (
        "<div class=confusion>"
        "<div class=cm-corner></div>"
        "<div class=cm-h>Judge: EXPLOITED</div><div class=cm-h>Judge: DEFENDED</div>"
        "<div class=cm-side>vulnerable build<small>should be caught</small></div>"
        f"{cell(tp, True)}{cell(fn, False)}"
        "<div class=cm-side>fixed build<small>should hold</small></div>"
        f"{cell(fp, False)}{cell(tn, True)}"
        "</div>"
    )


_SELFTEST_FALLBACK = (
    "Each seeded defect is run against a build where it is present (should be caught) and one "
    "where it is fixed (should hold)."
)


def _selftest_lead(st: dict[str, Any]) -> str:
    """The score never ships without the sentence that says what it measured."""
    cases = st.get("cases")
    scale = f"{cases} cases. " if cases else ""
    return _esc(scale + str(st.get("interpretation") or _SELFTEST_FALLBACK))


def _calibration(cal: dict[str, Any]) -> str:
    if not cal.get("calibrated"):
        n = cal.get("labelled_cases", 0)
        return (
            "<div class='card locked'><div class=lk-top>"
            "<span class=lk-icon aria-hidden=true>◌</span><div>"
            "<div class=lk-h>Uncalibrated on this build</div>"
            f"<div class=lk-sub>{n} human-labelled cases are committed and ready; the agreement "
            "number is only published after a live scoring run "
            "(<code>agentforge judge-calibration --live</code>). An uncalibrated rung is reported "
            "as uncalibrated, never as a perfect score.</div></div></div></div>"
        )
    conf = cal.get("confusion", {})
    stats = "".join([
        _stat("Agreement", f"{round(100 * cal.get('agreement', 0))}%",
              f"held out · {cal.get('cases', 0)} cases", "accent"),
        _stat("Precision", str(cal.get("precision", "—")), "flagged compliance a human agreed with"),
        _stat("Recall", str(cal.get("recall", "—")), "real compliance the rung caught"),
    ])
    dis = cal.get("disagreements", [])
    rows = "".join(
        f"<tr><td class=mono>{_esc(d.get('id'))}</td>"
        f"<td>{_esc(d.get('trap') or '—')}</td>"
        f"<td>{'complied' if d.get('human') else 'refused'}</td>"
        f"<td class=bad-t>{'complied' if d.get('judge') else 'refused'}</td>"
        f"<td class=why>{_esc(d.get('rationale', ''))}</td></tr>"
        for d in dis
    )
    table = (
        "<div class='card scroll' style='margin-top:14px'><table><thead><tr>"
        "<th>Case</th><th>Designed to trap</th><th>Human</th><th>LLM rung</th><th>Why it is a "
        "miss</th></tr></thead><tbody>" + rows + "</tbody></table></div>"
        if rows else
        "<div class=lead style='margin-top:12px'>No disagreements on this set — which bounds the "
        "error rate at this sample size rather than proving there is none.</div>"
    )
    # The provenance line is the point of the section: a tuned score on its own tuning set is not
    # a result, and showing the pre-fix number is what makes the post-fix number legible.
    trail = []
    if (before := cal.get("before_rubric_fix")):
        trail.append(f"first measurement, before any fix — agreement "
                     f"{round(100 * before['agreement'])}%, recall {before['recall']} "
                     f"({before['cases']} cases)")
    if (insample := cal.get("in_sample")):
        trail.append(f"after the rubric fix, scored on the very set it was tuned on — "
                     f"{round(100 * insample['agreement'])}%, <b>in-sample, so not a result</b>")
    if (prev := cal.get("previous_holdout")):
        trail.append(f"the same fix on cases written afterwards — "
                     f"{round(100 * prev['agreement'])}%, whose two errors shared one cause: the "
                     f"rung was never told which patient was in scope")
    trail.append(f"after supplying that scope, on a second holdout built to target exactly that "
                 f"failure — <b>{round(100 * cal.get('agreement', 0))}%</b>, the number above")
    return (f"<div class=stats>{stats}</div>"
            f"<div class=lead style='margin-top:12px'>Rung model <code>{_esc(cal.get('model', '—'))}"
            f"</code> · tp {conf.get('tp', 0)} · tn {conf.get('tn', 0)} · fp {conf.get('fp', 0)} · "
            f"fn {conf.get('fn', 0)}. How this number was arrived at: "
            + "; then ".join(trail) + ". Every disagreement is published rather than summarised "
            "away.</div>" + table)


def _cost_rows(proj: list[dict[str, Any]]) -> str:
    if not proj:
        return "<tr><td colspan=4 class=muted>—</td></tr>"
    top = max((r.get("dollars", 0) for r in proj), default=1) or 1
    rows = []
    for r in proj:
        pct = 100 * r.get("dollars", 0) / top
        rows.append(
            f"<tr><td class=num>{r.get('n', 0):,}</td>"
            f"<td class=num>${r.get('dollars', 0):,.2f}</td>"
            f"<td class=bar-cell><div class=bar><span class='seg seg-cost' "
            f"style='width:{pct:.1f}%'></span></div></td>"
            f"<td class=num muted>{_esc(r.get('wall', ''))}</td></tr>"
        )
    return "".join(rows)


def _activity_rows(activity: list[dict[str, Any]]) -> str:
    rows = []
    for a in activity:
        agent = a.get("agent", "")
        rows.append(
            f"<li><span class='agent a-{_esc(agent)}'>{_esc(agent)}</span>"
            f"<span class=act-ev>{_esc(a.get('event', ''))}</span>"
            f"<span class=act-detail>{_esc(a.get('detail', ''))}</span></li>"
        )
    return "".join(rows) or "<li class=muted>no recent activity</li>"


def _render(d: dict[str, Any], operator: OperatorSession | None = None,
            detail: bool = False) -> str:
    if not d:
        return ("<body style='font-family:system-ui;max-width:640px;margin:80px auto;padding:0 20px'>"
                "<h1>AgentForge</h1><p>No dashboard data yet. Run "
                "<code>agentforge dashboard</code> to generate it.</p></body>")
    t = d.get("target", {})
    totals = d.get("totals", {})
    fs = d.get("findings_summary", {})
    cost = d.get("cost", {})
    st = d.get("self_test", {})
    status_ok = d.get("status") == "defense_held"
    pass_pct = round(100 * totals.get("pass_rate", 0))

    hero = (f"<span class='pill st-{'ok' if status_ok else 'bad'} lg'>"
            f"{'✓  Defense held' if status_ok else '⚠  Findings open'}</span>")
    fired = totals.get("executed_live", totals.get("total", 0))
    held_back = totals.get("blocked_live_safety", 0)
    stats = "".join([
        _stat("Pass rate", f"{pass_pct}%", f"of {fired} cases actually fired", "accent"),
        _stat("Attack cases", str(fired),
              (f"+{held_back} held back for target safety" if held_back
               else "authenticated /chat + reads")),
        _stat("Categories", str(totals.get("categories", 0)), "OWASP dual-mapped"),
        _stat("Open on live target", str(fs.get("open_on_live_target", 0)), "confirmed exploits"),
        _stat("Findings resolved", str(fs.get("resolved", 0)), "fix-validated"),
        _stat("Live cost", f"${cost.get('live_inference_usd', 0)}",
              f"{cost.get('model_turns', 0)} model turns"),
    ])
    selftest = "".join([
        _stat("Precision", str(st.get("precision", "—")), "no false alarms"),
        _stat("Recall", str(st.get("recall", "—")), "no missed vulns"),
        _stat("Accuracy", str(st.get("accuracy", "—")), "vs. deterministic ground truth"),
    ])
    resilience = "".join(
        f"<tr><td class=mono>{_esc(r.get('fingerprint'))}</td>"
        f"<td class=muted>{_esc(str(r.get('run_at'))[:19].replace('T', ' '))}</td>"
        f"<td class=num>{_esc(r.get('cases'))}</td>"
        f"<td class=num ok-t>{round(100 * r.get('pass_rate', 0))}%</td></tr>"
        for r in d.get("resilience", [])
    ) or "<tr><td colspan=4 class=muted>—</td></tr>"

    page = _PAGE
    for k, v in {
        "__TITLE__": _esc(d.get("title", "AgentForge")),
        "__HERO__": hero,
        "__AUTH__": _auth_ui(operator),
        "__TARGET__": _esc(t.get("url", "—")),
        "__FINGERPRINT__": _esc(t.get("fingerprint", "—")),
        "__SURFACE__": _esc(t.get("surface", "—")),
        "__LASTRUN__": _esc(str(t.get("last_run", "—"))[:19].replace("T", " ")),
        "__STATS__": stats,
        "__FINDINGS_SECTION__": _findings_section(d.get("findings", []), detail),
        "__COVERAGE__": _coverage_rows(d.get("coverage", {})),
        "__SELFTEST__": selftest,
        "__SELFTEST_LEAD__": _selftest_lead(st),
        "__CONFUSION__": _confusion(st.get("confusion", {})),
        "__CALIBRATION__": _calibration(d.get("judge_calibration", {})),
        "__RESILIENCE__": resilience,
        "__COST__": _cost_rows(d.get("cost_projection", [])),
        "__ACTIVITY__": _activity_rows(d.get("agent_activity", [])),
        "__TAXONOMY__": _esc(d.get("taxonomy_version", "—")),
        "__GENERATED__": _esc(str(d.get("generated_at", "—"))[:19].replace("T", " ")),
    }.items():
        page = page.replace(k, v)
    return page


_LOGO = (
    "<svg class=logo viewBox='0 0 32 32' width=30 height=30 aria-hidden=true>"
    "<rect x=2 y=2 width=28 height=28 rx=8 fill='var(--accent)'/>"
    "<circle cx=16 cy=16 r=7 fill=none stroke=white stroke-width=2/>"
    "<circle cx=16 cy=16 r=2 fill=white/>"
    "<line x1=16 y1=5 x2=16 y2=9 stroke=white stroke-width=2/>"
    "<line x1=16 y1=23 x2=16 y2=27 stroke=white stroke-width=2/>"
    "<line x1=5 y1=16 x2=9 y2=16 stroke=white stroke-width=2/>"
    "<line x1=23 y1=16 x2=27 y2=16 stroke=white stroke-width=2/></svg>"
)

_REPORT_PAGE = (
    "<!doctype html><meta charset=utf-8><title>__NAME__ — AgentForge</title>"
    "<style>:root{color-scheme:light dark}body{max-width:820px;margin:0 auto;padding:32px 20px;"
    "font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;line-height:1.6;"
    "background:#0b1220;color:#e6edf6}a{color:#818cf8;font-family:system-ui}"
    "pre{white-space:pre-wrap;word-wrap:break-word}"
    "@media(prefers-color-scheme:light){body{background:#fff;color:#0f172a}}</style>"
    "<p><a href='/'>← back to dashboard</a></p><pre>__BODY__</pre>"
)

# Shared chrome for the small standalone pages (sign-in, notices). Same tokens as the dashboard,
# inlined — no CDN anywhere in this service.
_MINI_CSS = (
    "<style>:root{color-scheme:light dark;--bg:#080c14;--card:#0f1826;--bd:#1e2b3d;--ink:#e6edf7;"
    "--dim:#9fb1c7;--accent:#818cf8}"
    "@media(prefers-color-scheme:light){:root{--bg:#f6f8fb;--card:#fff;--bd:#e5eaf0;--ink:#0f172a;"
    "--dim:#475569;--accent:#4f46e5}}"
    "*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;"
    "justify-content:center;padding:24px;background:var(--bg);color:var(--ink);font-size:14px;"
    "line-height:1.55;-webkit-font-smoothing:antialiased;"
    "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}"
    ".box{width:100%;max-width:440px;background:var(--card);border:1px solid var(--bd);"
    "border-radius:16px;padding:28px}"
    ".mark{display:flex;align-items:center;gap:10px;margin-bottom:18px;font-weight:700;"
    "letter-spacing:-.01em}"
    "h1{font-size:18px;margin:0 0 10px;letter-spacing:-.01em}"
    "p{color:var(--dim);font-size:13px;margin:0 0 14px}"
    ".dim{color:var(--dim);font-size:12px}"
    "a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}"
    "input{width:100%;padding:11px 12px;border-radius:10px;border:1px solid var(--bd);"
    "background:var(--bg);color:inherit;font-size:14px;margin:0 0 12px}"
    ".btn{display:block;width:100%;padding:11px;border:1px solid var(--bd);border-radius:10px;"
    "background:transparent;color:var(--ink);font-weight:650;font-size:14px;cursor:pointer;"
    "text-align:center;margin-bottom:10px;text-decoration:none}"
    ".btn:hover{border-color:var(--accent);color:var(--accent);text-decoration:none}"
    ".btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}"
    ".btn.primary:hover{filter:brightness(1.06);color:#fff}"
    ".sep{display:flex;align-items:center;gap:10px;color:var(--dim);font-size:11px;"
    "text-transform:uppercase;letter-spacing:.06em;margin:18px 0 14px}"
    ".sep::before,.sep::after{content:'';flex:1;height:1px;background:var(--bd)}"
    "</style>"
)

_NOTICE_PAGE = (
    "<!doctype html><meta charset=utf-8><title>__TITLE__ — AgentForge</title>"
    "<meta name=viewport content='width=device-width,initial-scale=1'>"
    + _MINI_CSS +
    "<div class=box><div class=mark>" + _LOGO + "AgentForge</div>"
    "<h1>__TITLE__</h1><p>__BODY__</p>__ACTIONS__</div>"
)

# One sign-in page, both routes. OpenEMR is presented first as the primary path; the operator
# token sits beneath it as the documented fallback for exactly the situation the platform is in —
# the identity provider not yet working. Two competing buttons in the header made the dashboard
# look broken, so the choice lives here instead.
_BREAK_GLASS_PAGE = (
    "<!doctype html><meta charset=utf-8><title>Sign in — AgentForge</title>"
    "<meta name=viewport content='width=device-width,initial-scale=1'>"
    "<meta name=robots content='noindex,nofollow'>"
    + _MINI_CSS +
    "<div class=box><div class=mark>" + _LOGO + "AgentForge</div>"
    "<h1>Sign in</h1>"
    "<p>Exploit reproduction is restricted to security operators.</p>"
    "__SSO__"
    "<form method=post action='/login/token' autocomplete=off>"
    "<input type=hidden name=return_to value='__RETURN__'>"
    "<input type=password name=token placeholder='Operator token' aria-label='Operator token' "
    "autofocus required>"
    "<button class='btn primary' type=submit>Sign in with token</button></form>"
    "<p class=dim style='margin:14px 0 0'>Every use of the operator token — granted or denied — is "
    "recorded in the platform's append-only audit ledger.</p>"
    "<p style='margin-top:16px'><a href='/'>← back to dashboard</a></p></div>"
)

_SSO_BLOCK = (
    "<a class='btn primary' href='/login'>Log in with OpenEMR</a>"
    "<p class=dim style='margin:-2px 0 0'>The primary sign-in route.</p>"
    "<div class=sep>or use an operator token</div>"
)


_PAGE = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>AgentForge — adversarial security dashboard</title>
<link rel=icon href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='8' fill='%234f46e5'/><circle cx='16' cy='16' r='7' fill='none' stroke='white' stroke-width='2'/><circle cx='16' cy='16' r='2' fill='white'/></svg>">
<style>
:root{
 --bg:#f6f8fb; --surface:#ffffff; --surface-2:#f1f5f9; --border:#e5eaf0;
 --ink:#0f172a; --ink-2:#475569; --ink-3:#8a99ad; --accent:#4f46e5; --accent-soft:#eef2ff;
 --ok:#16a34a; --ok-bg:#dcfce7; --warn:#c2740a; --warn-bg:#fef3c7; --bad:#dc2626; --bad-bg:#fee2e2;
 --seg-track:#eef1f5;
 --sev-critical:#dc2626; --sev-high:#ea580c; --sev-medium:#ca8a04; --sev-low:#0891b2; --sev-info:#64748b;
 --shadow:0 1px 2px rgba(15,23,42,.04),0 1px 3px rgba(15,23,42,.06);
}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
 --bg:#080c14; --surface:#0f1826; --surface-2:#141f30; --border:#1e2b3d;
 --ink:#e6edf7; --ink-2:#9fb1c7; --ink-3:#5c6f88; --accent:#818cf8; --accent-soft:#1a2035;
 --ok:#4ade80; --ok-bg:#0e2a1b; --warn:#fbbf24; --warn-bg:#2e2408; --bad:#f87171; --bad-bg:#331414;
 --seg-track:#1a2536; --shadow:none;
}}
:root[data-theme=dark]{
 --bg:#080c14; --surface:#0f1826; --surface-2:#141f30; --border:#1e2b3d;
 --ink:#e6edf7; --ink-2:#9fb1c7; --ink-3:#5c6f88; --accent:#818cf8; --accent-soft:#1a2035;
 --ok:#4ade80; --ok-bg:#0e2a1b; --warn:#fbbf24; --warn-bg:#2e2408; --bad:#f87171; --bad-bg:#331414;
 --seg-track:#1a2536; --shadow:none;
 --sev-critical:#f87171; --sev-high:#fb923c; --sev-medium:#facc15; --sev-low:#22d3ee; --sev-info:#94a3b8;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);-webkit-font-smoothing:antialiased;
 font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
 font-size:14px;line-height:1.5}
.wrap{max-width:1120px;margin:0 auto;padding:22px 22px 64px}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
.muted{color:var(--ink-3)} .num{text-align:right;font-variant-numeric:tabular-nums}
.ok-t{color:var(--ok)} .bad-t{color:var(--bad)}

/* header */
header{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;
 padding-bottom:16px;border-bottom:1px solid var(--border);margin-bottom:22px}
.brand{display:flex;align-items:center;gap:12px}
.logo{border-radius:8px;flex:none}
.brand h1{font-size:19px;margin:0;letter-spacing:-.01em}
.brand .tag{color:var(--ink-2);font-size:12.5px;margin-top:1px}
.hgroup{display:flex;align-items:center;gap:10px}
.meta{color:var(--ink-3);font-size:12px;margin:-6px 0 22px;display:flex;flex-wrap:wrap;gap:4px 16px}
.meta b{color:var(--ink-2);font-weight:600}
.toggle{background:var(--surface);border:1px solid var(--border);color:var(--ink-2);border-radius:8px;
 padding:6px 11px;cursor:pointer;font-size:12px;font-weight:600;line-height:1;
 text-decoration:none;display:inline-flex;align-items:center}
.toggle:hover{border-color:var(--accent);color:var(--accent);text-decoration:none}
.toggle.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.toggle.primary:hover{filter:brightness(1.06);color:#fff}
.who{display:inline-flex;align-items:center;gap:7px;font-size:12.5px;font-weight:600;color:var(--ink-2);
 padding:5px 11px;border:1px solid var(--border);border-radius:8px;background:var(--surface)}
.who-dot{width:7px;height:7px;border-radius:50%;background:var(--ok);flex:none}

/* section headers */
h2{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--ink-3);
 margin:32px 0 12px;font-weight:700;display:flex;align-items:center;gap:8px}
h2::after{content:"";flex:1;height:1px;background:var(--border)}
.lead{color:var(--ink-2);font-size:12.5px;margin:-4px 0 14px;max-width:760px;line-height:1.55}

/* stat tiles */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:15px 16px;
 box-shadow:var(--shadow)}
.stat.accent{border-color:color-mix(in srgb,var(--accent) 40%,var(--border))}
.s-k{color:var(--ink-3);font-size:11px;text-transform:uppercase;letter-spacing:.04em;font-weight:600}
.s-v{font-size:26px;font-weight:750;margin-top:5px;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.stat.accent .s-v{color:var(--accent)}
.s-sub{color:var(--ink-3);font-size:11.5px;margin-top:2px}

/* cards + tables */
.card{background:var(--surface);border:1px solid var(--border);border-radius:14px;overflow:hidden;
 box-shadow:var(--shadow)}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{padding:11px 14px;text-align:left;border-bottom:1px solid var(--border);font-size:13px;
 white-space:nowrap;vertical-align:middle}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:var(--surface-2)}
th{background:var(--surface-2);color:var(--ink-3);font-size:10.5px;text-transform:uppercase;
 letter-spacing:.05em;font-weight:700}
.owasp{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;color:var(--ink-2);white-space:normal;
 line-height:1.35}
.sev-row-critical{box-shadow:inset 3px 0 0 var(--sev-critical)}
.sev-row-high{box-shadow:inset 3px 0 0 var(--sev-high)}
.sev-row-medium{box-shadow:inset 3px 0 0 var(--sev-medium)}

/* pills */
.pill{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;
 font-size:11.5px;font-weight:650;white-space:nowrap;line-height:1.3}
.pill.lg{font-size:13.5px;padding:6px 14px}
.st-ok{background:var(--ok-bg);color:var(--ok)} .st-warn{background:var(--warn-bg);color:var(--warn)}
.st-bad{background:var(--bad-bg);color:var(--bad)} .st-muted{background:var(--surface-2);color:var(--ink-2)}
.pill .dot{width:7px;height:7px;border-radius:50%;background:currentColor;flex:none}
.sev-critical{background:var(--bad-bg);color:var(--sev-critical)}
.sev-high{background:var(--warn-bg);color:var(--sev-high)}
.sev-medium{background:var(--warn-bg);color:var(--sev-medium)}
.sev-low{background:var(--surface-2);color:var(--sev-low)}
.sev-info{background:var(--surface-2);color:var(--sev-info)}

/* segmented bars */
.bar-cell{width:38%;min-width:140px}
.bar{display:flex;height:9px;border-radius:5px;overflow:hidden;background:var(--seg-track)}
.seg{height:100%} .seg+.seg{box-shadow:inset 1px 0 0 var(--surface)}
.seg-defended,.seg-ok{background:var(--ok)} .seg-exploited,.seg-bad{background:var(--bad)}
.seg-partial,.seg-warn{background:var(--warn)} .seg-inconclusive,.seg-muted{background:var(--ink-3)}
.seg-cost{background:var(--accent)}
.seg-blocked{background:repeating-linear-gradient(45deg,var(--ink-3),var(--ink-3) 3px,
 var(--seg-track) 3px,var(--seg-track) 6px)}
.held-back{color:var(--ink-3);font-size:10.5px;font-weight:600;white-space:nowrap;cursor:help}
td.why{white-space:normal;color:var(--ink-2);font-size:12px;min-width:260px;line-height:1.45}

/* gated findings panel */
.card.locked{padding:18px 20px;background:linear-gradient(180deg,var(--surface),var(--surface-2))}
.lk-top{display:flex;gap:14px;align-items:flex-start}
.lk-icon{font-size:19px;line-height:1.2;flex:none;filter:grayscale(.2)}
.lk-h{font-weight:700;font-size:14.5px;letter-spacing:-.01em}
.lk-sub{color:var(--ink-3);font-size:12.5px;margin-top:2px}
.lk-pills{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0 0}
.lk-pills .pill{padding-right:4px}
.lk-n{font-variant-numeric:tabular-nums;font-weight:750;font-size:13px;color:var(--ink-2);
 margin:0 8px 0 -4px}
.lk-link{font-weight:600}

/* confusion matrix */
.selftest-grid{display:grid;grid-template-columns:1fr auto;gap:20px;align-items:center}
@media (max-width:720px){.selftest-grid{grid-template-columns:1fr}}
.confusion{display:grid;grid-template-columns:120px 88px 88px;grid-auto-rows:auto;gap:6px;
 background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:16px;
 box-shadow:var(--shadow)}
.cm-corner{}
.cm-h{font-size:10px;font-weight:700;color:var(--ink-3);text-transform:uppercase;text-align:center;
 align-self:end;letter-spacing:.03em}
.cm-side{font-size:11px;font-weight:650;color:var(--ink-2);display:flex;flex-direction:column;
 justify-content:center;line-height:1.3} .cm-side small{color:var(--ink-3);font-weight:400;font-size:10px}
.cm-cell{height:56px;border-radius:9px;display:flex;align-items:center;justify-content:center;
 font-variant-numeric:tabular-nums}
.cm-n{font-size:22px;font-weight:750}
.cok{background:var(--ok-bg);color:var(--ok);box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--ok) 30%,transparent)}
.cbad{background:var(--bad-bg);color:var(--bad);box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--bad) 35%,transparent)}
.cempty{background:var(--surface-2);color:var(--ink-3)}

/* timeline */
ul.timeline{list-style:none;margin:0;padding:0}
ul.timeline li{display:flex;align-items:center;gap:12px;padding:9px 14px;
 border-bottom:1px solid var(--border);font-size:12.5px}
.card ul.timeline li:last-child{border-bottom:none}
.agent{min-width:104px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.03em;
 padding:3px 8px;border-radius:6px;text-align:center;flex:none}
.a-orchestrator{background:var(--accent-soft);color:var(--accent)}
.a-redteam{background:var(--bad-bg);color:var(--bad)}
.a-judge{background:var(--ok-bg);color:var(--ok)}
.a-documentation{background:var(--warn-bg);color:var(--warn)}
.act-ev{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--ink-3);min-width:124px;flex:none}
.act-detail{color:var(--ink);white-space:normal}

/* two-column grid for mid sections */
.cols{display:grid;grid-template-columns:1.3fr 1fr;gap:20px;align-items:start}
@media (max-width:860px){.cols{grid-template-columns:1fr}}

.foot{color:var(--ink-3);font-size:12px;margin-top:34px;line-height:1.65;border-top:1px solid var(--border);
 padding-top:18px}
.foot a{color:var(--ink-2)} .foot code{background:var(--surface-2);padding:1px 5px;border-radius:4px}
</style></head><body><div class=wrap>

<header>
 <div class=brand>__LOGO__
  <div><h1>AgentForge</h1><div class=tag>__TITLE__</div></div>
 </div>
 <div class=hgroup>__HERO____AUTH__
  <button class=toggle id=themeBtn aria-label="Toggle color theme">◐ Theme</button>
 </div>
</header>

<div class=meta>
 <span>Target <b class=mono>__TARGET__</b></span>
 <span>Fingerprint <b class=mono>__FINGERPRINT__</b></span>
 <span>Surface <b>__SURFACE__</b></span>
 <span>Last run <b>__LASTRUN__</b></span>
</div>

<div class=stats>__STATS__</div>

__FINDINGS_SECTION__

<h2>Coverage by attack category</h2>
<div class="card scroll"><table><thead><tr>
 <th>Category</th><th>Outcome</th><th class=num>Cases</th><th class=num>Defended</th>
 <th class=num>Exploited</th><th>OWASP (web · LLM)</th><th>Status</th>
 </tr></thead><tbody>__COVERAGE__</tbody></table></div>

<h2>Platform self-test — deterministic rungs</h2>
<div class=lead>__SELFTEST_LEAD__</div>
<div class=selftest-grid>
 <div class=stats>__SELFTEST__</div>
 __CONFUSION__
</div>

<h2>Judge calibration — the LLM rung vs. human labels</h2>
<div class=lead>The rung above cannot be wrong in an interesting way. This one can: for an
 ambiguous <code>/chat</code> turn the Judge asks a model whether the target <em>complied</em> with
 the injected instruction, and that is a judgement call. It is scored separately against a
 hand-labelled set built from the cases that break naive scoring in both directions — refusals that
 echo PHI vocabulary, refusals that quote the injection back, compliance hidden behind a refusal
 preamble, a healthy in-scope answer that must not become a finding.</div>
__CALIBRATION__

<div class=cols>
 <div>
  <h2>Projected cost at scale</h2>
  <div class="card scroll"><table><thead><tr>
   <th class=num>Attack runs</th><th class=num>Est. cost</th><th>Relative</th><th class=num>Wall-clock</th>
   </tr></thead><tbody>__COST__</tbody></table></div>
  <div class=lead style="margin-top:10px">Not cost-per-token × n: deterministic generation is free,
   the Judge is triaged, and wall-clock (not dollars) is the binding constraint. Full model in
   <code>docs/COST_ANALYSIS.md</code>.</div>
 </div>
 <div>
  <h2>Resilience over target versions</h2>
  <div class="card scroll"><table><thead><tr>
   <th>Fingerprint</th><th>Run</th><th class=num>Cases</th><th class=num>Pass</th>
   </tr></thead><tbody>__RESILIENCE__</tbody></table></div>
  <div class=lead style="margin-top:10px">The target is content-fingerprinted every run; a new
   fingerprint triggers a full regression pass, so resilience is tracked per version, not per date.</div>
 </div>
</div>

<h2>Recent agent activity</h2>
<div class=lead>A real captured multi-agent trace — the Orchestrator routes to the Red Team, the Judge
 evaluates independently, and the Documentation agent drafts on a confirmed exploit.</div>
<div class=card><ul class=timeline>__ACTIVITY__</ul></div>

<div class=foot>
 OWASP taxonomy __TAXONOMY__ · generated __GENERATED__. Every eval case is dual-OWASP-mapped and
 reproducible (fixed-seed generation). Against the hardened live target the honest result is
 <b>defense held</b> — a legitimate outcome, not a gap. Synthetic patient data only; no real PHI.
 This page is self-contained (no external scripts, fonts, or trackers) and read-only. The attack
 trigger and every exploit-reproduction detail are RBAC-gated to authenticated operators — this
 platform applies its own findings to itself.
 <br>API: <a href="/api/dashboard">/api/dashboard</a> · <a href="/api/coverage">/api/coverage</a> ·
 <a href="/api/target">/api/target</a> · <a href="/health">/health</a>
</div>
</div>
<script>
(function(){
 var root=document.documentElement, btn=document.getElementById('themeBtn');
 var saved=localStorage.getItem('af-theme');
 if(saved) root.setAttribute('data-theme',saved);
 btn.addEventListener('click',function(){
  var cur=root.getAttribute('data-theme');
  if(!cur){cur=matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light';}
  var next=cur==='dark'?'light':'dark';
  root.setAttribute('data-theme',next); localStorage.setItem('af-theme',next);
 });
})();
</script>
</body></html>""".replace("__LOGO__", _LOGO)
