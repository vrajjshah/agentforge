"""Exploit detail is operator-only — the platform applies its own findings to itself.

The deployed demo runs with ``AGENTFORGE_SSO_REQUIRE=0`` so a reviewer can assess posture without
credentials. These tests pin the line between *posture* (public: pass rate, category and severity
counts, "defense held") and *reproduction* (gated: finding titles, which name the technique, and
the reports, which are working attack sequences against a clinical system).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest

_REPORT_BODY = """# Vulnerability Report — Data Exfiltration: idor-document-keyed-read

## Minimal reproducible attack sequence
1. `GET /week2/documents/2/extraction`
"""
_TECHNIQUE = "idor-document-keyed-read"

_DASHBOARD: dict[str, Any] = {
    "title": "AgentForge", "status": "defense_held", "taxonomy_version": "2021/2023",
    "target": {"url": "https://target.test/copilot", "fingerprint": "abc123",
               "surface": "authenticated /chat", "last_run": "2026-07-21T07:01:06+00:00"},
    "totals": {"total": 48, "pass_defended": 47, "fail_exploited": 0, "pass_rate": 0.979,
               "categories": 4},
    "coverage": {"data_exfiltration": {"total": 12, "pass_defended": 12, "fail_exploited": 0,
                                       "owasp_web": ["A01:2021"], "owasp_llm": ["LLM06:2023"]}},
    "findings": [
        {"id": "v1", "severity": "critical", "category": "data_exfiltration", "status": "closed",
         "title": f"Data Exfiltration: {_TECHNIQUE}", "file": "ea8fa01.md",
         "owasp_web": "A01:2021", "owasp_llm": "LLM06:2023"},
        {"id": "v2", "severity": "high", "category": "identity_role", "status": "closed",
         "title": "Identity Role: attribution-forgery", "file": "e0e7b6a.md",
         "owasp_web": "A01:2021", "owasp_llm": "LLM08:2023"},
    ],
    "findings_summary": {"resolved": 2, "in_progress": 0, "open_on_live_target": 0},
    "cost": {"live_inference_usd": 0.42, "model_turns": 12},
    "self_test": {"confusion": {"tp": 3, "tn": 3, "fp": 0, "fn": 0}},
    "cost_projection": [], "agent_activity": [], "resilience": [],
}

_TOKEN = "test-operator-token"


@pytest.fixture
def web_app(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    """The public-demo posture: SSO configured but not required, break-glass token enabled."""
    from agentforge import web
    from agentforge.auth.config import SsoConfig
    from agentforge.auth.session import SessionStore

    evals, reports = tmp_path / "evals", tmp_path / "reports"
    evals.mkdir(), reports.mkdir()
    (evals / "dashboard.json").write_text(json.dumps(_DASHBOARD))
    (reports / "ea8fa01.md").write_text(_REPORT_BODY)

    monkeypatch.setattr(web, "_EVALS", evals)
    monkeypatch.setattr(web, "_REPORTS", reports)
    monkeypatch.setattr(web, "_sessions", SessionStore())
    monkeypatch.setattr(web, "_sso", SsoConfig(
        client_id="cid", client_secret="", issuer="https://idp.test/oauth2/default",
        redirect_uri="https://af.test/callback", scope="openid", operator_allowlist=(),
        operator_roles=("admin",), operator_names={}, require_sso=False,
        cookie_secure=False))
    monkeypatch.setenv("AGENTFORGE_ADMIN_TOKEN", _TOKEN)
    # Pin the gated baseline against the ambient environment. The deployment sets
    # AGENTFORGE_PUBLIC_REPORTS, so an exported shell value would otherwise open the gate under
    # the tests that exist to prove it closed, and they would pass by not testing anything.
    monkeypatch.delenv("AGENTFORGE_PUBLIC_REPORTS", raising=False)
    return web


def _client(web: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=web.app),
                             base_url="https://af.test")


# --- anonymous: posture yes, reproduction no --------------------------------------------------
async def test_anonymous_report_is_refused(web_app: Any) -> None:
    async with _client(web_app) as c:
        r = await c.get("/reports/ea8fa01.md")
    assert r.status_code == 403
    assert "GET /week2/documents" not in r.text     # no repro steps leak into the refusal page
    assert "restricted" in r.text


async def test_anonymous_dashboard_page_hides_technique(web_app: Any) -> None:
    async with _client(web_app) as c:
        r = await c.get("/")
    assert r.status_code == 200
    assert _TECHNIQUE not in r.text                  # finding titles name the technique
    assert "attribution-forgery" not in r.text
    assert "/reports/ea8fa01.md" not in r.text       # and no link to the repro
    assert "detail restricted" in r.text
    assert "98%" in r.text                           # posture (pass rate) stays public


async def test_anonymous_api_is_sanitized(web_app: Any) -> None:
    async with _client(web_app) as c:
        r = await c.get("/api/dashboard")
    body = r.json()
    assert body["findings"] == []
    assert body["detail_gated"] is True
    assert body["findings_public"] == {
        "total": 2, "by_severity": {"critical": 1, "high": 1},
        "note": body["findings_public"]["note"]}
    assert _TECHNIQUE not in r.text
    assert body["totals"]["pass_rate"] == 0.979      # posture survives the projection
    assert body["coverage"]["data_exfiltration"]["total"] == 12


async def test_anonymous_run_trigger_still_refused(web_app: Any) -> None:
    async with _client(web_app) as c:
        r = await c.post("/api/run/data_exfiltration")
    assert r.status_code == 401


# --- authorized: the full picture --------------------------------------------------------------
async def test_admin_token_header_unlocks_detail(web_app: Any) -> None:
    async with _client(web_app) as c:
        report = await c.get("/reports/ea8fa01.md", headers={"x-admin-token": _TOKEN})
        api = await c.get("/api/dashboard", headers={"x-admin-token": _TOKEN})
    assert report.status_code == 200
    assert "GET /week2/documents" in report.text
    assert len(api.json()["findings"]) == 2
    assert api.json()["detail_gated"] is False   # stated on both sides, never absent


async def test_wrong_admin_token_stays_locked(web_app: Any) -> None:
    async with _client(web_app) as c:
        r = await c.get("/reports/ea8fa01.md", headers={"x-admin-token": _TOKEN + "x"})
    assert r.status_code == 403


async def test_break_glass_login_grants_detail(web_app: Any) -> None:
    async with _client(web_app) as c:
        assert (await c.get("/login/token")).status_code == 200
        bad = await c.post("/login/token", data={"token": "nope"}, follow_redirects=False)
        assert bad.status_code == 401
        ok = await c.post("/login/token", data={"token": _TOKEN}, follow_redirects=False)
        assert ok.status_code == 302
        sid = ok.cookies[web_app._SESSION_COOKIE]
        page = await c.get("/", cookies={web_app._SESSION_COOKIE: sid})
        report = await c.get("/reports/ea8fa01.md", cookies={web_app._SESSION_COOKIE: sid})
        run = await c.post("/api/run/data_exfiltration",
                           cookies={web_app._SESSION_COOKIE: sid})
    assert _TECHNIQUE in page.text and "/reports/ea8fa01.md" in page.text
    assert report.status_code == 200
    assert run.status_code == 200


async def test_break_glass_revoked_when_token_cleared(
        web_app: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """A live break-glass session dies with the token that minted it — no lingering authority."""
    async with _client(web_app) as c:
        ok = await c.post("/login/token", data={"token": _TOKEN}, follow_redirects=False)
        sid = ok.cookies[web_app._SESSION_COOKIE]
        monkeypatch.delenv("AGENTFORGE_ADMIN_TOKEN")
        r = await c.get("/reports/ea8fa01.md", cookies={web_app._SESSION_COOKIE: sid})
    assert r.status_code == 403


async def test_break_glass_disabled_without_token(
        web_app: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTFORGE_ADMIN_TOKEN")
    async with _client(web_app) as c:
        assert (await c.get("/login/token")).status_code == 404
        assert (await c.post("/login/token", data={"token": "x"})).status_code == 404


async def test_report_path_traversal_still_blocked(web_app: Any) -> None:
    async with _client(web_app) as c:
        r = await c.get("/reports/..%2F..%2Fpyproject.toml", headers={"x-admin-token": _TOKEN})
    assert r.status_code == 404


# --- break-glass is auditable, and the UI never advertises a dead route --------------------------
async def test_break_glass_use_is_recorded_in_the_ledger(
        web_app: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A shared-token bypass is only defensible if every reach for it is on the record — the
    failures especially, since a run of `denied` is how token-guessing shows up."""
    import dataclasses

    from agentforge.stores.ledger import EventLedger, EventType

    monkeypatch.setattr(web_app, "_settings",
                        dataclasses.replace(web_app._settings, data_dir=tmp_path / "d"))
    async with _client(web_app) as c:
        await c.post("/login/token", data={"token": "wrong"}, follow_redirects=False)
        await c.post("/login/token", data={"token": _TOKEN}, follow_redirects=False)

    ledger = EventLedger(tmp_path / "d" / "ledger.db")
    try:
        events = ledger.events(event_type=EventType.AUTH_ACCESS)
    finally:
        ledger.close()
    outcomes = [e["payload"]["outcome"] for e in events]
    assert "denied" in outcomes and "granted" in outcomes
    assert all(e["agent"] == "web" for e in events)
    # The token itself is never written anywhere.
    assert _TOKEN not in json.dumps(events)


async def test_ledger_writer_for_auth_is_least_privilege() -> None:
    """The web service may record auth events and nothing else."""
    import tempfile

    from agentforge.stores.ledger import EventLedger as _L
    from agentforge.stores.ledger import EventType, WriterNotAuthorized

    with tempfile.TemporaryDirectory() as d:
        ledger = _L(Path(d) / "l.db")
        try:
            ledger.append(agent="web", event_type=EventType.AUTH_ACCESS, run_id="r", payload={})
            with pytest.raises(WriterNotAuthorized):
                ledger.append(agent="web", event_type=EventType.VERDICT_RECORDED,
                              run_id="r", payload={})
        finally:
            ledger.close()


async def test_one_sign_in_control_and_no_dead_buttons(web_app: Any) -> None:
    """Two competing 'Log in with OpenEMR' buttons both pointing at a broken IdP made the page
    read as broken. One control in the header; the findings panel gets a quiet inline link."""
    async with _client(web_app) as c:
        page = (await c.get("/")).text
    assert page.count("class='toggle primary'") == 1          # exactly one header control
    assert "Log in with OpenEMR" not in page                  # the choice lives on the sign-in page
    assert "Sign in to view" in page                          # quiet inline link instead
    assert page.count("/login/token") >= 1


async def test_sign_in_page_offers_both_routes_sso_first(web_app: Any) -> None:
    async with _client(web_app) as c:
        page = (await c.get("/login/token")).text
    assert page.index("Log in with OpenEMR") < page.index("Sign in with token")
    assert "audit ledger" in page


async def test_callback_failure_is_a_clean_notice_not_a_raw_error(
        web_app: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """A reviewer must never meet a bare 400 body or a stack trace, and the identity provider's
    internal reason must never reach the browser."""
    async with _client(web_app) as c:
        r = await c.get("/callback?error=access_denied&state=x")
    assert r.status_code == 400
    assert "isn't available yet" in r.text
    assert "Traceback" not in r.text
    # A working alternative is offered, since one exists on this deployment.
    assert "/login/token" in r.text


# --- findings 11 and 12 from docs/SCAN_TRIAGE.md, actually fixed ------------------------------
async def test_security_headers_are_set(web_app: Any) -> None:
    """The page is self-contained, so the strictest CSP costs nothing. frame-ancestors matters
    most: a security console that can be framed can be clickjacked into triggering a run."""
    async with _client(web_app) as c:
        r = await c.get("/")
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "max-age=" in r.headers["strict-transport-security"]  # base_url is https


async def test_unhandled_errors_do_not_leak_internals(
        web_app: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """An error body is an information-disclosure surface: this service's exceptions can name
    internal paths, the identity provider, and the target under test."""
    def boom() -> dict[str, Any]:
        raise RuntimeError("internal detail /srv/secret/path leaked here")

    monkeypatch.setattr(web_app, "_dashboard_data", boom)
    async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=web_app.app, raise_app_exceptions=False),
            base_url="https://af.test") as c:
        r = await c.get("/")
    assert r.status_code == 500
    assert "Something went wrong" in r.text
    assert "/srv/secret/path" not in r.text
    assert "Traceback" not in r.text


async def test_sso_records_the_verified_identity_on_both_outcomes(
        web_app: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Deny-by-default RBAC has a bootstrapping problem: the allow-list must contain a value nobody
    can know until a real login produces it. So the resolved identity is recorded whether the
    operator was admitted or refused — an audit trail that keeps every rejection and loses every
    success is backwards, and it would also make the allow-list impossible to populate.
    """
    import dataclasses

    from agentforge.auth.session import OperatorSession
    from agentforge.stores.ledger import EventLedger, EventType

    monkeypatch.setattr(web_app, "_settings",
                        dataclasses.replace(web_app._settings, data_dir=tmp_path / "d"))
    op = OperatorSession(subject="a2348815-c7ae-4eea-bb78-34517eef9cee", name="Administrator",
                         email="admin@example.test", fhir_user="Practitioner/a2348815")

    class _Req:
        headers: ClassVar[dict[str, str]] = {}
        client = None

    for outcome in ("granted", "rbac_denied"):
        web_app._audit_auth("sso_callback", outcome, _Req(), subject=op.subject[:64],
                            email=(op.email or "")[:64], fhir_user=(op.fhir_user or "")[:96])

    ledger = EventLedger(tmp_path / "d" / "ledger.db")
    try:
        events = ledger.events(event_type=EventType.AUTH_ACCESS)
    finally:
        ledger.close()
    by_outcome = {e["payload"]["outcome"]: e["payload"] for e in events}
    assert {"granted", "rbac_denied"} <= set(by_outcome)
    for payload in by_outcome.values():
        assert payload["subject"] == op.subject      # the value the allow-list needs
        assert payload["email"] == op.email


# --- post-disclosure: the read gate opens, the mutating one does not --------------------------
# The target was decommissioned and every finding is fixed, so the reports are published and the
# deployment sets AGENTFORGE_PUBLIC_REPORTS. What matters is that this opens *reads only* and
# stays reversible, so both properties are pinned here rather than assumed.
@pytest.fixture()
def public_app(web_app: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("AGENTFORGE_PUBLIC_REPORTS", "1")
    return web_app


async def test_public_mode_serves_the_report(public_app: Any) -> None:
    async with _client(public_app) as c:
        r = await c.get("/reports/ea8fa01.md")
    assert r.status_code == 200
    assert "GET /week2/documents" in r.text


async def test_public_mode_publishes_findings_and_says_so(public_app: Any) -> None:
    async with _client(public_app) as c:
        r = await c.get("/api/dashboard")
    body = r.json()
    assert body["detail_gated"] is False          # stated, not implied by a missing key
    assert [f["id"] for f in body["findings"]] == ["v1", "v2"]
    assert body["totals"]["pass_rate"] == 0.979   # posture is unchanged by the mode


async def test_public_mode_still_refuses_the_run_trigger(public_app: Any) -> None:
    """The load-bearing one: opening disclosure must not open a mutating action."""
    async with _client(public_app) as c:
        r = await c.post("/api/run/data_exfiltration")
    assert r.status_code == 401


async def test_public_mode_still_blocks_path_traversal(public_app: Any) -> None:
    async with _client(public_app) as c:
        r = await c.get("/reports/..%2f..%2fetc%2fpasswd")
    assert r.status_code == 404


async def test_public_mode_offers_no_sign_in_that_cannot_work(public_app: Any) -> None:
    """The IdP was decommissioned with the target; signing in would also unlock nothing."""
    async with _client(public_app) as c:
        r = await c.get("/")
    assert r.status_code == 200
    assert "Sign in" not in r.text
    assert "/login" not in r.text


async def test_public_mode_explains_why_the_detail_is_readable(public_app: Any) -> None:
    """Exploit steps on a public dashboard read as a leak unless the page says otherwise."""
    async with _client(public_app) as c:
        r = await c.get("/")
    assert "Why this is readable" in r.text
    assert "decommissioned" in r.text


async def test_removing_the_flag_restores_the_gate(web_app: Any,
                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-gating a redeployment is one environment variable, not a revert."""
    monkeypatch.setenv("AGENTFORGE_PUBLIC_REPORTS", "1")
    async with _client(web_app) as c:
        assert (await c.get("/reports/ea8fa01.md")).status_code == 200
    monkeypatch.delenv("AGENTFORGE_PUBLIC_REPORTS")
    async with _client(web_app) as c:
        r = await c.get("/reports/ea8fa01.md")
        assert r.status_code == 403
        assert (await c.get("/api/dashboard")).json()["detail_gated"] is True
    assert _TECHNIQUE not in r.text


async def test_only_explicit_truthy_values_open_the_gate(web_app: Any,
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    """An unset-but-present variable ("", "0", "false") must not be read as consent."""
    for value in ("", "0", "false", "no", "off"):
        monkeypatch.setenv("AGENTFORGE_PUBLIC_REPORTS", value)
        async with _client(web_app) as c:
            assert (await c.get("/reports/ea8fa01.md")).status_code == 403, value
