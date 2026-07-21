"""Exploit detail is operator-only — the platform applies its own findings to itself.

The deployed demo runs with ``AGENTFORGE_SSO_REQUIRE=0`` so a reviewer can assess posture without
credentials. These tests pin the line between *posture* (public: pass rate, category and severity
counts, "defense held") and *reproduction* (gated: finding titles, which name the technique, and
the reports, which are working attack sequences against a clinical system).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

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
        operator_roles=("admin",), require_sso=False, cookie_secure=False))
    monkeypatch.setenv("AGENTFORGE_ADMIN_TOKEN", _TOKEN)
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
    assert "detail_gated" not in api.json()


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
