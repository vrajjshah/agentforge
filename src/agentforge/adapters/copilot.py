"""``CopilotAdapter`` — the first target adapter: the deployed Clinical Co-Pilot.

Target-specific knowledge (routes, auth modes, the fingerprint recipe) belongs *here*.
What counts as a successful exploit does NOT — that lives in ``checkpacks/copilot`` behind
this boundary, so the platform core stays domain-agnostic (DIRECTION §12 F9, F2).
"""

from __future__ import annotations

import hashlib
import time
from urllib.parse import urljoin, urlparse

import httpx

from agentforge.config import Settings
from agentforge.contracts.models import AuthPrincipal, HttpProbe, ObservedResponse

from .base import (
    AdapterIdentity,
    AllowListViolation,
    AuthContext,
    Capability,
    PrincipalUnavailable,
    TargetAdapter,
)

# The verified Week-2 route map (W2-SYSTEM-UNDER-TEST §1), paths relative to the /copilot base.
_CAPABILITIES: tuple[Capability, ...] = (
    Capability("GET", "/health", "liveness", requires_auth=False),
    Capability("GET", "/", "UI root", requires_auth=False),
    Capability("GET", "/session", "SMART session state", requires_auth=False),
    Capability("GET", "/ready", "readiness (reads only)", requires_auth=False),
    Capability("GET", "/patients", "patient roster"),
    Capability("POST", "/chat", "the agent — direct/indirect/multi-turn injection surface"),
    Capability("POST", "/week2/upload", "file ingest — the untrusted-input boundary"),
    Capability("POST", "/week2/documents/{id}/process", "VLM extraction trigger"),
    Capability("GET", "/week2/documents/{id}/extraction", "document-keyed read (ea8fa01 class)"),
    Capability("GET", "/week2/documents/{id}/page/{page}", "document-keyed page read"),
    Capability("GET", "/week2/patients/{id}/provisional", "provisional facts"),
    Capability("GET", "/week2/patients/{id}/trends/{test}", "lab trends"),
    Capability("GET", "/week2/patients/{id}/reconciliation", "med reconciliation"),
    Capability("POST", "/week2/retrieve", "RAG entry"),
    Capability("POST", "/week2/analyze", "agent entry"),
    Capability("PATCH", "/week2/provisional/{id}", "clinician edit"),
    Capability("POST", "/week2/confirm/{id}", "the only chart write"),
    Capability("POST", "/week2/reject/{id}", "reject a provisional fact"),
    Capability("POST", "/week2/reopen/{id}", "reopen a rejected fact"),
)

_SESSION_COOKIE_NAME = "copilot_session"


class CopilotAdapter(TargetAdapter):
    def __init__(self, settings: Settings, session_cookie: str | None = None) -> None:
        self._settings = settings
        self._base = settings.target_url
        self._origin = settings.target_origin
        # A SMART session cookie may be injected (e.g. captured via the browser launch flow).
        self._session_cookie = session_cookie

    @property
    def identity(self) -> AdapterIdentity:
        return AdapterIdentity(name="openemr-clinical-copilot", base_url=self._base,
                               origin=self._origin)

    def capabilities(self) -> list[Capability]:
        return list(_CAPABILITIES)

    def authenticate(self, principal: AuthPrincipal) -> AuthContext:
        if principal == AuthPrincipal.NONE:
            return AuthContext(principal=principal)
        if principal == AuthPrincipal.API_KEY:
            if not self._settings.target_api_key:
                raise PrincipalUnavailable(
                    "API-key principal has no key configured "
                    "(AGENTFORGE_TARGET_API_KEY); optional for the MVP."
                )
            return AuthContext(principal, headers={"X-API-Key": self._settings.target_api_key})
        if principal == AuthPrincipal.SESSION:
            if not self._session_cookie:
                raise PrincipalUnavailable(
                    "SESSION principal has no cookie; obtain one via the SMART launch flow."
                )
            return AuthContext(principal, cookies={_SESSION_COOKIE_NAME: self._session_cookie})
        raise PrincipalUnavailable(f"unknown principal {principal!r}")

    def _resolve_url(self, path: str) -> str:
        # Join relative to the /copilot base, then enforce the immutable allow-list (F2).
        url = path if path.startswith("http") else urljoin(self._base + "/", path.lstrip("/"))
        if not _same_origin(url, self._origin):
            raise AllowListViolation(
                f"probe target {url!r} is outside the allow-listed origin {self._origin!r}"
            )
        return url

    async def invoke(self, probe: HttpProbe, auth: AuthContext) -> ObservedResponse:
        url = self._resolve_url(probe.path)
        headers = {**auth.headers, **probe.headers}
        started = time.monotonic()
        try:
            async with httpx.AsyncClient(
                timeout=self._settings.request_timeout_s,
                follow_redirects=False,  # a cross-host redirect must never be followed (F2)
                cookies=auth.cookies,
            ) as client:
                resp = await client.request(
                    probe.method.upper(), url,
                    headers=headers, json=probe.json_body, params=probe.query or None,
                )
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            elapsed = int((time.monotonic() - started) * 1000)
            return ObservedResponse(
                turn_index=0, status=0, latency_ms=elapsed, response_bytes=0,
                body_excerpt="", tool_calls=[], error=f"{type(exc).__name__}: {exc}",
            )
        elapsed = int((time.monotonic() - started) * 1000)
        body = resp.content
        return ObservedResponse(
            turn_index=0,
            status=resp.status_code,
            latency_ms=elapsed,
            response_bytes=len(body),
            body_excerpt=self.evidence_excerpt(body),
            tool_calls=_extract_tool_calls(resp),
        )

    async def version(self) -> str:
        """Fingerprint = sha256 over stable unauth surface (build changes → hash changes)."""
        parts: list[bytes] = []
        async with httpx.AsyncClient(timeout=self._settings.request_timeout_s,
                                     follow_redirects=False) as client:
            for path in ("/health", "/", "/session"):
                try:
                    r = await client.get(self._resolve_url(path))
                    parts.append(str(r.status_code).encode())
                    parts.append(r.content)
                    parts.append(r.headers.get("etag", "").encode())
                except (httpx.TimeoutException, httpx.TransportError):
                    parts.append(b"<unreachable>")
        return hashlib.sha256(b"|".join(parts)).hexdigest()[:16]

    async def health(self) -> tuple[bool, str]:
        try:
            async with httpx.AsyncClient(timeout=self._settings.request_timeout_s) as client:
                r = await client.get(self._resolve_url("/health"))
            return r.status_code == 200, f"HTTP {r.status_code}"
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            return False, f"{type(exc).__name__}: {exc}"

    async def reset(self) -> bool:
        # The shared live target is never reset by the platform (blast radius). Documented no-op;
        # the ephemeral vulnerable demo build overrides this.
        return False

    def evidence_excerpt(self, body: bytes, limit: int = 2000) -> str:
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover - decode never raises with errors="replace"
            text = repr(body[:limit])
        return text[:limit]


def _same_origin(url: str, origin: str) -> bool:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}" == origin


def _extract_tool_calls(resp: httpx.Response) -> list[str]:
    """Best-effort tool-call extraction from a chat response (excessive-agency evidence)."""
    if "application/json" not in resp.headers.get("content-type", ""):
        return []
    try:
        data = resp.json()
    except ValueError:
        return []
    calls: list[str] = []
    if isinstance(data, dict):
        for key in ("tool_calls", "tools_used", "actions"):
            val = data.get(key)
            if isinstance(val, list):
                calls.extend(str(v) for v in val)
    return calls
