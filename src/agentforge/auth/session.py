"""Server-side operator sessions + in-flight auth-flow state.

The browser holds only an opaque, HttpOnly session cookie that indexes into ``SessionStore``; the
operator's identity claims and the short-lived PKCE/state secrets never leave the server. Both
stores are in-process TTL dicts with a narrow interface (the Redis swap at scale is a drop-in).
The auth-flow state is **single-use** — ``pop`` consumes it — so an intercepted ``state`` cannot be
replayed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class OperatorSession:
    """An authenticated dashboard operator, derived server-side from the verified id_token."""

    subject: str                 # the OIDC `sub` — the stable principal id
    name: str
    email: str | None
    fhir_user: str | None
    roles: tuple[str, ...] = ()


@dataclass
class AuthFlow:
    """In-flight authorization-code state, keyed by the OAuth ``state``. Single-use."""

    code_verifier: str
    nonce: str
    redirect_uri: str
    return_to: str = "/"
    created_at: float = field(default_factory=time.monotonic)


class _TtlStore:
    def __init__(self, ttl_seconds: float) -> None:
        self._ttl = ttl_seconds
        self._data: dict[str, tuple[float, object]] = {}

    def _now(self) -> float:
        return time.monotonic()

    def _set(self, key: str, value: object) -> None:
        self._data[key] = (self._now() + self._ttl, value)

    def _get(self, key: str) -> object | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if self._now() > expires_at:
            self._data.pop(key, None)
            return None
        return value

    def purge_expired(self) -> int:
        now = self._now()
        expired = [k for k, (exp, _) in self._data.items() if now > exp]
        for k in expired:
            self._data.pop(k, None)
        return len(expired)


class SessionStore(_TtlStore):
    """Operator sessions keyed by an opaque session id, with TTL (default 8h)."""

    def __init__(self, ttl_seconds: float = 28800.0) -> None:
        super().__init__(ttl_seconds)

    def get(self, session_id: str) -> OperatorSession | None:
        val = self._get(session_id)
        return val if isinstance(val, OperatorSession) else None

    def set(self, session_id: str, session: OperatorSession) -> None:
        self._set(session_id, session)

    def delete(self, session_id: str) -> None:
        self._data.pop(session_id, None)


class AuthFlowStore(_TtlStore):
    """Short-lived, single-use authorization-flow state keyed by ``state`` (default 10 min)."""

    def __init__(self, ttl_seconds: float = 600.0) -> None:
        super().__init__(ttl_seconds)

    def set(self, state: str, flow: AuthFlow) -> None:
        self._set(state, flow)

    def pop(self, state: str) -> AuthFlow | None:
        """Consume the flow for ``state`` (single-use; None if unknown/expired)."""
        entry = self._data.pop(state, None)
        if entry is None:
            return None
        expires_at, flow = entry
        if self._now() > expires_at or not isinstance(flow, AuthFlow):
            return None
        return flow
