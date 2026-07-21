"""The ``TargetAdapter`` boundary (DIRECTION §12 F9).

The platform core talks to *any* system under test through this interface only. Clinical
success criteria never live here — they live in a pluggable check-pack keyed to the adapter.
A second "customer" needs only a new adapter + check-pack, proven by the conformance test.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from agentforge.contracts.models import AuthPrincipal, HttpProbe, ObservedResponse


@dataclass(frozen=True)
class AdapterIdentity:
    name: str
    base_url: str
    origin: str


@dataclass(frozen=True)
class Capability:
    """A route the target exposes — the map the Orchestrator explores for coverage."""

    method: str
    path: str
    note: str = ""
    requires_auth: bool = True


@dataclass(frozen=True)
class AuthContext:
    """Resolved credentials for one principal. Never logged."""

    principal: AuthPrincipal
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


class PrincipalUnavailable(RuntimeError):
    """Raised when a principal's credentials are not configured (e.g. no API key for MVP)."""


class AllowListViolation(RuntimeError):
    """Raised when a probe would leave the immutable target allow-list (F2)."""


class TargetAdapter(ABC):
    """Normalizing boundary between the platform and one deployed system under test."""

    @property
    @abstractmethod
    def identity(self) -> AdapterIdentity: ...

    @abstractmethod
    def capabilities(self) -> list[Capability]:
        """The routes/surfaces the target exposes (the coverage map)."""

    @abstractmethod
    def authenticate(self, principal: AuthPrincipal) -> AuthContext:
        """Resolve credentials for a principal, or raise ``PrincipalUnavailable``."""

    @abstractmethod
    async def invoke(self, probe: HttpProbe, auth: AuthContext) -> ObservedResponse:
        """Send one normalized attack request and return normalized evidence.

        Must enforce the allow-list: a probe whose resolved origin differs from the target
        origin raises ``AllowListViolation`` (never silently follows a cross-host redirect).
        """

    @abstractmethod
    async def version(self) -> str:
        """A content fingerprint of the deployed build, attached to every attempt/verdict."""

    @abstractmethod
    async def health(self) -> tuple[bool, str]:
        """(ok, detail) — is the target reachable and serving?"""

    @abstractmethod
    async def reset(self) -> bool:
        """Restore seeded state between runs so one run can't poison the next (F2d).

        For a shared live target this is a documented no-op returning ``False``; an ephemeral
        vulnerable build overrides it to actually restore.
        """

    @abstractmethod
    def evidence_excerpt(self, body: bytes, limit: int = 2000) -> str:
        """Normalize a raw response body into a bounded, PHI-disciplined excerpt."""
