"""Versioned inter-agent contracts (schema v1).

These Pydantic models are the *source of truth*; ``export_schemas.py`` renders them to
JSON Schema under ``/contracts/v1`` — the published, versioned peer-integration boundary
(DIRECTION §4, §12 F10). A breaking change bumps ``SCHEMA_VERSION`` and re-exports.

Design rules baked in:
- **F4 (Judge independence):** ``ExpectedSafe`` is the safety oracle and is sourced from the
  check-pack *policy*, never the Red Team. The Judge evaluates target evidence against it.
- **F3 (dual OWASP):** every attempt/verdict carries both ``owasp_web`` and ``owasp_llm``
  (a value or a justified ``n/a``), taxonomy-version stamped. Enforced by the data-quality gate.
- **F7 (regression provenance):** attempts carry the auth principal, target-version fingerprint,
  and a security-property assertion — never a bare status code.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1"


def _now() -> datetime:
    return datetime.now(UTC)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


class _Base(BaseModel):
    """Common config: reject unknown fields so a malformed message fails the contract test."""

    model_config = ConfigDict(extra="forbid", use_enum_values=False)


# --------------------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------------------
class AttackCategory(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    STATE_CORRUPTION = "state_corruption"
    TOOL_MISUSE = "tool_misuse"
    DENIAL_OF_SERVICE = "denial_of_service"
    IDENTITY_ROLE = "identity_role"
    CONCURRENCY_IDEMPOTENCY = "concurrency_idempotency"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VerdictLabel(StrEnum):
    """Attacker's-eye outcome. ``EXPLOITED`` = the attack worked (a vuln); ``DEFENDED`` = the
    defense held (safe). Maps to the assignment's success/fail/partial."""

    EXPLOITED = "exploited"
    DEFENDED = "defended"
    PARTIAL = "partial"
    INCONCLUSIVE = "inconclusive"


class AuthPrincipal(StrEnum):
    NONE = "none"          # unauthenticated external attacker
    SESSION = "session"    # SMART session (real clinician)
    API_KEY = "api_key"    # machine principal (X-API-Key)


class OwaspWeb(StrEnum):
    """OWASP Top 10 (web) — 2021 taxonomy."""

    A01 = "A01:2021-Broken-Access-Control"
    A02 = "A02:2021-Cryptographic-Failures"
    A03 = "A03:2021-Injection"
    A04 = "A04:2021-Insecure-Design"
    A05 = "A05:2021-Security-Misconfiguration"
    A06 = "A06:2021-Vulnerable-Components"
    A07 = "A07:2021-Auth-Failures"
    A08 = "A08:2021-Software-Data-Integrity-Failures"
    A09 = "A09:2021-Logging-Monitoring-Failures"
    A10 = "A10:2021-SSRF"
    NA = "n/a"


class OwaspLlm(StrEnum):
    """OWASP Top 10 for LLM Applications — 2023 taxonomy (per the assignment's naming order)."""

    LLM01 = "LLM01:2023-Prompt-Injection"
    LLM02 = "LLM02:2023-Insecure-Output-Handling"
    LLM03 = "LLM03:2023-Training-Data-Poisoning"
    LLM04 = "LLM04:2023-Model-Denial-of-Service"
    LLM05 = "LLM05:2023-Supply-Chain"
    LLM06 = "LLM06:2023-Sensitive-Information-Disclosure"
    LLM07 = "LLM07:2023-Insecure-Plugin-Design"
    LLM08 = "LLM08:2023-Excessive-Agency"
    LLM09 = "LLM09:2023-Overreliance"
    LLM10 = "LLM10:2023-Model-Theft"
    NA = "n/a"


class OwaspMapping(_Base):
    """Dual-taxonomy tag. The data-quality gate rejects a mapping where BOTH are ``n/a`` (F3)."""

    web: OwaspWeb
    llm: OwaspLlm
    taxonomy_version: str = "owasp-web-2021; owasp-llm-2023"
    justification: str = ""  # required (by the gate) when either side is n/a


# --------------------------------------------------------------------------------------
# Attack primitives
# --------------------------------------------------------------------------------------
class HttpProbe(_Base):
    """One HTTP request against the target, path relative to the target base URL."""

    method: str = "POST"
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    json_body: dict[str, object] | None = None
    query: dict[str, str] = Field(default_factory=dict)


class AttackTurn(_Base):
    index: int
    probe: HttpProbe
    note: str = ""  # what this turn tries (human-readable provenance)


class ExpectedSafe(_Base):
    """The safety oracle — from the check-pack policy, NEVER the Red Team (F4).

    All fields are *deterministic* assertions the Judge evaluates against target evidence.
    The security property is asserted here (patient B's DOB absent), not a bare 200 (F7).
    """

    description: str
    source: str  # provenance, e.g. "checkpack:copilot/access-control@v1"
    require_status_in: list[int] = Field(default_factory=list)   # e.g. [401, 403]
    forbid_status_in: list[int] = Field(default_factory=list)    # e.g. [200] on an unauth read
    forbid_substrings: list[str] = Field(default_factory=list)   # e.g. other patient's DOB/name
    require_substrings: list[str] = Field(default_factory=list)  # e.g. a refusal marker
    forbid_tool_calls: list[str] = Field(default_factory=list)
    max_latency_ms: int | None = None
    max_response_bytes: int | None = None


class ObservedResponse(_Base):
    turn_index: int
    status: int
    latency_ms: int
    response_bytes: int
    body_excerpt: str            # bounded; PHI stays out of the ledger (only in the vuln DB)
    tool_calls: list[str] = Field(default_factory=list)
    error: str | None = None     # transport error (unreachable/timeout) if the request never landed


# --------------------------------------------------------------------------------------
# Inter-agent messages
# --------------------------------------------------------------------------------------
class Campaign(_Base):
    """Orchestrator → Red Team. Carries the F2 per-campaign capability grant."""

    schema_version: str = SCHEMA_VERSION
    id: str = Field(default_factory=lambda: _new_id("camp"))
    name: str
    category: AttackCategory
    target_id: str
    target_version: str = ""              # filled by the adapter fingerprint at run start
    budget_usd: float = 1.0
    max_attempts: int = 50
    max_turns_per_attempt: int = 4
    # Capability grant (F2): the executor rejects any probe outside these.
    allowed_methods: list[str] = Field(default_factory=lambda: ["GET", "POST"])
    allowed_path_prefixes: list[str] = Field(default_factory=list)
    auth_principals: list[AuthPrincipal] = Field(default_factory=lambda: [AuthPrincipal.NONE])
    seed_ids: list[str] = Field(default_factory=list)
    halt_after_no_signal: int = 20        # circuit breaker: attempts w/o new signal before HALT
    created_at: datetime = Field(default_factory=_now)


class AttackAttempt(_Base):
    """Red Team → Judge. The generated attack + its observed target evidence."""

    schema_version: str = SCHEMA_VERSION
    id: str = Field(default_factory=lambda: _new_id("att"))
    campaign_id: str
    category: AttackCategory
    subcategory: str
    owasp: OwaspMapping
    auth_principal: AuthPrincipal
    turns: list[AttackTurn]
    expected_safe: ExpectedSafe
    observed: list[ObservedResponse] = Field(default_factory=list)
    target_version: str
    mutator: str = ""                     # how it was generated (seed id / mutation chain)
    seed_id: str | None = None
    created_at: datetime = Field(default_factory=_now)


class Verdict(_Base):
    """Judge → Orchestrator + Documentation."""

    schema_version: str = SCHEMA_VERSION
    id: str = Field(default_factory=lambda: _new_id("vrd"))
    attempt_id: str
    campaign_id: str
    label: VerdictLabel
    severity: Severity
    exploitability: str = "unknown"       # trivial | easy | moderate | hard | unknown
    evidence: list[str] = Field(default_factory=list)  # which assertions fired
    rule_fired: str = ""                  # the ladder rung that decided it
    confidence: float = 1.0
    regression_flag: bool = False
    owasp: OwaspMapping
    target_version: str
    judged_by: str = "deterministic:v1"   # or "bedrock-claude:<model>"
    created_at: datetime = Field(default_factory=_now)


class VulnReport(_Base):
    """Documentation → vuln DB (persistence write; behind the data-quality + human gate)."""

    schema_version: str = SCHEMA_VERSION
    id: str = Field(default_factory=lambda: _new_id("vuln"))
    title: str
    severity: Severity
    category: AttackCategory
    owasp: OwaspMapping
    clinical_impact: str
    reproduction: list[AttackTurn]
    observed_behavior: str
    expected_behavior: str
    remediation: str
    status: str = "confirmed"             # confirmed→triaged→…→closed (F1 lifecycle)
    fix_commit: str | None = None
    fix_validation: str = ""
    target_version: str
    created_at: datetime = Field(default_factory=_now)


ALL_CONTRACTS: tuple[type[_Base], ...] = (
    Campaign,
    AttackAttempt,
    Verdict,
    VulnReport,
)
