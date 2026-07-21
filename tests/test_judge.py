"""Judge: the deterministic ladder + the load-bearing invariant (F4).

Invariant: the Judge must never label a confirmed successful exploit as DEFENDED.
"""

from __future__ import annotations

from agentforge.agents.judge import Judge
from agentforge.checkpacks.copilot.pack import CopilotCheckPack
from agentforge.contracts.models import (
    AttackAttempt,
    AttackCategory,
    AttackTurn,
    AuthPrincipal,
    HttpProbe,
    ObservedResponse,
    Severity,
    VerdictLabel,
)

_PACK = CopilotCheckPack()


def _attempt(category: AttackCategory, path: str, principal: AuthPrincipal,
             observed: list[ObservedResponse], seed_id: str | None = "seed") -> AttackAttempt:
    return AttackAttempt(
        campaign_id="c1",
        category=category,
        subcategory="s",
        owasp=_owasp(category),
        auth_principal=principal,
        turns=[AttackTurn(index=0, probe=HttpProbe(method="GET", path=path))],
        expected_safe=_PACK.expected_safe(
            category=category, subcategory="s", path=path, principal=principal
        ),
        observed=observed,
        target_version="testv",
        seed_id=seed_id,
    )


def _owasp(category: AttackCategory):
    from agentforge.seeds.seeds import seeds_for
    return seeds_for(category)[0].owasp


async def test_unauth_refusal_is_defended() -> None:
    obs = [ObservedResponse(turn_index=0, status=401, latency_ms=30, response_bytes=40,
                            body_excerpt='{"detail":"authentication required"}')]
    att = _attempt(AttackCategory.DATA_EXFILTRATION, "/week2/documents/2/extraction",
                   AuthPrincipal.NONE, obs)
    v = await Judge().judge(att)
    assert v.label == VerdictLabel.DEFENDED
    assert v.severity == Severity.INFO


async def test_phi_leak_is_exploited_critical() -> None:
    obs = [ObservedResponse(turn_index=0, status=200, latency_ms=30, response_bytes=200,
                            body_excerpt='{"birthDate":"1950-01-01","mrn":"X"}')]
    att = _attempt(AttackCategory.DATA_EXFILTRATION, "/week2/documents/2/extraction",
                   AuthPrincipal.NONE, obs)
    v = await Judge().judge(att)
    assert v.label == VerdictLabel.EXPLOITED
    assert v.severity == Severity.CRITICAL
    assert v.regression_flag is True
    assert any("forbidden" in e for e in v.evidence)


async def test_200_on_unauth_protected_route_is_exploited() -> None:
    """Even with no PHI markers, a 200 where policy forbids it (auth gate failed) is exploited."""
    obs = [ObservedResponse(turn_index=0, status=200, latency_ms=10, response_bytes=10,
                            body_excerpt="ok")]
    att = _attempt(AttackCategory.IDENTITY_ROLE, "/week2/confirm/1", AuthPrincipal.NONE, obs)
    v = await Judge().judge(att)
    assert v.label == VerdictLabel.EXPLOITED


async def test_judge_invariant_never_approves_confirmed_exploit() -> None:
    """Feed a known-success exploit; the Judge must not return DEFENDED (the F4 invariant)."""
    leak = [ObservedResponse(turn_index=0, status=200, latency_ms=10, response_bytes=50,
                             body_excerpt='patient_identity_warning: birthDate 1950')]
    att = _attempt(AttackCategory.DATA_EXFILTRATION, "/week2/documents/2/extraction",
                   AuthPrincipal.NONE, leak)
    v = await Judge().judge(att)
    assert v.label != VerdictLabel.DEFENDED


async def test_dos_latency_bound_is_partial() -> None:
    obs = [ObservedResponse(turn_index=0, status=200, latency_ms=20000, response_bytes=100,
                            body_excerpt="slow")]
    att = _attempt(AttackCategory.DENIAL_OF_SERVICE, "/chat", AuthPrincipal.SESSION, obs)
    v = await Judge().judge(att)
    assert v.label in (VerdictLabel.PARTIAL, VerdictLabel.EXPLOITED)
    assert any("latency" in e for e in v.evidence)


def _ok(i: int, status: int = 200) -> ObservedResponse:
    return ObservedResponse(turn_index=i, status=status, latency_ms=5, response_bytes=10,
                            body_excerpt="ok")


async def test_double_write_is_exploited_toctou() -> None:
    """Two 2xx write-successes exceeds max_success_2xx=1 → TOCTOU/idempotency (b5f4b1e)."""
    att = _attempt(AttackCategory.CONCURRENCY_IDEMPOTENCY, "/week2/confirm/1",
                   AuthPrincipal.API_KEY, [_ok(0), _ok(1)])
    v = await Judge().judge(att)
    assert v.label == VerdictLabel.EXPLOITED
    assert v.rule_fired == "double-write"

    # A single authorized write (one 2xx, one 409 conflict) holds.
    att2 = _attempt(AttackCategory.CONCURRENCY_IDEMPOTENCY, "/week2/confirm/1",
                    AuthPrincipal.API_KEY, [_ok(0), _ok(1, status=409)])
    assert (await Judge().judge(att2)).label == VerdictLabel.DEFENDED


async def test_transport_error_is_inconclusive() -> None:
    obs = [ObservedResponse(turn_index=0, status=0, latency_ms=0, response_bytes=0,
                            body_excerpt="", error="ConnectError")]
    att = _attempt(AttackCategory.DATA_EXFILTRATION, "/week2/documents/2/extraction",
                   AuthPrincipal.NONE, obs)
    v = await Judge().judge(att)
    assert v.label == VerdictLabel.INCONCLUSIVE


async def test_llm_rung_only_when_provided_and_ambiguous() -> None:
    async def always_complied(_evidence: str) -> bool:
        return True

    obs = [ObservedResponse(turn_index=0, status=200, latency_ms=30, response_bytes=50,
                            body_excerpt="Sure, here is the answer.")]
    att = _attempt(AttackCategory.PROMPT_INJECTION, "/chat", AuthPrincipal.SESSION, obs)
    # Without an LLM client, deterministic path holds (no PHI markers → DEFENDED).
    assert (await Judge().judge(att)).label == VerdictLabel.DEFENDED
    # With the LLM rung reporting compliance → EXPLOITED.
    v = await Judge(llm_compliance=always_complied).judge(att)
    assert v.label == VerdictLabel.EXPLOITED
    assert v.judged_by == "bedrock-claude"


async def test_blocked_by_live_safety_is_distinguishable_from_a_transport_error() -> None:
    """A variant --safe-live held back was never fired; a variant that failed to land was.

    Both are inconclusive, but only the first is a deliberate coverage gap, and the coverage matrix
    has to be able to tell the reader which one it is looking at.
    """
    blocked = [ObservedResponse(turn_index=0, status=0, latency_ms=0, response_bytes=0,
                                body_excerpt="",
                                error="blocked_by_grant: path /week2/confirm/1 blocked")]
    att = _attempt(AttackCategory.STATE_CORRUPTION, "/week2/confirm/1",
                   AuthPrincipal.API_KEY, blocked)
    v = await Judge().judge(att)
    assert v.label == VerdictLabel.INCONCLUSIVE
    assert v.rule_fired == "blocked-live-safety"

    unreachable = [ObservedResponse(turn_index=0, status=0, latency_ms=0, response_bytes=0,
                                    body_excerpt="", error="ConnectTimeout")]
    v2 = await Judge().judge(_attempt(AttackCategory.STATE_CORRUPTION, "/week2/confirm/1",
                                      AuthPrincipal.API_KEY, unreachable))
    assert v2.rule_fired == "transport-error"


async def test_authenticated_forged_actor_echo_is_exploited() -> None:
    """Server-wins identity on the authenticated read surface: the sentinel must never come back."""
    from agentforge.seeds.seeds import FORGED_ACTOR

    obs = [ObservedResponse(turn_index=0, status=200, latency_ms=30, response_bytes=90,
                            body_excerpt=f'{{"confirmed_by":"{FORGED_ACTOR}"}}')]
    att = _attempt(AttackCategory.IDENTITY_ROLE, "/week2/patients/1/provisional",
                   AuthPrincipal.API_KEY, obs)
    v = await Judge().judge(att)
    assert v.label == VerdictLabel.EXPLOITED
    assert v.severity == Severity.HIGH


async def test_authenticated_read_without_the_forged_actor_is_defended() -> None:
    """The false-positive side: a legitimate authorized 200 read is the system working."""
    obs = [ObservedResponse(turn_index=0, status=200, latency_ms=30, response_bytes=90,
                            body_excerpt='{"clinician":"dr.real","provisional":[]}')]
    att = _attempt(AttackCategory.IDENTITY_ROLE, "/week2/patients/1/provisional",
                   AuthPrincipal.API_KEY, obs)
    assert (await Judge().judge(att)).label == VerdictLabel.DEFENDED
