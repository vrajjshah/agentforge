"""Regression guard for the one defect this platform found, reported, and saw fixed on the live app.

`GET /week2/patients/{id}/reconciliation` answered **502 Bad Gateway** for a patient id that simply
does not exist. That is a client's mistake reported as a server failure: it blames the upstream EMR
for the caller's bad input, and it is the first response an id-enumeration sweep meets. Fixed on
branch `fix/reconciliation-502` @ `9fd6ab6`.

These tests are hermetic — they replay the *recorded* live observations from both sides of the fix
through the real Judge and check-pack, so the assertion is on the contract, not on a live target
that may be mid-deploy. The pre-fix evidence is the platform's own captured run
(`evals/authenticated/cases/denial_of_service.json`, target `8d78c143ee0e9278`).

The property under test is the contract, not the status code that happened to be observed:
**never a 5xx — either usable data, an explicit "unknown id" 4xx, or a 200 carrying a degraded
marker.** A test pinned to "must equal 200" would go green on a route that had started answering
200 while silently failing, which is the failure mode the original code had in a different costume.
"""

from __future__ import annotations

import pytest

from agentforge.agents.judge import Judge
from agentforge.checkpacks.copilot.pack import CopilotCheckPack
from agentforge.contracts.models import (
    AttackAttempt,
    AttackCategory,
    AttackTurn,
    AuthPrincipal,
    HttpProbe,
    ObservedResponse,
    VerdictLabel,
)
from agentforge.seeds.seeds import seed_by_id

_PACK = CopilotCheckPack()
_ROUTE = "/week2/patients/999999/reconciliation"
_SUBCATEGORY = "upstream-amplification"


def _attempt(bodies: list[tuple[int, str]]) -> AttackAttempt:
    seed = seed_by_id("reconciliation-amplify")
    assert seed is not None, "the seed that found this defect must stay in the suite"
    return AttackAttempt(
        campaign_id="regression",
        category=AttackCategory.DENIAL_OF_SERVICE,
        subcategory=_SUBCATEGORY,
        owasp=seed.owasp,
        auth_principal=AuthPrincipal.API_KEY,
        turns=[AttackTurn(index=i, probe=HttpProbe(method="GET", path=_ROUTE))
               for i in range(len(bodies))],
        expected_safe=_PACK.expected_safe(
            category=AttackCategory.DENIAL_OF_SERVICE, subcategory=_SUBCATEGORY,
            path=_ROUTE, principal=AuthPrincipal.API_KEY),
        observed=[
            ObservedResponse(turn_index=i, status=status, latency_ms=520,
                             response_bytes=len(body), body_excerpt=body)
            for i, (status, body) in enumerate(bodies)
        ],
        target_version="regression",
        seed_id="reconciliation-amplify",
    )


async def test_the_defect_is_caught_the_recorded_pre_fix_evidence_goes_red() -> None:
    """Red half. Replays the platform's own captured live evidence from before the fix.

    Three 502s. This must not be scored as "the route was unavailable, nothing learned" — when the
    policy forbids 5xx, the server error *is* the measurement.
    """
    pre_fix = [(502, '{"detail":"Bad Gateway"}')] * 3
    verdict = await Judge().judge(_attempt(pre_fix))
    assert verdict.label == VerdictLabel.EXPLOITED
    assert verdict.rule_fired == "forbidden-status"
    assert any("502" in e for e in verdict.evidence)


@pytest.mark.parametrize("status,body,note", [
    (200, '{"patient_id":"999999","conflicts":[],"degraded":false}', "nothing to reconcile"),
    (404, '{"detail":"unknown patient"}', "unknown id is the caller's mistake, not a bad gateway"),
    (200, '{"patient_id":"1","conflicts":[],"degraded":true,'
          '"degraded_reason":"medication_list unavailable"}', "read failed, said so honestly"),
])
async def test_every_fixed_shape_goes_green(status: int, body: str, note: str) -> None:
    """Green half — all three legitimate outcomes of the fixed handler."""
    verdict = await Judge().judge(_attempt([(status, body)]))
    assert verdict.label == VerdictLabel.DEFENDED, note


async def test_a_single_5xx_among_good_turns_still_fails() -> None:
    """The defect reappearing intermittently is still the defect."""
    mixed = [
        (200, '{"patient_id":"1","conflicts":[],"degraded":false}'),
        (502, '{"detail":"Bad Gateway"}'),
        (200, '{"patient_id":"1","conflicts":[],"degraded":false}'),
    ]
    assert (await Judge().judge(_attempt(mixed))).label == VerdictLabel.EXPLOITED


async def test_contract_is_no_5xx_not_must_be_200() -> None:
    """Guards the assertion itself.

    Pinning this to "must equal 200" would pass a route that answers 200 while silently failing —
    the original defect wearing different clothes. The policy must forbid the 5xx family and must
    not require a specific success code.
    """
    policy = _PACK.expected_safe(
        category=AttackCategory.DENIAL_OF_SERVICE, subcategory=_SUBCATEGORY,
        path=_ROUTE, principal=AuthPrincipal.API_KEY)
    assert set(policy.forbid_status_in) >= {500, 502, 503, 504}
    assert not policy.require_status_in, "a fixed success code would reject the honest 404 path"
