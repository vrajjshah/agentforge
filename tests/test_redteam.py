"""Red Team: generation, live execution via the adapter, and capability-grant enforcement (F2)."""

from __future__ import annotations

import httpx
import pytest
import respx

from agentforge.adapters.copilot import CopilotAdapter
from agentforge.agents.redteam import CapabilityViolation, RedTeamAgent
from agentforge.checkpacks.copilot.pack import CopilotCheckPack
from agentforge.contracts.models import (
    AttackCategory,
    AttackTurn,
    AuthPrincipal,
    Campaign,
    HttpProbe,
)
from agentforge.mutation.engine import MutationEngine


def _campaign(**kw: object) -> Campaign:
    base: dict[str, object] = dict(
        name="exfil", category=AttackCategory.DATA_EXFILTRATION, target_id="copilot",
        auth_principals=[AuthPrincipal.NONE], max_attempts=6,
    )
    base.update(kw)
    return Campaign(**base)  # type: ignore[arg-type]


def _agent(adapter: CopilotAdapter) -> RedTeamAgent:
    return RedTeamAgent(adapter=adapter, checkpack=CopilotCheckPack(), engine=MutationEngine())


def test_generate_builds_attempts_with_policy_oracle(adapter: CopilotAdapter) -> None:
    attempts = _agent(adapter).generate(_campaign(), "testv")
    assert attempts
    a = attempts[0]
    assert a.category == AttackCategory.DATA_EXFILTRATION
    assert a.expected_safe.source.startswith("checkpack:copilot")  # oracle from the pack, not RT
    assert a.target_version == "testv"


def test_capability_grant_blocks_ungranted_method(adapter: CopilotAdapter) -> None:
    agent = _agent(adapter)
    camp = _campaign(allowed_methods=["POST"])  # GET not granted
    turn = AttackTurn(index=0, probe=HttpProbe(method="GET", path="/week2/documents/2/extraction"))
    with pytest.raises(CapabilityViolation):
        agent._check_grant(camp, turn)


@respx.mock
async def test_run_executes_live_and_fills_evidence(adapter: CopilotAdapter) -> None:
    respx.route(host="target.test").mock(
        return_value=httpx.Response(401, json={"detail": "authentication required"})
    )
    attempts = await _agent(adapter).run(_campaign(max_attempts=3), "testv")
    assert attempts
    for a in attempts:
        assert a.observed, "every executed attempt must carry evidence"
        assert a.observed[0].status == 401


async def test_execute_marks_principal_unavailable(adapter: CopilotAdapter) -> None:
    """API-key principal with no key → recorded, not crashed (honest degradation)."""
    agent = _agent(adapter)
    camp = _campaign(auth_principals=[AuthPrincipal.API_KEY])
    attempts = agent.generate(camp, "testv")
    if not attempts:
        pytest.skip("no api_key-applicable seeds in this campaign")
    executed = await agent.execute(attempts[0], camp)
    assert executed.observed[0].error == "principal_unavailable"
