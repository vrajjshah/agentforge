"""End-to-end multi-agent loop (hermetic) + the circuit-breaker halt (F8)."""

from __future__ import annotations

from pathlib import Path

import httpx
import respx

from agentforge.adapters.copilot import CopilotAdapter
from agentforge.agents.documentation import DocumentationAgent
from agentforge.agents.judge import Judge
from agentforge.agents.orchestrator import CampaignBudget, Orchestrator, estimate_attempt_cost
from agentforge.agents.redteam import RedTeamAgent
from agentforge.checkpacks.copilot.pack import CopilotCheckPack
from agentforge.contracts.models import (
    AttackAttempt,
    AttackCategory,
    AttackTurn,
    AuthPrincipal,
    Campaign,
    HttpProbe,
    ObservedResponse,
    OwaspLlm,
    OwaspMapping,
    OwaspWeb,
    Severity,
    Verdict,
    VerdictLabel,
)
from agentforge.graph import CampaignGraph
from agentforge.mutation.engine import MutationEngine
from agentforge.stores.ledger import EventLedger, EventType
from agentforge.stores.vulndb import VulnDB


def _graph(adapter: CopilotAdapter, tmp_path: Path) -> tuple[CampaignGraph, EventLedger, VulnDB]:
    ledger = EventLedger(tmp_path / "ledger.db")
    db = VulnDB(tmp_path / "vuln.db")
    rt = RedTeamAgent(adapter=adapter, checkpack=CopilotCheckPack(), engine=MutationEngine())
    graph = CampaignGraph(rt, Judge(), Orchestrator(), DocumentationAgent(db), ledger)
    return graph, ledger, db


@respx.mock
async def test_full_loop_defense_holds(adapter: CopilotAdapter, tmp_path: Path) -> None:
    """A hardened target returns 401 → the loop runs all four agents and finds no vuln."""
    respx.route(host="target.test").mock(
        return_value=httpx.Response(401, json={"detail": "authentication required"})
    )
    graph, ledger, _db = _graph(adapter, tmp_path)
    camp = Campaign(name="exfil", category=AttackCategory.DATA_EXFILTRATION,
                    target_id="copilot", max_attempts=4)
    result = await graph.run(camp, "testv", run_id="run1")
    assert result["done"] is True
    assert result["verdicts"], "judge produced verdicts"
    assert all(v.label == VerdictLabel.DEFENDED for v in result["verdicts"])
    # the event ledger recorded the multi-agent hops
    kinds = {e["event_type"] for e in ledger.events(run_id="run1")}
    assert EventType.ATTEMPT_EXECUTED.value in kinds
    assert EventType.VERDICT_RECORDED.value in kinds


@respx.mock
async def test_full_loop_detects_leak_and_drafts_report(
    adapter: CopilotAdapter, tmp_path: Path
) -> None:
    """A vulnerable target (200 + PHI marker) → Judge flags EXPLOITED, Documentation drafts."""
    respx.route(host="target.test").mock(
        return_value=httpx.Response(200, json={"birthDate": "1950-01-01", "mrn": "X"})
    )
    graph, _ledger, db = _graph(adapter, tmp_path)
    camp = Campaign(name="exfil", category=AttackCategory.DATA_EXFILTRATION,
                    target_id="copilot", max_attempts=3)
    result = await graph.run(camp, "vulnv", run_id="run2")
    assert any(v.label == VerdictLabel.EXPLOITED for v in result["verdicts"])
    assert result["reports"], "documentation drafted at least one report"
    # CRITICAL data-exfil reports are NOT auto-filed (human gate) — DB stays empty.
    assert db.all() == []


def test_circuit_breaker_halts_on_no_signal() -> None:
    budget = CampaignBudget(budget_usd=100.0, halt_after_no_signal=3)
    attempt = AttackAttempt(
        campaign_id="c", category=AttackCategory.DATA_EXFILTRATION, subcategory="s",
        owasp=OwaspMapping(web=OwaspWeb.A01, llm=OwaspLlm.LLM06), auth_principal=AuthPrincipal.NONE,
        turns=[AttackTurn(index=0, probe=HttpProbe(method="GET", path="/x"))],
        expected_safe=CopilotCheckPack().expected_safe(
            category=AttackCategory.DATA_EXFILTRATION, subcategory="s", path="/x",
            principal=AuthPrincipal.NONE),
        observed=[ObservedResponse(turn_index=0, status=401, latency_ms=1, response_bytes=1,
                                   body_excerpt="")],
        target_version="v")
    safe = Verdict(attempt_id="a", campaign_id="c", label=VerdictLabel.DEFENDED,
                   severity=Severity.INFO, owasp=attempt.owasp, target_version="v")
    for _ in range(3):
        budget.record(attempt, safe)
    assert budget.check_halt() is True
    assert budget.halt_reason == "no_findings_in_window"


def test_cost_model_charges_model_turns_only() -> None:
    """A 401 at the auth gate is HTTP-only; a 200 on /chat pays target-side inference (F8)."""
    def attempt_with(path: str, status: int) -> AttackAttempt:
        return AttackAttempt(
            campaign_id="c", category=AttackCategory.PROMPT_INJECTION, subcategory="s",
            owasp=OwaspMapping(web=OwaspWeb.A03, llm=OwaspLlm.LLM01),
            auth_principal=AuthPrincipal.SESSION,
            turns=[AttackTurn(index=0, probe=HttpProbe(method="POST", path=path))],
            expected_safe=CopilotCheckPack().expected_safe(
                category=AttackCategory.PROMPT_INJECTION, subcategory="s", path=path,
                principal=AuthPrincipal.SESSION),
            observed=[ObservedResponse(turn_index=0, status=status, latency_ms=1,
                                       response_bytes=1, body_excerpt="")],
            target_version="v")
    assert estimate_attempt_cost(attempt_with("/chat", 200)) > 0.05      # paid model turn
    assert estimate_attempt_cost(attempt_with("/week2/x", 401)) < 0.001  # HTTP only
