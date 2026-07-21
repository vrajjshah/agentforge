"""The LangGraph campaign graph — a genuine multi-agent loop, not a pipeline.

Distinct agent nodes with distinct trust levels coordinate through shared state:

    orchestrate ──(halt?)──▶ END ──▶ document
        ▲                    │
        └──── judge ◀── redteam_execute

The Orchestrator routes and owns the circuit breaker; the Red Team executes one attempt against
the live target; the Judge evaluates it independently; on halt, the Documentation agent drafts
reports for confirmed exploits. Every hop is appended to the event ledger (F11).
"""

from __future__ import annotations

from typing import Annotated, Any, TypedDict

from langgraph.graph import END, StateGraph

from agentforge.agents.documentation import DocumentationAgent
from agentforge.agents.judge import Judge
from agentforge.agents.orchestrator import CampaignBudget, Orchestrator
from agentforge.agents.redteam import RedTeamAgent
from agentforge.contracts.models import AttackAttempt, Campaign, Verdict, VerdictLabel
from agentforge.stores.ledger import EventLedger, EventType


def _keep_last(_a: Any, b: Any) -> Any:
    return b


class CampaignState(TypedDict, total=False):
    campaign: Campaign
    target_version: str
    run_id: str
    queue: list[AttackAttempt]
    cursor: int
    executed: Annotated[list[AttackAttempt], _keep_last]
    verdicts: Annotated[list[Verdict], _keep_last]
    budget: CampaignBudget
    reports: list[dict[str, Any]]
    done: bool


class CampaignGraph:
    def __init__(self, redteam: RedTeamAgent, judge: Judge, orchestrator: Orchestrator,
                 documentation: DocumentationAgent, ledger: EventLedger) -> None:
        self._rt = redteam
        self._judge = judge
        self._orch = orchestrator
        self._doc = documentation
        self._ledger = ledger
        self._graph = self._build()

    def _build(self) -> Any:
        g = StateGraph(CampaignState)
        g.add_node("orchestrate", self._orchestrate)
        g.add_node("redteam_execute", self._redteam_execute)
        g.add_node("judge", self._judge_node)
        g.add_node("document", self._document)
        g.set_entry_point("orchestrate")
        g.add_conditional_edges(
            "orchestrate", self._route, {"attack": "redteam_execute", "halt": "document"}
        )
        g.add_edge("redteam_execute", "judge")
        g.add_edge("judge", "orchestrate")
        g.add_edge("document", END)
        return g.compile()

    async def run(self, campaign: Campaign, target_version: str, run_id: str) -> CampaignState:
        budget = CampaignBudget(
            budget_usd=campaign.budget_usd, halt_after_no_signal=campaign.halt_after_no_signal
        )
        state: CampaignState = {
            "campaign": campaign, "target_version": target_version, "run_id": run_id,
            "queue": [], "cursor": 0, "executed": [], "verdicts": [], "budget": budget,
            "reports": [], "done": False,
        }
        # recursion_limit bounds the loop (Aaron's circuit breaker as a hard graph limit).
        result: CampaignState = await self._graph.ainvoke(
            state, config={"recursion_limit": campaign.max_attempts * 3 + 10}
        )
        return result

    # --- nodes ---------------------------------------------------------------------------
    async def _orchestrate(self, state: CampaignState) -> dict[str, Any]:
        campaign = state["campaign"]
        if not state["queue"]:
            queue = self._rt.generate(campaign, state["target_version"])
            self._ledger.append(agent="orchestrator", event_type=EventType.CAMPAIGN_STARTED,
                                run_id=state["run_id"],
                                payload={"campaign": campaign.id,
                                         "category": campaign.category.value,
                                         "generated": len(queue)})
            return {"queue": queue}
        return {}

    def _route(self, state: CampaignState) -> str:
        budget = state["budget"]
        at_end = state["cursor"] >= len(state["queue"])
        if at_end or budget.check_halt():
            if budget.halted:
                self._ledger.append(agent="orchestrator", event_type=EventType.HALT,
                                    run_id=state["run_id"],
                                    payload={"reason": budget.halt_reason, "cost": budget.cost_usd})
            return "halt"
        return "attack"

    async def _redteam_execute(self, state: CampaignState) -> dict[str, Any]:
        campaign = state["campaign"]
        attempt = state["queue"][state["cursor"]]
        executed = await self._rt.execute(attempt, campaign)
        self._ledger.append(agent="redteam", event_type=EventType.ATTEMPT_EXECUTED,
                            run_id=state["run_id"],
                            payload={"attempt": executed.id, "mutator": executed.mutator,
                                     "principal": executed.auth_principal.value,
                                     "statuses": [r.status for r in executed.observed]})
        return {"executed": [*state["executed"], executed], "cursor": state["cursor"] + 1}

    async def _judge_node(self, state: CampaignState) -> dict[str, Any]:
        attempt = state["executed"][-1]
        verdict = await self._judge.judge(attempt)
        state["budget"].record(attempt, verdict)
        self._ledger.append(agent="judge", event_type=EventType.VERDICT_RECORDED,
                            run_id=state["run_id"],
                            payload={"attempt": attempt.id, "label": verdict.label.value,
                                     "severity": verdict.severity.value,
                                     "rule": verdict.rule_fired})
        return {"verdicts": [*state["verdicts"], verdict]}

    async def _document(self, state: CampaignState) -> dict[str, Any]:
        pairs = list(zip(state["verdicts"], state["executed"], strict=False))
        exploited = [(v, a) for v, a in pairs if v.label == VerdictLabel.EXPLOITED]
        reports = self._doc.document_verdicts(exploited, human_approved=False)
        for r in reports:
            self._ledger.append(agent="documentation", event_type=EventType.AGENT_ACTION,
                                run_id=state["run_id"],
                                payload={"drafted_report": r.id, "severity": r.severity.value})
        return {"reports": [r.model_dump(mode="json") for r in reports], "done": True}
