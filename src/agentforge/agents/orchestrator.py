"""The Orchestrator — strategy (DIRECTION §3.1, §12 F8/F11).

Mostly deterministic (Aaron: don't give a node an LLM if it doesn't need one): pick the
least-covered surface, meter cost, and HALT when spend accrues without new signal (the
circuit breaker as a first-class state). Read-only on the stores; it triggers runs but never
writes findings. The one genuinely strategic call (given these open highs + this regression,
what's the highest-value next campaign) is where an LLM would earn its place — stubbed
deterministically for the MVP.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agentforge.contracts.models import AttackAttempt, AttackCategory, Verdict, VerdictLabel
from agentforge.cost_model import COST_HTTP_ONLY, COST_JUDGE_CALL, COST_TARGET_TURN

# Honest cost model (see cost_model.py): a live turn that reaches the target's model pays for
# inference; a request rejected at the auth gate never reaches the model, so it costs only HTTP.
COST_TARGET_MODEL_TURN = COST_TARGET_TURN
COST_JUDGE_LLM = COST_JUDGE_CALL

_MODEL_ROUTES = ("/chat", "/week2/analyze", "/week2/retrieve", "/week2/documents")


def estimate_attempt_cost(attempt: AttackAttempt) -> float:
    cost = 0.0
    for turn, resp in zip(attempt.turns, attempt.observed, strict=False):
        reached_model = resp.status == 200 and any(
            turn.probe.path.startswith(r) for r in _MODEL_ROUTES
        )
        cost += COST_TARGET_MODEL_TURN if reached_model else COST_HTTP_ONLY
    return cost


def verdict_cost(verdict: Verdict) -> float:
    return COST_JUDGE_LLM if verdict.judged_by.startswith("bedrock") else 0.0


@dataclass
class CampaignBudget:
    budget_usd: float
    halt_after_no_signal: int
    cost_usd: float = 0.0
    attempts_since_signal: int = 0
    halted: bool = False
    halt_reason: str = ""
    coverage: dict[str, int] = field(default_factory=dict)  # subcategory -> count

    def record(self, attempt: AttackAttempt, verdict: Verdict) -> None:
        self.cost_usd += estimate_attempt_cost(attempt) + verdict_cost(verdict)
        self.coverage[attempt.subcategory] = self.coverage.get(attempt.subcategory, 0) + 1
        if verdict.label in (VerdictLabel.EXPLOITED, VerdictLabel.PARTIAL):
            self.attempts_since_signal = 0
        else:
            self.attempts_since_signal += 1

    def check_halt(self) -> bool:
        """Circuit breaker: halt on over-budget or no-signal (never decide blind)."""
        if self.cost_usd >= self.budget_usd:
            self.halted, self.halt_reason = True, "budget_exceeded"
        elif self.attempts_since_signal >= self.halt_after_no_signal:
            self.halted, self.halt_reason = True, "no_findings_in_window"
        return self.halted


class Orchestrator:
    """Deterministic strategy for the MVP: single-category campaigns, coverage-driven halt."""

    def least_covered(self, coverage: dict[str, int], candidates: list[str]) -> str | None:
        if not candidates:
            return None
        return min(candidates, key=lambda c: coverage.get(c, 0))

    def next_category(self, tested: set[AttackCategory]) -> AttackCategory | None:
        for c in AttackCategory:
            if c not in tested:
                return c
        return None
