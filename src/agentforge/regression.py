"""Deterministic regression & validation harness (DIRECTION §3.5, §12 F7).

A confirmed exploit becomes a replayable case. On every target-version change the harness
re-runs it and asserts the **security property** (patient B's DOB absent), never a bare 200 — a
test that greens because the model rephrased is "worse than no test." The harness is fully
deterministic (no LLM): it re-executes the recorded attack and checks the check-pack's
forbid/require assertions against fresh evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentforge.agents.judge import Judge
from agentforge.agents.redteam import RedTeamAgent
from agentforge.contracts.models import AttackAttempt, Campaign, VerdictLabel


@dataclass
class RegressionResult:
    attempt_id: str
    seed_id: str | None
    passed: bool               # True = the vuln did NOT reproduce (defense held)
    reproduced: bool           # True = the exploit came back (a regression)
    security_property: str     # the assertion checked
    evidence: list[str]
    target_version: str


class RegressionHarness:
    def __init__(self, redteam: RedTeamAgent, judge: Judge) -> None:
        self._rt = redteam
        self._judge = judge

    async def replay(self, attempt: AttackAttempt, campaign: Campaign,
                     target_version: str) -> RegressionResult:
        """Re-execute a confirmed exploit against the current target; assert it can't reproduce."""
        fresh = attempt.model_copy(update={"target_version": target_version, "observed": []})
        executed = await self._rt.execute(fresh, campaign)
        verdict = await self._judge.judge(executed)
        reproduced = verdict.label == VerdictLabel.EXPLOITED
        return RegressionResult(
            attempt_id=attempt.id,
            seed_id=attempt.seed_id,
            passed=not reproduced,
            reproduced=reproduced,
            security_property=attempt.expected_safe.description,
            evidence=verdict.evidence,
            target_version=target_version,
        )

    async def replay_all(self, attempts: list[AttackAttempt], campaign: Campaign,
                         target_version: str) -> list[RegressionResult]:
        return [await self.replay(a, campaign, target_version) for a in attempts]
