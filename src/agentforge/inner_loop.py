"""Inner-loop eval — testing the tester (predicted-vs-actual finding productivity).

An adversarial platform is only trustworthy if its *own* verdicts are accurate, so we evaluate the
platform against known ground truth: each seeded defect is run against a build where it is present
(prediction: EXPLOITED) and a build where it is fixed (prediction: DEFENDED). Comparing the
platform's verdict to that prediction yields a confusion matrix and precision/recall/accuracy — the
platform's finding productivity, measured, not asserted. It also reports attack **diversity** (how
many distinct mutation families each seed produced), a proxy for "does the Red Team generate novel
attacks rather than one payload."
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from agentforge.adapters.copilot import CopilotAdapter
from agentforge.agents.judge import Judge
from agentforge.agents.redteam import RedTeamAgent
from agentforge.checkpacks.copilot.pack import CopilotCheckPack
from agentforge.config import Settings
from agentforge.contracts.models import AuthPrincipal, Campaign, VerdictLabel
from agentforge.demo.vulnerable_target import build_target
from agentforge.mutation.engine import MutationEngine
from agentforge.seeds.seeds import seed_by_id

# Seeds the ephemeral build reproduces, with the principal that triggers them.
_GROUND_TRUTH: tuple[tuple[str, AuthPrincipal], ...] = (
    ("ea8fa01", AuthPrincipal.NONE),
    ("e0e7b6a", AuthPrincipal.NONE),
    ("b5f4b1e", AuthPrincipal.API_KEY),
)
_VARIANTS_PER_SEED = 4


@dataclass
class InnerLoopResult:
    cases: list[dict[str, Any]] = field(default_factory=list)
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return round(self.tp / (self.tp + self.fp), 3) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return round(self.tp / (self.tp + self.fn), 3) if (self.tp + self.fn) else 1.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.tn + self.fp + self.fn
        return round((self.tp + self.tn) / total, 3) if total else 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "confusion": {"tp": self.tp, "tn": self.tn, "fp": self.fp, "fn": self.fn},
            "precision": self.precision, "recall": self.recall, "accuracy": self.accuracy,
            "cases": self.cases,
        }


def _redteam(settings: Settings, vulnerable: bool) -> RedTeamAgent:
    adapter = CopilotAdapter(settings, transport=httpx.ASGITransport(
        app=build_target(vulnerable=vulnerable)))
    return RedTeamAgent(adapter=adapter, checkpack=CopilotCheckPack(), engine=MutationEngine())


async def _detected(rt: RedTeamAgent, judge: Judge, seed_id: str,
                    principal: AuthPrincipal, version: str) -> tuple[bool, int]:
    """Run the canonical attack + a few variants; return (any-exploited, distinct-mutator-count)."""
    seed = seed_by_id(seed_id)
    if seed is None:
        raise ValueError(f"unknown seed id {seed_id!r}")
    campaign = Campaign(name=f"inner-{seed_id}", category=seed.category, target_id="demo",
                        seed_ids=[seed_id], auth_principals=[principal],
                        max_attempts=_VARIANTS_PER_SEED)
    attempts = rt.generate(campaign, version)
    exploited = False
    mutators: set[str] = set()
    for attempt in attempts:
        mutators.add(attempt.mutator.split("|", 1)[-1])
        executed = await rt.execute(attempt, campaign)
        verdict = await judge.judge(executed)
        if verdict.label == VerdictLabel.EXPLOITED:
            exploited = True
    return exploited, len(mutators)


async def run_inner_loop() -> InnerLoopResult:
    settings = dataclasses.replace(
        Settings.from_env(load=False), target_url="http://demo.local", target_api_key="inner-key")
    judge = Judge()
    vuln_rt = _redteam(settings, vulnerable=True)
    fixed_rt = _redteam(settings, vulnerable=False)
    vuln_v = await vuln_rt.adapter.version()
    fixed_v = await fixed_rt.adapter.version()

    result = InnerLoopResult()
    for seed_id, principal in _GROUND_TRUTH:
        # Present build → prediction EXPLOITED.
        caught, diversity = await _detected(vuln_rt, judge, seed_id, principal, vuln_v)
        if caught:
            result.tp += 1
        else:
            result.fn += 1
        result.cases.append({"seed": seed_id, "build": "vulnerable", "predicted": "exploited",
                             "actual": "exploited" if caught else "defended",
                             "correct": caught, "mutation_families": diversity})
        # Fixed build → prediction DEFENDED.
        flagged, _ = await _detected(fixed_rt, judge, seed_id, principal, fixed_v)
        if flagged:
            result.fp += 1
        else:
            result.tn += 1
        result.cases.append({"seed": seed_id, "build": "fixed", "predicted": "defended",
                             "actual": "exploited" if flagged else "defended",
                             "correct": not flagged, "mutation_families": diversity})
    return result


async def write_inner_loop(out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps((await run_inner_loop()).to_dict(), indent=2) + "\n")
    return out
