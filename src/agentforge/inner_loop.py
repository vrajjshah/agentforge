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

# Seeds the ephemeral build reproduces, with the principal that triggers them. Four categories
# across five seeds; every pair is run against both builds.
#
# Membership is deliberately limited to seeds whose *fix* the ephemeral build actually models.
# 7fbf995 (audit-record overwrite) is excluded: the build models the overwrite but not the route's
# authentication, so its "fixed" side would be scored against a policy the build never claimed to
# satisfy — an inflated error rate is as dishonest as an inflated score.
_GROUND_TRUTH: tuple[tuple[str, AuthPrincipal], ...] = (
    ("ea8fa01", AuthPrincipal.NONE),                 # data_exfiltration — document-keyed IDOR
    ("ea8fa01-page", AuthPrincipal.NONE),            # data_exfiltration — page-keyed IDOR
    ("e0e7b6a", AuthPrincipal.NONE),                 # identity_role — attribution forgery
    ("stored-payload-reason", AuthPrincipal.API_KEY),  # state_corruption — stored payload
    ("b5f4b1e", AuthPrincipal.API_KEY),              # concurrency — TOCTOU double-confirm
)
_VARIANTS_PER_SEED = 4

# What this number does and does not mean — carried into the JSON so the dashboard, the docs, and
# a reviewer all read the same caveat rather than an unqualified "1.0".
_INTERPRETATION = (
    "Ground truth here is deterministic and exact by construction: each seed is run against a "
    "build where the defect is present and one where it is fixed, and the oracle is the check-pack "
    "policy, not a model. A perfect score is therefore a wiring proof — the harness fires, the "
    "oracle is independent of the attacker, and the ladder decides — not evidence of semantic "
    "accuracy. The rung that can genuinely be wrong is the LLM compliance check, which is "
    "calibrated separately against human labels (evals/judge_calibration/)."
)


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
            "ground_truth": "deterministic (exact by construction)",
            "scope": "deterministic rungs of the Judge ladder; the LLM rung is scored separately",
            "interpretation": _INTERPRETATION,
            "confusion": {"tp": self.tp, "tn": self.tn, "fp": self.fp, "fn": self.fn},
            "precision": self.precision, "recall": self.recall, "accuracy": self.accuracy,
            "cases": self.cases,
        }


def _redteam(settings: Settings, vulnerable: bool) -> RedTeamAgent:
    adapter = CopilotAdapter(settings, transport=httpx.ASGITransport(
        app=build_target(vulnerable=vulnerable)))
    return RedTeamAgent(adapter=adapter, checkpack=CopilotCheckPack(), engine=MutationEngine())


async def _detected(settings: Settings, judge: Judge, seed_id: str,
                    principal: AuthPrincipal, vulnerable: bool) -> tuple[bool, int]:
    """Run the canonical attack + a few variants; return (any-exploited, distinct-mutator-count).

    Each variant executes against a **freshly built** ephemeral app. Several seeds exercise
    stateful write routes, and a variant that only passes because a previous variant already
    consumed the idempotency slot is measuring leftover state, not the defect.
    """
    seed = seed_by_id(seed_id)
    if seed is None:
        raise ValueError(f"unknown seed id {seed_id!r}")
    campaign = Campaign(name=f"inner-{seed_id}", category=seed.category, target_id="demo",
                        seed_ids=[seed_id], auth_principals=[principal],
                        max_attempts=_VARIANTS_PER_SEED)
    generator = _redteam(settings, vulnerable)
    version = await generator.adapter.version()
    attempts = generator.generate(campaign, version)   # generation is deterministic
    exploited = False
    mutators: set[str] = set()
    for attempt in attempts:
        mutators.add(attempt.mutator.split("|", 1)[-1])
        rt = _redteam(settings, vulnerable)
        executed = await rt.execute(attempt, campaign)
        verdict = await judge.judge(executed)
        if verdict.label == VerdictLabel.EXPLOITED:
            exploited = True
    return exploited, len(mutators)


async def run_inner_loop() -> InnerLoopResult:
    settings = dataclasses.replace(
        Settings.from_env(load=False), target_url="http://demo.local", target_api_key="inner-key")
    judge = Judge()

    result = InnerLoopResult()
    for seed_id, principal in _GROUND_TRUTH:
        # Present build → prediction EXPLOITED.
        caught, diversity = await _detected(settings, judge, seed_id, principal, vulnerable=True)
        if caught:
            result.tp += 1
        else:
            result.fn += 1
        result.cases.append({"seed": seed_id, "build": "vulnerable", "predicted": "exploited",
                             "actual": "exploited" if caught else "defended",
                             "correct": caught, "mutation_families": diversity})
        # Fixed build → prediction DEFENDED.
        flagged, _ = await _detected(settings, judge, seed_id, principal, vulnerable=False)
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
