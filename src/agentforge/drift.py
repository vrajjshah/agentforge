"""Judge drift detection on frozen, signed fixtures (DIRECTION §12 F6).

The Judge's ground truth is a set of **frozen recordings** (request + observed response + the
known-correct label) captured from BOTH a vulnerable and a fixed build — not attacks replayed
against a moving live target (which can't separate "judge drifted" from "app changed"). Every
session re-judges the fixtures; if the Judge misclassifies a golden, it has **drifted → the gate
alerts and blocks**. Each fixture is content-signed, so a tampered fixture is caught too.

Proof-of-firing: flip a fixture's expected label and watch the gate fire (`tests/test_drift.py`).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from agentforge.agents.judge import Judge
from agentforge.contracts.models import AttackAttempt, VerdictLabel


def _sign(attempt: AttackAttempt) -> str:
    return hashlib.sha256(attempt.model_dump_json().encode()).hexdigest()[:16]


@dataclass(frozen=True)
class DriftFixture:
    provenance: str            # e.g. "ea8fa01@vulnerable"
    attempt: AttackAttempt     # frozen recording (with observed responses)
    expected_label: VerdictLabel
    signature: str             # sha256 over the attempt at freeze time

    def to_json(self) -> str:
        return json.dumps({
            "provenance": self.provenance,
            "expected_label": self.expected_label.value,
            "signature": self.signature,
            "attempt": self.attempt.model_dump(mode="json"),
        }, indent=2)

    @classmethod
    def from_json(cls, text: str) -> DriftFixture:
        d = json.loads(text)
        return cls(
            provenance=d["provenance"],
            attempt=AttackAttempt.model_validate(d["attempt"]),
            expected_label=VerdictLabel(d["expected_label"]),
            signature=d["signature"],
        )

    @classmethod
    def freeze(cls, provenance: str, attempt: AttackAttempt,
               expected_label: VerdictLabel) -> DriftFixture:
        return cls(provenance, attempt, expected_label, _sign(attempt))


@dataclass(frozen=True)
class DriftResult:
    provenance: str
    expected: VerdictLabel
    actual: VerdictLabel
    tampered: bool
    drifted: bool


class DriftGate:
    """Re-judges frozen fixtures; a mismatch (or a tampered fixture) is drift → block."""

    async def check(self, judge: Judge,
                    fixtures: list[DriftFixture]) -> tuple[bool, list[DriftResult]]:
        results: list[DriftResult] = []
        blocked = False
        for f in fixtures:
            tampered = _sign(f.attempt) != f.signature
            verdict = await judge.judge(f.attempt)
            drifted = verdict.label != f.expected_label
            if tampered or drifted:
                blocked = True
            results.append(DriftResult(f.provenance, f.expected_label, verdict.label,
                                       tampered, drifted))
        return blocked, results


def load_fixtures(fixtures_dir: Path) -> list[DriftFixture]:
    return [DriftFixture.from_json(p.read_text())
            for p in sorted(fixtures_dir.glob("*.json"))]


async def build_drift_fixtures() -> list[DriftFixture]:
    """Capture golden recordings from the ephemeral vulnerable + fixed builds (deterministic,
    LLM-free): the same attacks the killer demo uses, with their known-correct labels."""
    import dataclasses

    import httpx

    from agentforge.adapters.copilot import CopilotAdapter
    from agentforge.agents.redteam import RedTeamAgent
    from agentforge.checkpacks.copilot.pack import CopilotCheckPack
    from agentforge.config import Settings
    from agentforge.contracts.models import AuthPrincipal, Campaign
    from agentforge.demo.vulnerable_target import build_target
    from agentforge.mutation.engine import MutationEngine

    settings = dataclasses.replace(Settings.from_env(load=False), target_url="http://demo.local")

    def rt(vulnerable: bool) -> RedTeamAgent:
        adapter = CopilotAdapter(settings, transport=httpx.ASGITransport(
            app=build_target(vulnerable=vulnerable)))
        return RedTeamAgent(adapter=adapter, checkpack=CopilotCheckPack(), engine=MutationEngine())

    specs = [("ea8fa01", AuthPrincipal.NONE), ("e0e7b6a", AuthPrincipal.NONE)]
    fixtures: list[DriftFixture] = []
    for vulnerable, label in ((True, VerdictLabel.EXPLOITED), (False, VerdictLabel.DEFENDED)):
        agent = rt(vulnerable)
        version = await agent.adapter.version()
        for seed_id, principal in specs:
            from agentforge.seeds.seeds import seed_by_id

            seed = seed_by_id(seed_id)
            if seed is None:
                continue
            camp = Campaign(name=f"fix-{seed_id}", category=seed.category, target_id="demo",
                            seed_ids=[seed_id], auth_principals=[principal], max_attempts=50)
            attempts = agent.generate(camp, version)
            canonical = next((a for a in attempts if a.mutator == seed_id), attempts[0])
            executed = await agent.execute(canonical, camp)
            tag = "vulnerable" if vulnerable else "fixed"
            fixtures.append(DriftFixture.freeze(f"{seed_id}@{tag}", executed, label))
    return fixtures
