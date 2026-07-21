"""The killer demo, as a reproducible test (DIRECTION §8) + the regression proof-of-firing (F12).

Ground-truth validation: the platform re-discovers a real, known-answer vulnerability (`ea8fa01`)
live against an ephemeral vulnerable build, the Judge flags MUST-FIX, Documentation drafts the
report — then the regression harness goes RED on the vulnerable build and GREEN on the fixed one,
asserting the *security property* (patient B's DOB absent), not a bare status.
"""

from __future__ import annotations

from pathlib import Path

import httpx

from agentforge.adapters.copilot import CopilotAdapter
from agentforge.agents.documentation import DocumentationAgent
from agentforge.agents.judge import Judge
from agentforge.agents.redteam import RedTeamAgent
from agentforge.checkpacks.copilot.pack import CopilotCheckPack
from agentforge.config import Settings
from agentforge.contracts.models import (
    AttackCategory,
    AuthPrincipal,
    Campaign,
    Severity,
    VerdictLabel,
)
from agentforge.demo.vulnerable_target import build_target
from agentforge.mutation.engine import MutationEngine
from agentforge.regression import RegressionHarness
from agentforge.stores.vulndb import VulnDB


def _settings(tmp_path: Path) -> Settings:
    return Settings(target_url="http://demo.local", target_api_key="", aws_region="us-east-1",
                    judge_model="t", redteam_seed_model="t", data_dir=tmp_path / "d",
                    request_timeout_s=5.0, global_max_latency_s=15.0)


def _redteam(settings: Settings, app: object) -> RedTeamAgent:
    adapter = CopilotAdapter(settings, transport=httpx.ASGITransport(app=app))  # type: ignore[arg-type]
    return RedTeamAgent(adapter=adapter, checkpack=CopilotCheckPack(), engine=MutationEngine())


async def test_killer_demo_and_regression_proof_of_firing(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    judge = Judge()
    campaign = Campaign(name="demo", category=AttackCategory.DATA_EXFILTRATION,
                        target_id="copilot-demo", auth_principals=[AuthPrincipal.NONE],
                        max_attempts=6)

    # 1) Vulnerable build — the platform re-discovers the ea8fa01 leak, live.
    vuln_rt = _redteam(settings, build_target(vulnerable=True))
    vuln_version = await vuln_rt.adapter.version()
    attempts = await vuln_rt.run(campaign, vuln_version)
    pairs = [(await judge.judge(a), a) for a in attempts]
    exploited = [(v, a) for v, a in pairs if v.label == VerdictLabel.EXPLOITED]
    assert exploited, "platform must re-discover the ea8fa01 leak on the vulnerable build"
    verdict, attempt = exploited[0]
    assert verdict.severity == Severity.CRITICAL
    assert any("forbidden marker" in e for e in verdict.evidence)

    # 2) Documentation drafts a MUST-FIX report (human-approved here for the demo).
    db = VulnDB(tmp_path / "vuln.db")
    reports = DocumentationAgent(db).document_verdicts(exploited, human_approved=True)
    assert reports and reports[0].category == AttackCategory.DATA_EXFILTRATION
    assert db.get(reports[0].id) is not None

    # 3) Regression proof-of-firing — RED on the vulnerable build (the vuln reproduces).
    red = await RegressionHarness(vuln_rt, judge).replay(attempt, campaign, vuln_version)
    assert red.reproduced is True and red.passed is False

    # 4) Fixed build — the SAME attack cannot reproduce; the regression goes GREEN.
    fixed_rt = _redteam(settings, build_target(vulnerable=False))
    fixed_version = await fixed_rt.adapter.version()
    assert fixed_version != vuln_version  # a target-version change (what triggers regression)
    green = await RegressionHarness(fixed_rt, judge).replay(attempt, campaign, fixed_version)
    assert green.passed is True and green.reproduced is False
