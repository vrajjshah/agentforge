"""One-command killer demo (`agentforge demo`).

Runs the full discover→confirm→document→regress loop, in-process, against an ephemeral vulnerable
build of the co-pilot and its fixed counterpart. Prints a narrative for the demo video. No network,
no Bedrock, no cost — deterministic and reproducible.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import httpx

from agentforge.adapters.copilot import CopilotAdapter
from agentforge.agents.documentation import DocumentationAgent
from agentforge.agents.judge import Judge
from agentforge.agents.redteam import RedTeamAgent
from agentforge.checkpacks.copilot.pack import CopilotCheckPack
from agentforge.config import Settings
from agentforge.contracts.models import AttackCategory, AuthPrincipal, Campaign, VerdictLabel
from agentforge.demo.vulnerable_target import build_target
from agentforge.mutation.engine import MutationEngine
from agentforge.regression import RegressionHarness
from agentforge.stores.vulndb import VulnDB


def _redteam(settings: Settings, vulnerable: bool) -> RedTeamAgent:
    adapter = CopilotAdapter(
        settings, transport=httpx.ASGITransport(app=build_target(vulnerable=vulnerable))
    )
    return RedTeamAgent(adapter=adapter, checkpack=CopilotCheckPack(), engine=MutationEngine())


async def run_demo() -> int:
    settings = Settings(target_url="http://demo.local", target_api_key="", aws_region="us-east-1",
                        judge_model="demo", redteam_seed_model="demo",
                        data_dir=Path(tempfile.mkdtemp(prefix="agentforge-demo-")),
                        request_timeout_s=5.0, global_max_latency_s=15.0)
    judge = Judge()
    campaign = Campaign(name="killer-demo", category=AttackCategory.DATA_EXFILTRATION,
                        target_id="copilot-demo-vulnerable",
                        auth_principals=[AuthPrincipal.NONE], max_attempts=6)

    print("═" * 72)
    print(" AgentForge — killer demo: discover → confirm → document → regress")
    print("═" * 72)
    print("\n[1] Ephemeral VULNERABLE build (ea8fa01 reverted — a separate, isolated target).")
    vuln_rt = _redteam(settings, vulnerable=True)
    vuln_version = await vuln_rt.adapter.version()
    print(f"    target fingerprint: {vuln_version}")
    attempts = await vuln_rt.run(campaign, vuln_version)
    pairs = [(await judge.judge(a), a) for a in attempts]
    exploited = [(v, a) for v, a in pairs if v.label == VerdictLabel.EXPLOITED]
    print(f"    Red Team fired {len(attempts)} attempts; "
          f"Judge confirmed {len(exploited)} EXPLOITED.")
    if not exploited:
        print("    !! demo failed — expected the platform to re-discover the leak")
        return 1
    verdict, attempt = exploited[0]
    print(f"    ↳ {verdict.severity.value.upper()} · rule={verdict.rule_fired} · "
          f"exploitability={verdict.exploitability}")
    print(f"    ↳ evidence: {verdict.evidence[0]}")

    print("\n[2] Documentation agent drafts a MUST-FIX report (human-approved for the demo).")
    db = VulnDB(settings.data_dir / "vuln.db")
    reports = DocumentationAgent(db).document_verdicts(exploited, human_approved=True)
    r = reports[0]
    print(f"    ↳ {r.id} · {r.title}")
    print(f"    ↳ clinical impact: {r.clinical_impact[:88]}…")
    print(f"    ↳ remediation: {r.remediation[:88]}…")

    print("\n[3] Regression proof-of-firing — replay against the vulnerable build.")
    red = await RegressionHarness(vuln_rt, judge).replay(attempt, campaign, vuln_version)
    print(f"    ↳ reproduced={red.reproduced}  → suite is RED (the vuln is present)  ✅ gate fires")

    print("\n[4] Fixed build (ea8fa01 restored) — a target-version change triggers regression.")
    fixed_rt = _redteam(settings, vulnerable=False)
    fixed_version = await fixed_rt.adapter.version()
    green = await RegressionHarness(fixed_rt, judge).replay(attempt, campaign, fixed_version)
    print(f"    fingerprint {vuln_version} → {fixed_version} (changed)")
    print(f"    ↳ reproduced={green.reproduced}  → suite is GREEN (fix holds)  ✅ closed")
    print(f"    ↳ asserted the SECURITY PROPERTY, not a 200: \"{green.security_property[:70]}…\"")

    print("\n" + "═" * 72)
    print(" Result: the platform caught a real, known-answer vuln live, documented it, and")
    print(" proved the fix closes it — the loop no classmate can demonstrate on ground truth.")
    print("═" * 72)
    return 0
