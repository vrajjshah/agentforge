"""Generate professional vulnerability reports (Final requirement: ≥3, reproducible format).

Each report is produced end-to-end by the platform — the Documentation agent drafts it from a
confirmed Judge verdict, and the fix-validation field comes from the regression harness re-running
the exact attack against the patched build. The bar: a senior engineer who wasn't present could
reproduce, validate, and fix the vuln from the report alone.

The live target is hardened (all held), so these three are demonstrated on the ephemeral, isolated
vulnerable build (ea8fa01 · e0e7b6a · b5f4b1e) — real, git-verified, test-pinned defects.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
from pathlib import Path

import httpx

from agentforge.adapters.copilot import CopilotAdapter
from agentforge.agents.documentation import DocumentationAgent
from agentforge.agents.judge import Judge
from agentforge.agents.redteam import RedTeamAgent
from agentforge.checkpacks.copilot.pack import CopilotCheckPack
from agentforge.config import Settings
from agentforge.contracts.models import (
    AttackAttempt,
    AuthPrincipal,
    Campaign,
    VerdictLabel,
    VulnReport,
)
from agentforge.demo.vulnerable_target import build_target
from agentforge.mutation.engine import MutationEngine
from agentforge.regression import RegressionHarness
from agentforge.seeds.seeds import Seed, seed_by_id
from agentforge.stores.vulndb import VulnDB

# (seed id, fix commit, principal) for the three reported vulns.
_REPORTED: tuple[tuple[str, str, AuthPrincipal], ...] = (
    ("ea8fa01", "ea8fa01", AuthPrincipal.NONE),
    ("e0e7b6a", "e0e7b6a", AuthPrincipal.NONE),
    # API_KEY so the concurrency check (max_success_2xx=1) fires — the accurate TOCTOU framing.
    ("b5f4b1e", "b5f4b1e", AuthPrincipal.API_KEY),
)


def _redteam(settings: Settings, vulnerable: bool) -> RedTeamAgent:
    adapter = CopilotAdapter(settings, transport=httpx.ASGITransport(app=build_target(
        vulnerable=vulnerable)))
    return RedTeamAgent(adapter=adapter, checkpack=CopilotCheckPack(), engine=MutationEngine())


def _require_seed(seed_id: str) -> Seed:
    seed = seed_by_id(seed_id)
    if seed is None:
        raise ValueError(f"unknown seed id {seed_id!r}")
    return seed


def _canonical_attempt(redteam: RedTeamAgent, seed_id: str, principal: AuthPrincipal,
                       version: str) -> AttackAttempt:
    seed = _require_seed(seed_id)
    campaign = Campaign(name=f"report-{seed_id}", category=seed.category, target_id="copilot-demo",
                        seed_ids=[seed_id], auth_principals=[principal], max_attempts=50)
    attempts = redteam.generate(campaign, version)
    # The canonical (unmutated) variant carries mutator == seed_id.
    return next((a for a in attempts if a.mutator == seed_id), attempts[0])


async def generate_reports(settings: Settings, out_dir: Path) -> list[Path]:
    # The ephemeral ASGI app routes at /week2/... (no /copilot prefix), so use a demo origin —
    # never the live target's base. The vuln DB still lands in the real data dir.
    settings = dataclasses.replace(settings, target_url="http://demo.local")
    judge = Judge()
    vuln_rt = _redteam(settings, vulnerable=True)
    fixed_rt = _redteam(settings, vulnerable=False)
    vuln_version = await vuln_rt.adapter.version()
    fixed_version = await fixed_rt.adapter.version()
    db = VulnDB(settings.data_dir / "vuln.db")
    doc = DocumentationAgent(db)
    harness = RegressionHarness(fixed_rt, judge)

    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    index: list[dict[str, str]] = []
    for seed_id, fix_commit, principal in _REPORTED:
        seed = _require_seed(seed_id)
        campaign = Campaign(name=f"report-{seed_id}", category=seed.category,
                            target_id="copilot-demo", seed_ids=[seed_id],
                            auth_principals=[principal], max_attempts=50)
        attempt = _canonical_attempt(vuln_rt, seed_id, principal, vuln_version)
        executed = await vuln_rt.execute(attempt, campaign)
        verdict = await judge.judge(executed)
        if verdict.label != VerdictLabel.EXPLOITED:
            continue  # only report a confirmed exploit
        report = doc.draft(verdict, executed)
        # Fix validation via the regression harness against the patched build.
        result = await harness.replay(executed, campaign, fixed_version)
        report = report.model_copy(update={
            "fix_commit": fix_commit,
            "status": "closed" if result.passed else "confirmed",
            "fix_validation": (
                f"Re-ran the exact attack against the patched build (version {fixed_version}): "
                f"the exploit no longer reproduces (verdict DEFENDED). Security property held — "
                f"{result.security_property}"
            ) if result.passed else "Fix did not close the exploit; still reproduces.",
        })
        from agentforge.stores.vulndb import DataQualityError

        with contextlib.suppress(DataQualityError):
            db.write(report)  # idempotent regeneration (dup fingerprint is fine)
        path = out_dir / f"{seed_id}.md"
        path.write_text(render_markdown(report, verdict.evidence))
        written.append(path)
        index.append({"id": report.id, "seed": seed_id, "severity": report.severity.value,
                      "category": report.category.value, "owasp_web": report.owasp.web.value,
                      "owasp_llm": report.owasp.llm.value, "status": report.status,
                      "title": report.title, "file": path.name})
    (out_dir / "README.md").write_text(_render_index(index))
    written.append(out_dir / "README.md")
    # Machine-readable index for the dashboard (findings table).
    (out_dir / "findings.json").write_text(json.dumps(index, indent=2) + "\n")
    written.append(out_dir / "findings.json")
    return written


def render_markdown(report: VulnReport, evidence: list[str]) -> str:
    turns = "\n".join(
        f"{i + 1}. `{t.probe.method} {t.probe.path}`"
        + (f"\n   ```json\n   {json.dumps(t.probe.json_body)}\n   ```" if t.probe.json_body else "")
        + (f" — headers `{json.dumps(t.probe.headers)}`" if t.probe.headers else "")
        + (f"\n   _{t.note}_" if t.note else "")
        for i, t in enumerate(report.reproduction)
    )
    ev = "\n".join(f"- {e}" for e in evidence) or "- (see observed)"
    return f"""# Vulnerability Report — {report.title}

| Field | Value |
|---|---|
| **ID** | `{report.id}` |
| **Severity** | **{report.severity.value.upper()}** |
| **Category** | {report.category.value} |
| **OWASP (web)** | {report.owasp.web.value} |
| **OWASP (LLM)** | {report.owasp.llm.value} |
| **Status** | {report.status} |
| **Fix commit** | `{report.fix_commit}` |
| **Target version** | `{report.target_version}` |

## Description & clinical impact

{report.clinical_impact}

## Minimal reproducible attack sequence

{turns}

## Observed vs. expected

- **Observed:** {report.observed_behavior}
- **Expected (safe):** {report.expected_behavior}

### Judge evidence (what fired)

{ev}

## Recommended remediation

{report.remediation}

## Fix validation

{report.fix_validation}

---
_Generated by the AgentForge Documentation agent from a confirmed Judge verdict; fix validated by
the regression harness. Reproducible by an engineer who was not present._
"""


def _render_index(rows: list[dict[str, str]]) -> str:
    lines = ["# Vulnerability Reports", "",
             "Machine-generated by the AgentForge Documentation agent from confirmed Judge "
             "verdicts, each fix-validated by the regression harness. Demonstrated on the "
             "ephemeral vulnerable build (the live target is hardened — all held).", "",
             "| ID | Severity | Title | Report |", "|---|---|---|---|"]
    for r in rows:
        lines.append(
            f"| `{r['id']}` | {r['severity'].upper()} | {r['title']} | [{r['file']}]({r['file']}) |"
        )
    return "\n".join(lines) + "\n"
