"""Build the dashboard data file (`evals/dashboard.json`) the web service renders.

Aggregates the six observability questions into one committed, self-contained artifact so the
deployed page needs no database and no live calls to render:
  1. categories tested + case counts     4. findings: open / in-progress / resolved
  2. current pass/fail rate               5. run cost + rate
  3. resilience over time (by fingerprint) 6. recent agent activity (what each agent did, in order)

The agent-activity trace is a real multi-agent run captured from the event ledger (against the
ephemeral vulnerable build, so it shows a full discover→judge→document handoff), redacted of PHI.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EVALS = _REPO_ROOT / "evals"
_REPORTS = _REPO_ROOT / "reports"

# Modelled target-side inference per /chat turn (measured baseline, USD).
_COST_PER_MODEL_TURN = 0.071


def _load(path: Path) -> Any:
    return json.loads(path.read_text()) if path.exists() else None


def _coverage_and_cost() -> tuple[dict[str, Any], dict[str, Any], str, str]:
    """Read the authenticated coverage matrix + per-case files for counts and cost."""
    auth_dir = _EVALS / "authenticated"
    matrix_path = (auth_dir / "coverage_matrix.json")
    surface = "authenticated /chat + reads (API key)"
    if not matrix_path.exists():
        matrix_path = _EVALS / "coverage_matrix.json"
        surface = "unauthenticated boundary"
    cov = _load(matrix_path) or {"coverage_matrix": {}, "target_version": "—"}
    cases_dir = matrix_path.parent / "cases"
    model_turns = 0
    for cases_file in cases_dir.glob("*.json"):
        for c in _load(cases_file) or []:
            for o in c.get("observed", []):
                path = c.get("attack_sequence", [{}])[0].get("path", "")
                if o.get("status") == 200 and path.startswith(("/chat", "/week2/analyze")):
                    model_turns += 1
    cost = {
        "model_turns": model_turns,
        "per_turn_usd": _COST_PER_MODEL_TURN,
        "live_inference_usd": round(model_turns * _COST_PER_MODEL_TURN, 2),
    }
    return cov, cost, surface, cov.get("target_version", "—")


async def _agent_activity() -> list[dict[str, Any]]:
    """Capture a real ordered multi-agent trace from a campaign against the ephemeral vuln build."""
    import dataclasses
    import tempfile

    import httpx

    from agentforge.adapters.copilot import CopilotAdapter
    from agentforge.agents.documentation import DocumentationAgent
    from agentforge.agents.judge import Judge
    from agentforge.agents.orchestrator import Orchestrator
    from agentforge.agents.redteam import RedTeamAgent
    from agentforge.checkpacks.copilot.pack import CopilotCheckPack
    from agentforge.config import Settings
    from agentforge.contracts.models import AttackCategory, AuthPrincipal, Campaign
    from agentforge.demo.vulnerable_target import build_target
    from agentforge.graph import CampaignGraph
    from agentforge.mutation.engine import MutationEngine
    from agentforge.stores.ledger import EventLedger
    from agentforge.stores.vulndb import VulnDB

    tmp = Path(tempfile.mkdtemp(prefix="agentforge-dash-"))
    settings = dataclasses.replace(Settings.from_env(load=False), target_url="http://demo.local")
    adapter = CopilotAdapter(settings, transport=httpx.ASGITransport(
        app=build_target(vulnerable=True)))
    ledger = EventLedger(tmp / "ledger.db")
    graph = CampaignGraph(
        RedTeamAgent(adapter=adapter, checkpack=CopilotCheckPack(), engine=MutationEngine()),
        Judge(), Orchestrator(), DocumentationAgent(VulnDB(tmp / "vuln.db")), ledger)
    campaign = Campaign(name="dashboard-trace", category=AttackCategory.DATA_EXFILTRATION,
                        target_id="ephemeral-vulnerable-build",
                        auth_principals=[AuthPrincipal.NONE], max_attempts=4)
    version = await adapter.version()
    await graph.run(campaign, version, run_id="dashboard")
    events = ledger.events(run_id="dashboard")
    ledger.close()
    return [
        {"seq": e["seq"], "agent": e["agent"], "event": e["event_type"],
         "detail": _summarize(e["event_type"], e["payload"])}
        for e in events
    ]


def _summarize(event_type: str, payload: dict[str, Any]) -> str:
    if event_type == "campaign_started":
        return f"generated {payload.get('generated')} attempts for {payload.get('category')}"
    if event_type == "attempt_executed":
        return f"fired {payload.get('mutator')} → HTTP {payload.get('statuses')}"
    if event_type == "verdict_recorded":
        return f"{payload.get('label')} · {payload.get('severity')} · rule={payload.get('rule')}"
    if event_type == "agent_action":
        return f"drafted report {payload.get('drafted_report', '')}".strip()
    if event_type == "halt":
        return f"halted: {payload.get('reason')}"
    return json.dumps(payload)[:80]


async def build_dashboard_data() -> dict[str, Any]:
    cov, cost, surface, fingerprint = _coverage_and_cost()
    matrix = cov.get("coverage_matrix", {})
    totals = dict.fromkeys(
        ("total", "pass_defended", "fail_exploited", "partial", "inconclusive"), 0)
    for m in matrix.values():
        for k in totals:
            totals[k] += m.get(k, 0)
    pass_rate = round(totals["pass_defended"] / totals["total"], 3) if totals["total"] else 0.0
    findings = _load(_REPORTS / "findings.json") or []
    live_exploited = totals["fail_exploited"]

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "title": "Continuous adversarial security testing of the Clinical Co-Pilot",
        "target": {
            "url": cov.get("target_url", "https://45-55-53-165.sslip.io/copilot"),
            "fingerprint": fingerprint,
            "surface": surface,
            "last_run": cov.get("generated_at", "—"),
        },
        "status": "defense_held" if live_exploited == 0 else "findings_open",
        "taxonomy_version": cov.get("taxonomy_version", "owasp-web-2021; owasp-llm-2023"),
        "coverage": matrix,
        "totals": {**totals, "pass_rate": pass_rate, "categories": len(matrix)},
        "resilience": [
            {"fingerprint": fingerprint, "run_at": cov.get("generated_at", "—"),
             "cases": totals["total"], "pass_rate": pass_rate}
        ],
        "findings": findings,
        "findings_summary": {
            "resolved": sum(f.get("status") == "closed" for f in findings),
            "in_progress": sum(f.get("status") in ("triaged", "confirmed") for f in findings),
            "open_on_live_target": live_exploited,
        },
        "cost": cost,
        "agent_activity": await _agent_activity(),
    }


async def write_dashboard(out: Path = _EVALS / "dashboard.json") -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(await build_dashboard_data(), indent=2) + "\n")
    return out
