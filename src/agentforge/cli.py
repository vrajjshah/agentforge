"""AgentForge CLI — drive campaigns and (re)generate the eval dataset.

Live subcommands (``--live``) hit the real deployed target and cost real money/time; they are
opt-in and meant to be batched (never per-test). Hermetic runs judge the generated cases without
touching the network, so the dataset stays reproducible offline.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from agentforge.adapters.copilot import CopilotAdapter
from agentforge.agents.documentation import DocumentationAgent
from agentforge.agents.judge import Judge
from agentforge.agents.orchestrator import Orchestrator
from agentforge.agents.redteam import RedTeamAgent
from agentforge.checkpacks.copilot.pack import CopilotCheckPack
from agentforge.config import Settings
from agentforge.contracts.models import AttackCategory, AuthPrincipal, Campaign
from agentforge.evals import DEFAULT_CATEGORIES, EvalWriter, run_category
from agentforge.graph import CampaignGraph
from agentforge.mutation.engine import MutationEngine
from agentforge.stores.ledger import EventLedger
from agentforge.stores.vulndb import VulnDB

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _principals(spec: str) -> list[AuthPrincipal]:
    return [AuthPrincipal(p.strip()) for p in spec.split(",") if p.strip()]


def _build(settings: Settings, session_cookie: str | None = None) -> tuple[
    CopilotAdapter, RedTeamAgent, Judge, DocumentationAgent, EventLedger, VulnDB
]:
    adapter = CopilotAdapter(settings, session_cookie=session_cookie)
    ledger = EventLedger(settings.data_dir / "ledger.db")
    db = VulnDB(settings.data_dir / "vuln.db")
    judge = Judge()
    redteam = RedTeamAgent(adapter=adapter, checkpack=CopilotCheckPack(), engine=MutationEngine())
    return adapter, redteam, judge, DocumentationAgent(db), ledger, db


async def _cmd_health(settings: Settings) -> int:
    adapter = CopilotAdapter(settings)
    ok, detail = await adapter.health()
    version = await adapter.version() if ok else "unreachable"
    print(json.dumps({"target": settings.target_url, "healthy": ok, "detail": detail,
                      "fingerprint": version}, indent=2))
    return 0 if ok else 1


async def _cmd_probe_bedrock(settings: Settings) -> int:
    from agentforge.bedrock import probe_bedrock

    results = await probe_bedrock(settings)
    for r in results:
        print(f"{'✓' if r.reachable else '✗'} {r.model}: {r.detail}")
    return 0 if any(r.reachable for r in results) else 1


async def _cmd_run(settings: Settings, args: argparse.Namespace) -> int:
    adapter, redteam, judge, doc, ledger, _ = _build(settings)
    graph = CampaignGraph(redteam, judge, Orchestrator(), doc, ledger)
    version = await adapter.version() if args.live else "hermetic"
    campaign = Campaign(name=f"cli-{args.category}", category=AttackCategory(args.category),
                        target_id="copilot", auth_principals=_principals(args.principals),
                        max_attempts=args.max)
    if not args.live:
        print("(hermetic — pass --live to hit the deployed target)", file=sys.stderr)
    result = await graph.run(campaign, version, run_id=f"cli-{args.category}")
    labels: dict[str, int] = {}
    for v in result["verdicts"]:
        labels[v.label.value] = labels.get(v.label.value, 0) + 1
    print(json.dumps({
        "campaign": campaign.id, "category": args.category, "target_version": version,
        "attempts": len(result["verdicts"]), "verdicts": labels,
        "cost_usd_est": round(result["budget"].cost_usd, 4),
        "halt_reason": result["budget"].halt_reason or "queue_exhausted",
        "reports_drafted": len(result["reports"]),
    }, indent=2))
    ledger.close()
    return 0


async def _cmd_evals(settings: Settings, args: argparse.Namespace) -> int:
    adapter, redteam, judge, _, ledger, _ = _build(settings)
    if args.live:
        cookie = _maybe_session(adapter)
        if cookie:
            adapter = CopilotAdapter(settings, session_cookie=cookie)
            redteam = RedTeamAgent(adapter=adapter, checkpack=CopilotCheckPack(),
                                   engine=MutationEngine())
    version = await adapter.version() if args.live else "hermetic"
    categories = ([AttackCategory(c.strip()) for c in args.categories.split(",")]
                  if args.categories else list(DEFAULT_CATEGORIES))
    principals = _principals(args.principals)
    results_by_cat = {}
    for cat in categories:
        results_by_cat[cat] = await run_category(
            redteam, judge, cat, version, principals, args.max, args.live
        )
        print(f"  {cat.value}: {len(results_by_cat[cat])} cases", file=sys.stderr)
    writer = EvalWriter(_REPO_ROOT / "evals")
    summary = writer.write(results_by_cat, version)
    print(json.dumps(summary, indent=2))
    ledger.close()
    return 0


def _maybe_session(adapter: CopilotAdapter) -> str | None:
    import os

    return os.environ.get("AGENTFORGE_TARGET_SESSION_COOKIE") or None


def _cmd_export(_settings: Settings) -> int:
    from agentforge.contracts.export_schemas import export

    for p in export():
        print(f"wrote {p}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentforge", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("health", help="check the target is reachable + print its fingerprint")
    sub.add_parser("probe-bedrock", help="probe Judge + seed model reachability (build-time)")
    sub.add_parser("export-schemas", help="re-export the JSON Schema contracts")

    run = sub.add_parser("run", help="run one campaign through the multi-agent graph")
    run.add_argument("--category", required=True, choices=[c.value for c in AttackCategory])
    run.add_argument("--principals", default="none")
    run.add_argument("--max", type=int, default=20)
    run.add_argument("--live", action="store_true")

    ev = sub.add_parser("evals", help="(re)generate the ./evals/ dataset")
    ev.add_argument("--categories", default="")
    ev.add_argument("--principals", default="none")
    ev.add_argument("--max", type=int, default=12)
    ev.add_argument("--live", action="store_true")

    args = parser.parse_args(argv)
    settings = Settings.from_env()

    if args.cmd == "health":
        return asyncio.run(_cmd_health(settings))
    if args.cmd == "probe-bedrock":
        return asyncio.run(_cmd_probe_bedrock(settings))
    if args.cmd == "export-schemas":
        return _cmd_export(settings)
    if args.cmd == "run":
        return asyncio.run(_cmd_run(settings, args))
    if args.cmd == "evals":
        return asyncio.run(_cmd_evals(settings, args))
    parser.error(f"unknown command {args.cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
