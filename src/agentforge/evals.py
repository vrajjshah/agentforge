"""The reproducible adversarial eval dataset (MVP hard gate: ./evals/, ≥3 dual-OWASP categories).

A *case* is a deterministic ``AttackAttempt`` (fixed-seed generation → byte-identical between
machines). A *result* adds the observed target evidence + the Judge verdict. Each record carries
the full F7 manifest: category+subcategory, the prompt/sequence, expected-safe, observed,
severity, exploitability, both OWASP tags (version-stamped), and the regression flag.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentforge.agents.judge import Judge
from agentforge.agents.redteam import RedTeamAgent
from agentforge.contracts.models import (
    AttackAttempt,
    AttackCategory,
    Campaign,
    Verdict,
    VerdictLabel,
)

DEFAULT_CATEGORIES: tuple[AttackCategory, ...] = (
    AttackCategory.DATA_EXFILTRATION,
    AttackCategory.IDENTITY_ROLE,
    AttackCategory.DENIAL_OF_SERVICE,
    AttackCategory.PROMPT_INJECTION,
    AttackCategory.STATE_CORRUPTION,
    AttackCategory.CONCURRENCY_IDEMPOTENCY,
)


@dataclass
class EvalResult:
    attempt: AttackAttempt
    verdict: Verdict

    def to_manifest(self) -> dict[str, Any]:
        a, v = self.attempt, self.verdict
        return {
            "id": a.id,
            "category": a.category.value,
            "subcategory": a.subcategory,
            "seed_id": a.seed_id,
            "mutator": a.mutator,
            "auth_principal": a.auth_principal.value,
            "owasp_web": a.owasp.web.value,
            "owasp_llm": a.owasp.llm.value,
            "owasp_taxonomy_version": a.owasp.taxonomy_version,
            "attack_sequence": [
                {"method": t.probe.method, "path": t.probe.path,
                 "body": t.probe.json_body, "headers": t.probe.headers, "note": t.note}
                for t in a.turns
            ],
            "expected_safe": a.expected_safe.description,
            "expected_safe_source": a.expected_safe.source,
            "observed": [
                {"turn": o.turn_index, "status": o.status, "latency_ms": o.latency_ms,
                 "bytes": o.response_bytes, "error": o.error}
                for o in a.observed
            ],
            "verdict": v.label.value,
            "result": _pass_fail(v.label),
            "severity": v.severity.value,
            "exploitability": v.exploitability,
            "rule_fired": v.rule_fired,
            "judged_by": v.judged_by,
            "regression": v.regression_flag,
            "evidence": v.evidence,
            "target_version": a.target_version,
        }


def _pass_fail(label: VerdictLabel) -> str:
    # From the target's perspective: DEFENDED = the target passed (safe); EXPLOITED = it failed.
    return {VerdictLabel.DEFENDED: "pass", VerdictLabel.EXPLOITED: "fail",
            VerdictLabel.PARTIAL: "partial", VerdictLabel.INCONCLUSIVE: "inconclusive"}[label]


def _campaign(category: AttackCategory, principals: list[Any], max_attempts: int) -> Campaign:
    return Campaign(name=f"eval-{category.value}", category=category, target_id="copilot",
                    auth_principals=principals, max_attempts=max_attempts)


async def run_category(
    redteam: RedTeamAgent, judge: Judge, category: AttackCategory, target_version: str,
    principals: list[Any], max_attempts: int, live: bool,
) -> list[EvalResult]:
    campaign = _campaign(category, principals, max_attempts)
    attempts = redteam.generate(campaign, target_version)
    results: list[EvalResult] = []
    for attempt in attempts:
        executed = await redteam.execute(attempt, campaign) if live else attempt
        verdict = await judge.judge(executed)
        results.append(EvalResult(executed, verdict))
    return results


def summarize(results_by_cat: dict[AttackCategory, list[EvalResult]],
              target_version: str) -> dict[str, Any]:
    matrix: dict[str, Any] = {}
    for cat, results in results_by_cat.items():
        labels = [r.verdict.label for r in results]
        matrix[cat.value] = {
            "total": len(results),
            "pass_defended": sum(x == VerdictLabel.DEFENDED for x in labels),
            "fail_exploited": sum(x == VerdictLabel.EXPLOITED for x in labels),
            "partial": sum(x == VerdictLabel.PARTIAL for x in labels),
            "inconclusive": sum(x == VerdictLabel.INCONCLUSIVE for x in labels),
            "owasp_web": sorted({r.attempt.owasp.web.value for r in results}),
            "owasp_llm": sorted({r.attempt.owasp.llm.value for r in results}),
        }
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "target_version": target_version,
        "taxonomy_version": "owasp-web-2021; owasp-llm-2023",
        "categories_tested": len(results_by_cat),
        "coverage_matrix": matrix,
    }


@dataclass
class EvalWriter:
    out_dir: Path
    written: list[Path] = field(default_factory=list)

    def write(self, results_by_cat: dict[AttackCategory, list[EvalResult]],
              target_version: str) -> dict[str, Any]:
        cases_dir = self.out_dir / "cases"
        cases_dir.mkdir(parents=True, exist_ok=True)
        for cat, results in results_by_cat.items():
            path = cases_dir / f"{cat.value}.json"
            path.write_text(json.dumps([r.to_manifest() for r in results], indent=2) + "\n")
            self.written.append(path)
        summary = summarize(results_by_cat, target_version)
        (self.out_dir / "coverage_matrix.json").write_text(json.dumps(summary, indent=2) + "\n")
        self.written.append(self.out_dir / "coverage_matrix.json")
        return summary
