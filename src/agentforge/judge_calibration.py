"""Calibration of the Judge's LLM rung against human labels.

The inner-loop self-test (``inner_loop.py``) scores the Judge's *deterministic* rungs against
ground truth that is exact by construction — a status code either is 401 or it isn't. That number
is a wiring proof, and reporting it alone overstates what has been measured: the rung that can
genuinely be wrong is the narrow LLM compliance check, which reads a free-text ``/chat`` response
and decides whether the target complied with an injected instruction.

This module scores exactly that rung against a hand-labelled set (``evals/judge_calibration/
cases.json``), and reports agreement, precision, recall, and the disagreements themselves. The set
is deliberately loaded with the cases that break naive scoring in both directions — refusals that
echo PHI vocabulary, refusals that quote the injection back, compliance hidden behind a refusal
preamble, compliance wrapped in a safety justification — so the number means something.

Running it costs one model call per case and is opt-in (``agentforge judge-calibration --live``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentforge.agents.judge import LlmComplianceCheck, delimited_evidence
from agentforge.contracts.models import ObservedResponse

_REPO_ROOT = Path(__file__).resolve().parents[2]
CALIBRATION_DIR = _REPO_ROOT / "evals" / "judge_calibration"
CASES_PATH = CALIBRATION_DIR / "cases.json"
RESULTS_PATH = CALIBRATION_DIR / "results.json"


@dataclass(frozen=True)
class CalibrationCase:
    id: str
    complied: bool                 # the human label
    difficulty: str                # "clear" | "ambiguous"
    trap: str | None               # the scoring failure this case is designed to catch
    rationale: str
    evidence: str                  # exactly the blob the Judge's rung receives in production


@dataclass
class CalibrationResult:
    """Agreement of the LLM rung with the human labels. ``tp`` = both say complied."""

    model: str = ""
    rows: list[dict[str, Any]] = field(default_factory=list)
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.tn + self.fp + self.fn

    @property
    def agreement(self) -> float:
        return round((self.tp + self.tn) / self.total, 3) if self.total else 0.0

    @property
    def precision(self) -> float:
        """Of the turns the rung called compliance, how many a human also did."""
        return round(self.tp / (self.tp + self.fp), 3) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        """Of the turns a human called compliance, how many the rung caught."""
        return round(self.tp / (self.tp + self.fn), 3) if (self.tp + self.fn) else 0.0

    @property
    def disagreements(self) -> list[dict[str, Any]]:
        return [r for r in self.rows if not r["agreed"]]

    def to_dict(self) -> dict[str, Any]:
        ambiguous = [r for r in self.rows if r["difficulty"] == "ambiguous"]
        ambiguous_agreed = sum(1 for r in ambiguous if r["agreed"])
        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "model": self.model,
            "scope": "the Judge's LLM compliance rung only (the deterministic rungs are scored "
                     "by the inner-loop self-test)",
            "ground_truth": "human labels, assigned before any model was run",
            "cases": self.total,
            "confusion": {"tp": self.tp, "tn": self.tn, "fp": self.fp, "fn": self.fn},
            "agreement": self.agreement,
            "precision": self.precision,
            "recall": self.recall,
            "ambiguous_cases": len(ambiguous),
            "ambiguous_agreement": (round(ambiguous_agreed / len(ambiguous), 3)
                                    if ambiguous else 0.0),
            "disagreements": self.disagreements,
            "rows": self.rows,
        }


def load_cases(path: Path = CASES_PATH) -> list[CalibrationCase]:
    """Load the labelled set, rendering each case into the exact evidence format the rung sees."""
    raw = json.loads(path.read_text())
    cases = []
    for c in raw["cases"]:
        responses = [
            ObservedResponse(turn_index=i, status=r["status"], latency_ms=0,
                             response_bytes=len(r["body"]), body_excerpt=r["body"])
            for i, r in enumerate(c["responses"])
        ]
        cases.append(CalibrationCase(
            id=c["id"], complied=bool(c["complied"]), difficulty=c["difficulty"],
            trap=c.get("trap"), rationale=c["rationale"],
            evidence=delimited_evidence(responses)))
    return cases


async def run_calibration(check: LlmComplianceCheck, model: str = "",
                          path: Path = CASES_PATH) -> CalibrationResult:
    result = CalibrationResult(model=model)
    for case in load_cases(path):
        predicted = await check(case.evidence)
        agreed = predicted == case.complied
        if case.complied and predicted:
            result.tp += 1
        elif not case.complied and not predicted:
            result.tn += 1
        elif predicted:
            result.fp += 1
        else:
            result.fn += 1
        result.rows.append({
            "id": case.id, "human": case.complied, "judge": predicted, "agreed": agreed,
            "difficulty": case.difficulty, "trap": case.trap, "rationale": case.rationale,
        })
    return result


def read_results(path: Path = RESULTS_PATH) -> dict[str, Any] | None:
    """The last recorded calibration, or None if the rung has never been calibrated."""
    if not path.exists():
        return None
    data: dict[str, Any] = json.loads(path.read_text())
    return data


def write_results(result: CalibrationResult, path: Path = RESULTS_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2) + "\n")
    return path
