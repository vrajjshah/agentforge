"""The Documentation agent — confirmed verdict → structured vuln report (DIRECTION §3.4).

Template-driven (deterministic — no LLM needed to fill a known schema). It is the *only* writer
to the vuln DB, and only through the data-quality gate. A CRITICAL report additionally requires
an explicit human-approval flag before it is filed (the deliberate trust boundary the PDF asks
for — "an agent that confidently documents a false positive wastes engineering time").
"""

from __future__ import annotations

import contextlib

from agentforge.contracts.models import (
    AttackAttempt,
    AttackCategory,
    Severity,
    Verdict,
    VerdictLabel,
    VulnReport,
)
from agentforge.stores.vulndb import VulnDB

_CLINICAL_IMPACT: dict[AttackCategory, str] = {
    AttackCategory.DATA_EXFILTRATION: (
        "A caller could read another patient's chart data (PHI), a HIPAA breach: wrong-patient "
        "information also risks a clinician acting on the wrong record."
    ),
    AttackCategory.IDENTITY_ROLE: (
        "An action could be attributed to a clinician who did not perform it, corrupting the "
        "accountability record a chart audit depends on."
    ),
    AttackCategory.PROMPT_INJECTION: (
        "Untrusted content could steer the co-pilot out of scope — surfacing another patient's "
        "data or fabricating clinical guidance a physician might trust."
    ),
    AttackCategory.STATE_CORRUPTION: (
        "A prior clinician's decision or reason could be silently overwritten, so the record no "
        "longer reflects what actually happened."
    ),
    AttackCategory.CONCURRENCY_IDEMPOTENCY: (
        "A duplicated or raced write could place two conflicting rows in the chart, and a human "
        "reviewing the UI would not see the discrepancy."
    ),
    AttackCategory.DENIAL_OF_SERVICE: (
        "Resource exhaustion could make the co-pilot unavailable or silently truncate an "
        "extraction, dropping clinical facts (labs, meds) without warning."
    ),
    AttackCategory.TOOL_MISUSE: (
        "An unintended or looping tool call could read or write data outside the intended scope, "
        "or run up cost without clinical value."
    ),
}


class HumanApprovalRequired(RuntimeError):
    """A CRITICAL report cannot be filed without explicit human approval."""


class DocumentationAgent:
    def __init__(self, db: VulnDB) -> None:
        self._db = db

    def draft(self, verdict: Verdict, attempt: AttackAttempt) -> VulnReport:
        observed = "; ".join(
            f"turn {r.turn_index}: HTTP {r.status} ({r.response_bytes}B)"
            + (f" — {r.error}" if r.error else "")
            for r in attempt.observed
        ) or "no evidence captured"
        return VulnReport(
            title=f"{attempt.category.value.replace('_', ' ').title()}: {attempt.subcategory}",
            severity=verdict.severity,
            category=attempt.category,
            owasp=attempt.owasp,
            clinical_impact=_CLINICAL_IMPACT.get(attempt.category, "See category."),
            reproduction=attempt.turns,
            observed_behavior=observed,
            expected_behavior=attempt.expected_safe.description,
            remediation=_remediation(attempt.category),
            status="confirmed",
            target_version=attempt.target_version,
        )

    def file(self, report: VulnReport, *, human_approved: bool = False) -> str:
        """File a report to the vuln DB. CRITICAL requires human approval (trust boundary)."""
        if report.severity == Severity.CRITICAL and not human_approved:
            raise HumanApprovalRequired(
                f"report {report.id} is CRITICAL — requires human approval before filing"
            )
        return self._db.write(report)

    def document_verdicts(
        self, pairs: list[tuple[Verdict, AttackAttempt]], *, human_approved: bool = False
    ) -> list[VulnReport]:
        """Draft reports for EXPLOITED verdicts; file the non-critical ones (dedup by sequence)."""
        drafted: list[VulnReport] = []
        seen: set[str] = set()
        for verdict, attempt in pairs:
            if verdict.label != VerdictLabel.EXPLOITED:
                continue
            from agentforge.stores.vulndb import attack_fingerprint

            report = self.draft(verdict, attempt)
            fp = attack_fingerprint(report)
            if fp in seen:
                continue
            seen.add(fp)
            drafted.append(report)
            # A CRITICAL report is left as an un-filed draft pending human sign-off.
            with contextlib.suppress(HumanApprovalRequired):
                self.file(report, human_approved=human_approved)
        return drafted


def _remediation(category: AttackCategory) -> str:
    return {
        AttackCategory.DATA_EXFILTRATION: (
            "Scope every read by the authenticated patient, not by a document id; fail closed "
            "(404) when ownership can't be resolved."
        ),
        AttackCategory.IDENTITY_ROLE: (
            "Resolve identity server-side from the session/principal; never trust a body- or "
            "header-claimed actor for attribution."
        ),
        AttackCategory.PROMPT_INJECTION: (
            "Treat retrieved/uploaded content as untrusted data, delimit it, and keep the model "
            "on a patient-scoped tool allow-list; verify outputs before delivery."
        ),
        AttackCategory.STATE_CORRUPTION: (
            "Make state transitions append-only or guarded; never overwrite a prior actor's "
            "reason/attribution on a repeat action."
        ),
        AttackCategory.CONCURRENCY_IDEMPOTENCY: (
            "Use a DB-level atomic claim (UPDATE ... WHERE status=? AND claimed IS NULL) and an "
            "idempotency key on writes; do not retry non-idempotent writes."
        ),
        AttackCategory.DENIAL_OF_SERVICE: (
            "Bound input size and token budget; check stop_reason==max_tokens and fail loudly "
            "rather than truncating silently; rate-limit per principal."
        ),
        AttackCategory.TOOL_MISUSE: (
            "Give the model an atomic, least-privilege tool set; cap iterations; validate every "
            "tool parameter against the authenticated scope."
        ),
    }.get(category, "Scope, validate, and fail closed at the boundary.")
