"""The check-pack boundary — pluggable, domain-specific success criteria (DIRECTION §12 F9).

The platform core knows nothing about patients, PHI, or clinical routes. A check-pack, keyed
to a target adapter, supplies:
  * the ``ExpectedSafe`` policy for each attack (the Judge's oracle — F4), and
  * the domain ground truth (e.g. PHI markers) the deterministic Judge asserts against.

Swapping the target = swapping the adapter + check-pack; the engine is untouched.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from agentforge.contracts.models import AttackCategory, AuthPrincipal, ExpectedSafe


class CheckPack(ABC):
    name: str
    version: str

    @abstractmethod
    def expected_safe(
        self,
        *,
        category: AttackCategory,
        subcategory: str,
        path: str,
        principal: AuthPrincipal,
    ) -> ExpectedSafe:
        """The safety oracle for one attack. Deterministic; independent of the Red Team."""

    @abstractmethod
    def phi_markers(self) -> list[str]:
        """Ground-truth identifiers that must never appear out of their patient scope."""

    def scope_rule(self) -> str:
        """One sentence stating what "in scope" means for this target.

        The Judge's semantic rung is asked whether a free-text answer left its scope, which is
        unanswerable if the rung is never told what the scope *is* — measured: that omission was
        the root cause of both errors in the held-out calibration. Domain knowledge, so it lives
        in the check-pack with the rest of it; the core stays target-agnostic.
        """
        return ""
