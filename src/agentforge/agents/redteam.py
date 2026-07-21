"""The Red Team agent — offense (DIRECTION §3.2).

Generation is deterministic-first: the mutation engine produces the bulk of variants with no
model call (reproducible, no refusals); an optional novel-seed LLM rung adds paid variety. The
Red Team may call the target but **cannot judge its own success** and cannot write the stores.
Every probe is checked against the campaign's capability grant before it leaves (F2).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from agentforge.adapters.base import (
    AllowListViolation,
    AuthContext,
    PrincipalUnavailable,
    TargetAdapter,
)
from agentforge.checkpacks.base import CheckPack
from agentforge.contracts.models import (
    AttackAttempt,
    AttackTurn,
    AuthPrincipal,
    Campaign,
    ObservedResponse,
)
from agentforge.mutation.engine import MutatedAttack, MutationEngine
from agentforge.seeds.seeds import Seed, seed_by_id, seeds_for

# Optional novel-seed generator (Bedrock Llama/DeepSeek). Given a seed, returns extra payloads.
SeedGenerator = Callable[[Seed], Awaitable[list[str]]]


class CapabilityViolation(RuntimeError):
    """A probe fell outside the campaign's declared capability grant (F2)."""


@dataclass
class RedTeamAgent:
    adapter: TargetAdapter
    checkpack: CheckPack
    engine: MutationEngine
    seed_generator: SeedGenerator | None = None

    def _seeds(self, campaign: Campaign) -> list[Seed]:
        if campaign.seed_ids:
            return [s for sid in campaign.seed_ids if (s := seed_by_id(sid)) is not None]
        return seeds_for(campaign.category)

    def _check_grant(self, campaign: Campaign, turn: AttackTurn) -> None:
        method = turn.probe.method.upper()
        if method not in {m.upper() for m in campaign.allowed_methods}:
            raise CapabilityViolation(f"method {method} not granted by campaign {campaign.id}")
        prefixes = campaign.allowed_path_prefixes
        if prefixes and not any(turn.probe.path.startswith(p) for p in prefixes):
            raise CapabilityViolation(
                f"path {turn.probe.path} not granted by campaign {campaign.id}"
            )

    def generate(self, campaign: Campaign, target_version: str) -> list[AttackAttempt]:
        """Build attempts (no execution). Used for the eval dataset and hermetic tests."""
        attempts: list[AttackAttempt] = []
        for seed in self._seeds(campaign):
            for principal in campaign.auth_principals:
                if principal not in seed.principals:
                    continue
                for variant in self.engine.mutate(
                    seed, principal, max_variants=campaign.max_turns_per_attempt + 8
                ):
                    attempts.append(self._build(campaign, seed, principal, variant, target_version))
                    if len(attempts) >= campaign.max_attempts:
                        return attempts
        return attempts

    def _build(self, campaign: Campaign, seed: Seed, principal: AuthPrincipal,
               variant: MutatedAttack, target_version: str) -> AttackAttempt:
        turns = [AttackTurn(index=i, probe=t.probe, note=t.note)
                 for i, t in enumerate(variant.turns)]
        first_path = turns[0].probe.path if turns else "/"
        expected = self.checkpack.expected_safe(
            category=seed.category, subcategory=seed.subcategory,
            path=first_path, principal=principal,
        )
        return AttackAttempt(
            campaign_id=campaign.id,
            category=seed.category,
            subcategory=seed.subcategory,
            owasp=seed.owasp,
            auth_principal=principal,
            turns=turns,
            expected_safe=expected,
            target_version=target_version,
            mutator=variant.mutator,
            seed_id=seed.id,
        )

    async def execute(self, attempt: AttackAttempt, campaign: Campaign) -> AttackAttempt:
        """Fire the attempt against the live target; return it with observed evidence filled."""
        try:
            auth: AuthContext = self.adapter.authenticate(attempt.auth_principal)
        except PrincipalUnavailable:
            return attempt.model_copy(update={"observed": [ObservedResponse(
                turn_index=0, status=0, latency_ms=0, response_bytes=0, body_excerpt="",
                error="principal_unavailable")]})
        observed: list[ObservedResponse] = []
        for turn in attempt.turns:
            self._check_grant(campaign, turn)
            try:
                resp = await self.adapter.invoke(turn.probe, auth)
            except AllowListViolation as exc:
                resp = ObservedResponse(turn_index=turn.index, status=0, latency_ms=0,
                                        response_bytes=0, body_excerpt="",
                                        error=f"allow_list_violation: {exc}")
            observed.append(resp.model_copy(update={"turn_index": turn.index}))
        return attempt.model_copy(update={"observed": observed})

    async def run(self, campaign: Campaign, target_version: str) -> list[AttackAttempt]:
        """Generate + execute live. Available principals are filtered at execution time."""
        out: list[AttackAttempt] = []
        for attempt in self.generate(campaign, target_version):
            out.append(await self.execute(attempt, campaign))
        return out
