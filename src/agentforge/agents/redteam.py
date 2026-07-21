"""The Red Team agent — offense (DIRECTION §3.2).

Generation is deterministic-first: the mutation engine produces the bulk of variants with no
model call (reproducible, no refusals); an optional novel-seed LLM rung adds paid variety. The
Red Team may call the target but **cannot judge its own success** and cannot write the stores.
Every probe is checked against the campaign's capability grant before it leaves (F2).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace

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
    # Novel payloads (e.g. from the Bedrock seed model), keyed by seed id, merged before mutation.
    extra_payloads: dict[str, list[str]] = field(default_factory=dict)

    def _seeds(self, campaign: Campaign) -> list[Seed]:
        base = (
            [s for sid in campaign.seed_ids if (s := seed_by_id(sid)) is not None]
            if campaign.seed_ids else seeds_for(campaign.category)
        )
        return [self._augment(s) for s in base]

    def _augment(self, seed: Seed) -> Seed:
        extra = self.extra_payloads.get(seed.id)
        if not extra:
            return seed
        merged = [*seed.injection_payloads, *extra]
        return replace(seed, injection_payloads=merged)

    def _check_grant(self, campaign: Campaign, turn: AttackTurn) -> None:
        method = turn.probe.method.upper()
        if method not in {m.upper() for m in campaign.allowed_methods}:
            raise CapabilityViolation(f"method {method} not granted by campaign {campaign.id}")
        prefixes = campaign.allowed_path_prefixes
        if prefixes and not any(turn.probe.path.startswith(p) for p in prefixes):
            raise CapabilityViolation(
                f"path {turn.probe.path} not granted by campaign {campaign.id}"
            )
        for blocked in campaign.blocked_path_substrings:
            if blocked in turn.probe.path:
                raise CapabilityViolation(
                    f"path {turn.probe.path} blocked (live-target safety) by {campaign.id}"
                )

    def generate(self, campaign: Campaign, target_version: str) -> list[AttackAttempt]:
        """Build attempts (no execution). Used for the eval dataset and hermetic tests.

        Attempts are distributed **round-robin across seed+principal** so a category with many
        seeds exercises all of them under a small budget — otherwise the first seed's variants would
        fill the whole budget and later seeds (e.g. a new-surface probe) would never run. The
        canonical variant of each seed stays first in its own list, so it is always included."""
        groups: list[list[AttackAttempt]] = []
        for seed in self._seeds(campaign):
            for principal in campaign.auth_principals:
                if principal not in seed.principals:
                    continue
                variants = self.engine.mutate(
                    seed, principal, max_variants=campaign.max_turns_per_attempt + 8)
                groups.append(
                    [self._build(campaign, seed, principal, v, target_version) for v in variants])
        attempts: list[AttackAttempt] = []
        depth = 0
        while len(attempts) < campaign.max_attempts and any(depth < len(g) for g in groups):
            for g in groups:
                if depth < len(g):
                    attempts.append(g[depth])
                    if len(attempts) >= campaign.max_attempts:
                        return attempts
            depth += 1
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
            try:
                self._check_grant(campaign, turn)
            except CapabilityViolation as exc:
                observed.append(ObservedResponse(
                    turn_index=turn.index, status=0, latency_ms=0, response_bytes=0,
                    body_excerpt="", error=f"blocked_by_grant: {exc}"))
                continue
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
