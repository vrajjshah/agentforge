"""Mutation engine: reproducibility (a hard gate) and coverage of mutator families."""

from __future__ import annotations

from agentforge.contracts.models import AuthPrincipal
from agentforge.mutation.engine import MutationEngine, _fingerprint
from agentforge.seeds.seeds import seed_by_id


def test_mutation_is_deterministic() -> None:
    seed = seed_by_id("audit-ocr")
    assert seed is not None
    a = MutationEngine(1337).mutate(seed, AuthPrincipal.SESSION, 12)
    b = MutationEngine(1337).mutate(seed, AuthPrincipal.SESSION, 12)
    assert [_fingerprint(x) for x in a] == [_fingerprint(x) for x in b]


def test_canonical_variant_is_first() -> None:
    seed = seed_by_id("ea8fa01")
    assert seed is not None
    variants = MutationEngine().mutate(seed, AuthPrincipal.NONE, 8)
    assert variants[0].mutator == "ea8fa01"


def test_http_seed_produces_forged_headers_and_idor() -> None:
    seed = seed_by_id("ea8fa01")
    assert seed is not None
    variants = MutationEngine().mutate(seed, AuthPrincipal.NONE, 20)
    mutators = {v.mutator for v in variants}
    assert any("forged-headers" in m for m in mutators)
    assert any("idor-" in m for m in mutators)


def test_message_seed_encodes_and_splits() -> None:
    seed = seed_by_id("audit-ocr")
    assert seed is not None
    variants = MutationEngine().mutate(seed, AuthPrincipal.SESSION, 30)
    mutators = {v.mutator for v in variants}
    assert any("base64" in m for m in mutators)
    assert any("multi-turn" in m for m in mutators)
    # multi-turn variant carries more than one turn
    multi = next(v for v in variants if "multi-turn" in v.mutator)
    assert len(multi.turns) >= 2
