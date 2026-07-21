"""Config resolution — the off-by-default (flag-guarded) attacker model + PHI masking."""

from __future__ import annotations

import pytest

from agentforge.config import _DEFAULT_SEED_MODEL, _resolve_seed_model
from agentforge.phi import mask_phi

_DEEPSEEK = "us.deepseek.r1-v1:0"


def test_default_attacker_is_maverick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTFORGE_REDTEAM_SEED_MODEL", raising=False)
    assert _resolve_seed_model() == _DEFAULT_SEED_MODEL


def test_deepseek_refused_without_optin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTFORGE_REDTEAM_SEED_MODEL", _DEEPSEEK)
    monkeypatch.delenv("AGENTFORGE_ALLOW_FLAGGED_MODELS", raising=False)
    # Off-by-default: falls back to the vetted default, never silently uses DeepSeek.
    assert _resolve_seed_model() == _DEFAULT_SEED_MODEL


def test_deepseek_allowed_only_behind_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTFORGE_REDTEAM_SEED_MODEL", _DEEPSEEK)
    monkeypatch.setenv("AGENTFORGE_ALLOW_FLAGGED_MODELS", "1")
    assert _resolve_seed_model() == _DEEPSEEK


def test_mask_phi_redacts_shapes() -> None:
    assert mask_phi("DOB 1958-03-12") == "DOB [REDACTED]"
    assert "[REDACTED]" in mask_phi("MRN-SYNTH-0002")
    assert mask_phi({"note": "born 1958-03-12"})["note"] == "born [REDACTED]"
    assert mask_phi(["1958-03-12", 7]) == ["[REDACTED]", 7]
