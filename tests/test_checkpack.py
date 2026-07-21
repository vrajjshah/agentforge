"""Check-pack: the safety oracle is deterministic, versioned, and route-driven (F4)."""

from __future__ import annotations

from agentforge.checkpacks.copilot.pack import CopilotCheckPack
from agentforge.contracts.models import AttackCategory, AuthPrincipal

_PACK = CopilotCheckPack()


def test_unauth_protected_read_requires_refusal() -> None:
    es = _PACK.expected_safe(category=AttackCategory.DATA_EXFILTRATION, subcategory="s",
                             path="/week2/documents/2/extraction", principal=AuthPrincipal.NONE)
    assert 200 in es.forbid_status_in
    assert set(es.require_status_in) >= {401, 403}
    assert es.forbid_substrings  # PHI-shaped markers
    assert es.source.endswith("@v1")


def test_open_route_is_not_treated_as_protected() -> None:
    # /health is open; DoS policy should not require an auth refusal there.
    es = _PACK.expected_safe(category=AttackCategory.DENIAL_OF_SERVICE, subcategory="s",
                             path="/health", principal=AuthPrincipal.NONE)
    assert es.max_latency_ms is not None
    assert 401 not in es.require_status_in


def test_prompt_injection_unauth_is_auth_gated() -> None:
    es = _PACK.expected_safe(category=AttackCategory.PROMPT_INJECTION, subcategory="s",
                             path="/chat", principal=AuthPrincipal.NONE)
    assert set(es.require_status_in) >= {401, 403}


def test_phi_markers_present() -> None:
    assert "birthDate" in _PACK.phi_markers()
