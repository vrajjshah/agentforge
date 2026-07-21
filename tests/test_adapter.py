"""TargetAdapter conformance + the immutable allow-list guard (F2, F9)."""

from __future__ import annotations

import httpx
import pytest
import respx

from agentforge.adapters.base import AllowListViolation, PrincipalUnavailable
from agentforge.adapters.copilot import CopilotAdapter
from agentforge.config import Settings
from agentforge.contracts.models import AuthPrincipal, HttpProbe


def test_conformance_interface(adapter: CopilotAdapter) -> None:
    ident = adapter.identity
    assert ident.origin == "http://target.test"
    assert adapter.capabilities(), "adapter must publish a capability map"
    assert adapter.authenticate(AuthPrincipal.NONE).principal == AuthPrincipal.NONE


def test_allow_list_blocks_off_origin(adapter: CopilotAdapter) -> None:
    with pytest.raises(AllowListViolation):
        adapter._resolve_url("http://evil.example/steal")


def test_api_key_principal_unavailable_without_key(adapter: CopilotAdapter) -> None:
    with pytest.raises(PrincipalUnavailable):
        adapter.authenticate(AuthPrincipal.API_KEY)


@respx.mock
async def test_invoke_normalizes_response(adapter: CopilotAdapter) -> None:
    route = respx.get("http://target.test/copilot/week2/documents/2/extraction").mock(
        return_value=httpx.Response(401, json={"detail": "authentication required"})
    )
    obs = await adapter.invoke(
        HttpProbe(method="GET", path="/week2/documents/2/extraction"),
        adapter.authenticate(AuthPrincipal.NONE),
    )
    assert route.called
    assert obs.status == 401
    assert "authentication required" in obs.body_excerpt
    assert obs.error is None


@respx.mock
async def test_invoke_records_transport_error(settings: Settings) -> None:
    adapter = CopilotAdapter(settings)
    respx.get("http://target.test/copilot/health").mock(side_effect=httpx.ConnectError("down"))
    obs = await adapter.invoke(
        HttpProbe(method="GET", path="/health"), adapter.authenticate(AuthPrincipal.NONE)
    )
    assert obs.status == 0
    assert obs.error and "ConnectError" in obs.error


async def test_version_fingerprint_changes_with_build(adapter: CopilotAdapter) -> None:
    def mock_all(health_body: str) -> None:
        respx.get("http://target.test/copilot/health").mock(
            return_value=httpx.Response(200, text=health_body))
        respx.get("http://target.test/copilot/").mock(return_value=httpx.Response(200, text="root"))
        respx.get("http://target.test/copilot/session").mock(
            return_value=httpx.Response(200, json={"smart": False}))

    with respx.mock:
        mock_all("build-A")
        v1 = await adapter.version()
    with respx.mock:
        mock_all("build-B")
        v2 = await adapter.version()
    assert v1 != v2 and len(v1) == 16
