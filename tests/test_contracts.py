"""Contract tests (F10): schemas are versioned, round-trip, and reject malformed messages."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentforge.contracts.errors import AgentError, ErrorCode
from agentforge.contracts.export_schemas import SCHEMA_DIR, export, schema_for
from agentforge.contracts.models import (
    ALL_CONTRACTS,
    AttackCategory,
    AuthPrincipal,
    Campaign,
)


def test_exported_schemas_match_models(tmp_path: Path) -> None:
    """A model change that wasn't re-exported fails here (schemas stay in sync)."""
    written = export(tmp_path / "v1")
    assert written
    for model in ALL_CONTRACTS:
        name = "".join(f"_{c.lower()}" if c.isupper() else c for c in model.__name__).lstrip("_")
        committed = SCHEMA_DIR / f"{name}.schema.json"
        assert committed.exists(), f"{committed} not committed — run export_schemas"
        assert json.loads(committed.read_text()) == schema_for(model), (
            f"{name}.schema.json is stale — re-run export_schemas"
        )


def test_campaign_roundtrips() -> None:
    c = Campaign(name="t", category=AttackCategory.DATA_EXFILTRATION, target_id="copilot")
    assert Campaign.model_validate_json(c.model_dump_json()) == c


def test_consumer_rejects_unknown_field() -> None:
    """extra='forbid': a malformed inter-agent message is rejected by the consumer."""
    with pytest.raises(ValidationError):
        Campaign.model_validate(
            {"name": "t", "category": "data_exfiltration", "target_id": "c", "rogue": 1}
        )


def test_error_schema() -> None:
    e = AgentError(code=ErrorCode.TARGET_UNREACHABLE, message="down", run_id="r1", retryable=True)
    assert e.idempotency_key
    assert AgentError.model_validate_json(e.model_dump_json()).code == ErrorCode.TARGET_UNREACHABLE


def test_all_principals_enumerated() -> None:
    assert {p.value for p in AuthPrincipal} == {"none", "session", "api_key"}
