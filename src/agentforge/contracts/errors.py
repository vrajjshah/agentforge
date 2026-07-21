"""The five typed inter-agent error schemas (DIRECTION §4, §12 F10).

Every failure is a *defined* message, not a bare exception string: it carries a run id for
correlation, whether a retry is safe, and an idempotency key so a retried write can't double.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from .models import SCHEMA_VERSION


class ErrorCode(StrEnum):
    TARGET_UNREACHABLE = "target_unreachable"
    BUDGET_EXCEEDED = "budget_exceeded"
    JUDGE_TIMEOUT = "judge_timeout"
    NO_FINDINGS_IN_WINDOW = "no_findings_in_window"
    REGRESSION_DETECTED = "regression_detected"


class AgentError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    code: ErrorCode
    message: str
    run_id: str
    retryable: bool = False
    partial_result: bool = False
    provenance: str = ""  # which agent/edge raised it
    idempotency_key: str = Field(default_factory=lambda: uuid.uuid4().hex)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


ALL_ERRORS: tuple[type[BaseModel], ...] = (AgentError,)
