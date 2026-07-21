from __future__ import annotations

from pathlib import Path

import pytest

from agentforge.adapters.copilot import CopilotAdapter
from agentforge.checkpacks.copilot.pack import CopilotCheckPack
from agentforge.config import Settings
from agentforge.mutation.engine import MutationEngine


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        target_url="http://target.test/copilot",
        target_api_key="",
        aws_region="us-east-1",
        judge_model="test-judge",
        redteam_seed_model="test-redteam",
        orchestrator_model="test-orchestrator",
        data_dir=tmp_path / "data",
        request_timeout_s=5.0,
        global_max_latency_s=15.0,
    )


@pytest.fixture
def adapter(settings: Settings) -> CopilotAdapter:
    return CopilotAdapter(settings)


@pytest.fixture
def checkpack() -> CopilotCheckPack:
    return CopilotCheckPack()


@pytest.fixture
def engine() -> MutationEngine:
    return MutationEngine()
