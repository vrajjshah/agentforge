"""Platform configuration — env-driven; secrets never live in the tree.

The target URL is treated as an **immutable allow-list** (DIRECTION §12 F2): the platform
attacks exactly this origin and nothing else. Redirects to other hosts are rejected by the
adapter, so a DNS-rebinding or open-redirect trick can't repoint the Red Team.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

_REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    target_url: str
    target_api_key: str
    aws_region: str
    judge_model: str
    redteam_seed_model: str
    data_dir: Path
    request_timeout_s: float
    # A hard ceiling the adapter enforces regardless of any campaign's request (defense in depth).
    global_max_latency_s: float

    @property
    def target_origin(self) -> str:
        p = urlparse(self.target_url)
        return f"{p.scheme}://{p.netloc}"

    @property
    def has_bedrock(self) -> bool:
        return bool(os.environ.get("AWS_BEARER_TOKEN_BEDROCK") or os.environ.get("AWS_PROFILE"))

    @classmethod
    def from_env(cls, *, load: bool = True) -> Settings:
        if load:
            load_dotenv(_REPO_ROOT / ".env", override=False)
        target_url = os.environ.get("AGENTFORGE_TARGET_URL", "https://45-55-53-165.sslip.io/copilot")
        return cls(
            target_url=target_url.rstrip("/"),
            target_api_key=os.environ.get("AGENTFORGE_TARGET_API_KEY", ""),
            aws_region=os.environ.get("AGENTFORGE_AWS_REGION")
            or os.environ.get("AWS_REGION", "us-east-1"),
            judge_model=os.environ.get(
                "AGENTFORGE_JUDGE_MODEL", "us.anthropic.claude-opus-4-8"
            ),
            redteam_seed_model=os.environ.get(
                "AGENTFORGE_REDTEAM_SEED_MODEL", "us.meta.llama3-3-70b-instruct-v1:0"
            ),
            data_dir=Path(os.environ.get("AGENTFORGE_DATA_DIR", str(_REPO_ROOT / "data"))),
            request_timeout_s=float(os.environ.get("AGENTFORGE_REQUEST_TIMEOUT_S", "30")),
            global_max_latency_s=float(os.environ.get("AGENTFORGE_GLOBAL_MAX_LATENCY_S", "60")),
        )
