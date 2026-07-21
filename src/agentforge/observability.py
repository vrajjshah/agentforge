"""Langfuse tracing facade — per-agent traces of a campaign (the observability substrate).

A guarded wrapper: every method is a no-op when Langfuse keys are unset, so the hermetic suite and
offline runs need no backend, and a tracing failure can never break a run. When enabled, a campaign
is one trace and each agent hop (Orchestrator → Red Team → Judge → Documentation) is a nested span,
so the multi-agent handoff is inspectable with per-call latency and metadata.

**Data governance.** Traces can carry attack payloads and, mid-exploit, leaked target data, so a
PHI-shaped mask is applied before anything leaves the process. For this project the target's data is
synthetic and Langfuse Cloud is used; a deployment against real PHI must instead self-host Langfuse
inside the same BAA boundary — sending real PHI to a third-party SaaS would break the single-BAA
guarantee. This choice is stated in the AI-use disclosure.
"""

from __future__ import annotations

import contextlib
import logging
import os
from collections.abc import Iterator
from typing import Any

from agentforge.phi import mask_phi

logger = logging.getLogger("agentforge.observability")


def _mask(data: Any, **_: Any) -> Any:
    """Langfuse mask callback — the shared PHI-shape redactor (same one the ledger uses)."""
    return mask_phi(data)


class _NoopSpan:
    def update(self, **_: Any) -> None: ...
    def __enter__(self) -> _NoopSpan: return self
    def __exit__(self, *_: Any) -> None: ...


class Observability:
    """Guarded facade over Langfuse. All methods swallow errors — tracing never breaks a run."""

    def __init__(self) -> None:
        self._client: Any = None
        pk = os.environ.get("AGENTFORGE_LANGFUSE_PUBLIC_KEY")
        sk = os.environ.get("AGENTFORGE_LANGFUSE_SECRET_KEY")
        host = os.environ.get("AGENTFORGE_LANGFUSE_HOST", "https://us.cloud.langfuse.com")
        if not (pk and sk):
            return
        try:
            from langfuse import Langfuse

            self._client = Langfuse(public_key=pk, secret_key=sk, host=host, mask=_mask)
        except Exception:
            logger.exception("Langfuse init failed — continuing without tracing")
            self._client = None

    @property
    def enabled(self) -> bool:
        return self._client is not None

    @contextlib.contextmanager
    def span(self, name: str, **kwargs: Any) -> Iterator[Any]:
        if self._client is None:
            yield _NoopSpan()
            return
        try:
            with self._client.start_as_current_span(name=name, **kwargs) as span:
                yield span
        except Exception:
            logger.exception("Langfuse span failed", extra={"span": name})
            yield _NoopSpan()

    def update_trace(self, **kwargs: Any) -> None:
        if self._client is None:
            return
        with contextlib.suppress(Exception):
            self._client.update_current_trace(**kwargs)

    def flush(self) -> None:
        if self._client is None:
            return
        with contextlib.suppress(Exception):
            self._client.flush()
