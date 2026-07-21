"""PHI-shape masking — one redactor used everywhere data is persisted or exported.

The platform's discipline is that PHI-shaped values never reach a log, trace, or the event ledger
(synthetic here, but built to the real-hospital bar). This module is the single source of the mask,
shared by the Langfuse trace callback and the event-ledger write path so redaction can't drift
between them.
"""

from __future__ import annotations

import re
from typing import Any

_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),            # ISO dates (DOB-shaped)
    re.compile(r"\bMRN[-\s]?\w+\b", re.IGNORECASE),  # MRNs
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),            # SSN-shaped
)
_REDACTED = "[REDACTED]"


def mask_phi(data: Any) -> Any:
    """Recursively redact PHI-shaped substrings from any JSON-ish value (str/dict/list)."""
    if isinstance(data, str):
        out = data
        for pat in _PATTERNS:
            out = pat.sub(_REDACTED, out)
        return out
    if isinstance(data, dict):
        return {k: mask_phi(v) for k, v in data.items()}
    if isinstance(data, list):
        return [mask_phi(v) for v in data]
    return data
