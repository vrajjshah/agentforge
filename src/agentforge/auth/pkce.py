"""PKCE (RFC 7636) — the S256 code-verifier/challenge pair.

The verifier is a high-entropy secret kept server-side (never sent to the browser); only its
SHA-256 challenge travels in the authorization request. OpenEMR advertises S256, so plain is never
used. Kept free of I/O so the security-critical derivation is unit-testable in isolation.
"""

from __future__ import annotations

import base64
import hashlib
import secrets


def pkce_pair() -> tuple[str, str]:
    """Return ``(code_verifier, code_challenge)`` using S256."""
    verifier = secrets.token_urlsafe(64)[:128]  # RFC 7636: 43-128 chars
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge
