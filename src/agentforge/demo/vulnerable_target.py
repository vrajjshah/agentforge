"""Ephemeral, isolated vulnerable target for the killer demo (DIRECTION §8, §9 decision 4, F2e).

A *separate* minimal app that faithfully reproduces the real `ea8fa01` defect — a document-keyed
read that returns another patient's PHI without a patient-scoped principal — plus its fixed
counterpart. This is spun up for the demo and destroyed after; it is **never** a vuln toggle on
the live target (blast radius). Ground-truth validation: the platform re-discovers a real,
known-answer vulnerability, live, and the regression harness watches the fix close it.

Synthetic data only — no real PHI. "Patient B" is a fabricated record.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# A fabricated "other patient" whose identifiers must never cross a scope boundary.
_PATIENT_B = {
    "patient_id": "2",
    "name": "Jordan Vulnera (SYNTHETIC)",
    "birthDate": "1958-03-11",
    "mrn": "MRN-SYNTH-0002",
    "facts": ["Warfarin 5mg daily", "INR 4.8 (critical)"],
    "patient_identity_warning": "document belongs to patient 2, session bound to patient 1",
}


def build_target(*, vulnerable: bool) -> FastAPI:
    """Return the vulnerable build (leaks) or the fixed build (fails closed 401)."""
    app = FastAPI(title=f"copilot-{'vulnerable' if vulnerable else 'fixed'}")

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok", "build": "vulnerable" if vulnerable else "fixed"})

    @app.get("/")
    async def root() -> JSONResponse:
        return JSONResponse({"copilot": "demo", "build": "vulnerable" if vulnerable else "fixed"})

    @app.get("/session")
    async def session() -> JSONResponse:
        return JSONResponse({"smart": False})

    @app.get("/week2/documents/{document_id}/extraction")
    async def extraction(document_id: str, request: Request) -> JSONResponse:
        if not vulnerable:
            # FIXED: reads are patient-scoped; without a session the request fails closed.
            return JSONResponse(status_code=401, content={"detail": "authentication required"})
        # VULNERABLE (ea8fa01): document-keyed, not patient-keyed — returns patient B's PHI to
        # anyone who knows the document id, with no patient-scope check.
        return JSONResponse(status_code=200, content=_PATIENT_B)

    @app.get("/week2/documents/{document_id}/page/{page}")
    async def page(document_id: str, page: int) -> JSONResponse:
        if not vulnerable:
            return JSONResponse(status_code=401, content={"detail": "authentication required"})
        return JSONResponse(status_code=200, content={"page": page, **_PATIENT_B})

    # Everything else the eval touches fails closed in both builds (only the ea8fa01 route differs).
    @app.api_route("/{path:path}", methods=["GET", "POST", "PATCH"])
    async def catch_all(path: str) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": "authentication required"})

    return app
