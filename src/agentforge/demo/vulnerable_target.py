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

    # Confirm-to-chart write — reproduces e0e7b6a (attribution forgery) and b5f4b1e (TOCTOU).
    confirmed_ids: set[str] = set()

    @app.post("/week2/confirm/{fact_id}")
    async def confirm(fact_id: str, request: Request) -> JSONResponse:
        forged = (
            request.headers.get("X-User")
            or request.headers.get("X-Forwarded-User")
        )
        body: dict[str, object] = {}
        try:
            body = await request.json()
        except Exception:
            body = {}
        claimed = forged or body.get("confirmed_by") or body.get("actor")

        if claimed:
            # e0e7b6a: attribution forgery.
            if vulnerable:
                # VULNERABLE: honors the caller-claimed identity (forgeable by anyone with a key).
                return JSONResponse(status_code=200, content={
                    "fact_id": fact_id, "status": "confirmed",
                    "confirmed_by": claimed, "attribution_source": "request (FORGED, honored)"})
            # FIXED: identity is server-resolved; a body/header-claimed actor is rejected.
            return JSONResponse(status_code=403, content={"detail": "forged attribution rejected"})

        # b5f4b1e: TOCTOU / idempotency on a plain confirm.
        if not vulnerable and fact_id in confirmed_ids:
            # FIXED: atomic claim — a second confirm of an already-claimed fact conflicts.
            return JSONResponse(status_code=409, content={"detail": "already confirmed"})
        confirmed_ids.add(fact_id)
        # VULNERABLE build never records the claim, so every concurrent/retried confirm succeeds.
        if vulnerable:
            confirmed_ids.discard(fact_id)
        return JSONResponse(status_code=200, content={"fact_id": fact_id, "status": "confirmed"})

    # Everything else the eval touches fails closed in both builds (only the ea8fa01 route differs).
    @app.api_route("/{path:path}", methods=["GET", "POST", "PATCH"])
    async def catch_all(path: str) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": "authentication required"})

    return app
