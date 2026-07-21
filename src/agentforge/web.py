"""AgentForge web service — the platform's own URL + a lightweight observability dashboard.

Read-only by default: it surfaces the committed eval coverage matrix, the live target
fingerprint, and the gate-ledger status (the security-specific metrics Langfuse doesn't model —
DIRECTION §10 "build both"). The attack trigger is RBAC-gated and disabled unless an admin token
is configured, so a public URL can never launch attacks against the target (trust & safety).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from agentforge.adapters.copilot import CopilotAdapter
from agentforge.config import Settings

_REPO_ROOT = Path(__file__).resolve().parents[2]
# In a container the package installs to site-packages, so the repo-relative default is wrong;
# AGENTFORGE_EVALS_DIR overrides it (the Dockerfile points it at /app/evals).
_EVALS = Path(os.environ.get("AGENTFORGE_EVALS_DIR", str(_REPO_ROOT / "evals")))

app = FastAPI(title="AgentForge", description="Adversarial AI security platform")
_settings = Settings.from_env()


def _coverage() -> dict[str, Any]:
    path = _EVALS / "coverage_matrix.json"
    return json.loads(path.read_text()) if path.exists() else {"coverage_matrix": {}}


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"service": "agentforge", "status": "ok"})


@app.get("/api/coverage")
async def coverage() -> JSONResponse:
    return JSONResponse(_coverage())


@app.get("/api/target")
async def target() -> JSONResponse:
    adapter = CopilotAdapter(_settings)
    ok, detail = await adapter.health()
    version = await adapter.version() if ok else "unreachable"
    return JSONResponse({"target_url": _settings.target_url, "healthy": ok,
                         "detail": detail, "fingerprint": version})


@app.get("/api/evals/{category}")
async def evals(category: str) -> JSONResponse:
    path = _EVALS / "cases" / f"{category}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="unknown category")
    return JSONResponse(json.loads(path.read_text()))


@app.post("/api/run/{category}")
async def run(category: str, x_admin_token: str | None = Header(default=None)) -> JSONResponse:
    """RBAC-gated attack trigger. Disabled unless AGENTFORGE_ADMIN_TOKEN is set (trust & safety)."""
    admin = os.environ.get("AGENTFORGE_ADMIN_TOKEN", "")
    if not admin:
        raise HTTPException(status_code=403, detail="run trigger disabled (no admin token)")
    if x_admin_token != admin:
        raise HTTPException(status_code=401, detail="invalid admin token")
    # Deliberately not auto-executing here: live attacks are batched from the CLI and their
    # results committed to ./evals/. This endpoint documents the RBAC boundary.
    return JSONResponse({"accepted": category, "note": "run via CLI; results land in ./evals/"})


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    cov = _coverage()
    matrix = cov.get("coverage_matrix", {})
    rows = []
    for cat, m in matrix.items():
        total = m.get("total", 0)
        passed = m.get("pass_defended", 0)
        exploited = m.get("fail_exploited", 0)
        partial = m.get("partial", 0)
        web_tags = ", ".join(m.get("owasp_web", []))
        llm_tags = ", ".join(m.get("owasp_llm", []))
        badge = "#16a34a" if exploited == 0 else "#dc2626"
        rows.append(
            f"<tr><td><b>{cat}</b></td><td>{total}</td>"
            f"<td style='color:#16a34a'>{passed}</td>"
            f"<td style='color:#dc2626'>{exploited}</td>"
            f"<td style='color:#d97706'>{partial}</td>"
            f"<td class='owasp'>{web_tags}</td><td class='owasp'>{llm_tags}</td>"
            f"<td><span class='dot' style='background:{badge}'></span></td></tr>"
        )
    body = _DASHBOARD_HTML.format(
        target=_settings.target_url,
        version=cov.get("target_version", "—"),
        taxonomy=cov.get("taxonomy_version", "—"),
        generated=cov.get("generated_at", "—"),
        categories=cov.get("categories_tested", len(matrix)),
        rows="".join(rows) or "<tr><td colspan=8>no eval data yet</td></tr>",
    )
    return HTMLResponse(body)


_DASHBOARD_HTML = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>AgentForge — adversarial AI security platform</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;
   background:#0f172a;color:#e2e8f0}}
 .wrap{{max-width:1000px;margin:0 auto;padding:32px 20px}}
 h1{{font-size:26px;margin:0 0 4px}} .sub{{color:#94a3b8;margin-bottom:24px}}
 .cards{{display:flex;flex-wrap:wrap;gap:14px;margin-bottom:28px}}
 .card{{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px 18px;flex:1;
   min-width:180px}}
 .card .k{{color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:.04em}}
 .card .v{{font-size:18px;font-weight:700;margin-top:4px;word-break:break-all}}
 table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:10px;overflow:hidden}}
 th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid #334155;font-size:13px}}
 th{{background:#0b1220;color:#94a3b8;text-transform:uppercase;font-size:11px;letter-spacing:.04em}}
 .owasp{{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:#cbd5e1}}
 .dot{{display:inline-block;width:11px;height:11px;border-radius:50%}}
 a{{color:#60a5fa}} .foot{{color:#64748b;font-size:12px;margin-top:22px;line-height:1.6}}
</style></head><body><div class=wrap>
<h1>AgentForge</h1>
<div class=sub>Autonomous multi-agent adversarial evaluation — live-target coverage</div>
<div class=cards>
 <div class=card><div class=k>Target</div><div class=v>{target}</div></div>
 <div class=card><div class=k>Target fingerprint</div><div class=v>{version}</div></div>
 <div class=card><div class=k>Categories tested</div><div class=v>{categories}</div></div>
 <div class=card><div class=k>OWASP taxonomy</div><div class=v>{taxonomy}</div></div>
</div>
<table><thead><tr><th>Category</th><th>Total</th><th>Defended</th><th>Exploited</th>
 <th>Partial</th><th>OWASP web</th><th>OWASP LLM</th><th>Status</th></tr></thead>
<tbody>{rows}</tbody></table>
<div class=foot>
 Results generated {generated}. Every case is dual-OWASP-mapped and reproducible
 (fixed-seed generation). Against the hardened live target the honest result is "defense held";
 the platform proves it catches real vulns via an ephemeral vulnerable build and a frozen
 ground-truth set. Read-only dashboard — the attack trigger is RBAC-gated and off by default.
 <br>API: <a href="/api/coverage">/api/coverage</a> · <a href="/api/target">/api/target</a> ·
 <a href="/health">/health</a>
</div>
</div></body></html>"""
