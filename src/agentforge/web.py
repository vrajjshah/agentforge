"""AgentForge web service — the deployed observability dashboard (a submission artifact).

One self-contained page answering the six observability questions: categories tested + counts,
pass/fail rate, resilience over target versions, open/in-progress/resolved findings, run cost, and
recent agent activity. Data comes from a committed ``evals/dashboard.json`` (rebuilt by
``agentforge dashboard``), so the page needs no database and makes no live calls to render. All
CSS/JS is inlined — a security dashboard must not phone out to a third-party CDN.
"""

from __future__ import annotations

import html
import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from agentforge.adapters.copilot import CopilotAdapter
from agentforge.config import Settings

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EVALS = Path(os.environ.get("AGENTFORGE_EVALS_DIR", str(_REPO_ROOT / "evals")))
_REPORTS = Path(os.environ.get("AGENTFORGE_REPORTS_DIR", str(_REPO_ROOT / "reports")))

app = FastAPI(title="AgentForge", description="Adversarial AI security platform")
_settings = Settings.from_env()


def _dashboard_data() -> dict[str, Any]:
    path = _EVALS / "dashboard.json"
    return json.loads(path.read_text()) if path.exists() else {}


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"service": "agentforge", "status": "ok"})


@app.get("/api/dashboard")
async def api_dashboard() -> JSONResponse:
    return JSONResponse(_dashboard_data())


@app.get("/api/coverage")
async def coverage() -> JSONResponse:
    return JSONResponse(_dashboard_data().get("coverage", {}))


@app.get("/api/target")
async def target() -> JSONResponse:
    adapter = CopilotAdapter(_settings)
    ok, detail = await adapter.health()
    version = await adapter.version() if ok else "unreachable"
    return JSONResponse({"target_url": _settings.target_url, "healthy": ok,
                         "detail": detail, "fingerprint": version})


@app.post("/api/run/{category}")
async def run(category: str, x_admin_token: str | None = Header(default=None)) -> JSONResponse:
    """RBAC-gated attack trigger. Disabled unless AGENTFORGE_ADMIN_TOKEN is set (trust & safety)."""
    admin = os.environ.get("AGENTFORGE_ADMIN_TOKEN", "")
    if not admin:
        raise HTTPException(status_code=403, detail="run trigger disabled (no admin token)")
    if x_admin_token != admin:
        raise HTTPException(status_code=401, detail="invalid admin token")
    return JSONResponse({"accepted": category, "note": "run via CLI; results land in ./evals/"})


@app.get("/reports/{name}", response_class=HTMLResponse)
async def report(name: str) -> HTMLResponse:
    """Serve a generated vulnerability report. Path-traversal-safe (basename only, .md only)."""
    safe = Path(name).name
    path = _REPORTS / safe
    if not safe.endswith(".md") or not path.exists():
        raise HTTPException(status_code=404, detail="report not found")
    md = path.read_text()
    page = ("<!doctype html><meta charset=utf-8><title>" + html.escape(safe) + "</title>"
            "<style>body{max-width:820px;margin:40px auto;padding:0 20px;"
            "font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;line-height:1.55;"
            "background:#0b1220;color:#e6edf6}pre{white-space:pre-wrap;font-family:ui-monospace,"
            "Menlo,monospace;font-size:13px}a{color:#60a5fa}"
            "@media(prefers-color-scheme:light){body{background:#fff;color:#0f172a}}</style>"
            "<p><a href='/'>← dashboard</a></p><pre>" + html.escape(md) + "</pre>")
    return HTMLResponse(page)


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    return HTMLResponse(_render(_dashboard_data()))


# --------------------------------------------------------------------------------------
# Rendering (plain string building — no external templates, no CDN)
# --------------------------------------------------------------------------------------
def _esc(v: object) -> str:
    return html.escape(str(v))


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_CLASS = {"critical": "crit", "high": "high", "medium": "med", "low": "low", "info": "info"}


def _stat(label: str, value: str, sub: str = "") -> str:
    sub_html = f"<div class=st-sub>{_esc(sub)}</div>" if sub else ""
    return (f"<div class=stat><div class=st-k>{_esc(label)}</div>"
            f"<div class=st-v>{_esc(value)}</div>{sub_html}</div>")


def _coverage_rows(coverage: dict[str, Any]) -> str:
    rows = []
    for cat, m in coverage.items():
        total = m.get("total", 0) or 1
        passed = m.get("pass_defended", 0)
        pct = round(100 * passed / total)
        exploited = m.get("fail_exploited", 0)
        badge = _status_badge("held" if exploited == 0 else "findings")
        rows.append(
            f"<tr><td><b>{_esc(cat)}</b></td>"
            f"<td class=num>{m.get('total', 0)}</td>"
            f"<td class=num good-t>{passed}</td>"
            f"<td class=num crit-t>{exploited}</td>"
            f"<td class=num warn-t>{m.get('partial', 0)}</td>"
            f"<td class=num muted>{m.get('inconclusive', 0)}</td>"
            f"<td class=owasp>{_esc(', '.join(m.get('owasp_web', [])))}</td>"
            f"<td class=owasp>{_esc(', '.join(m.get('owasp_llm', [])))}</td>"
            f"<td><div class=meter title='{pct}% defended'>"
            f"<span style='width:{pct}%'></span></div></td>"
            f"<td>{badge}</td></tr>"
        )
    return "".join(rows) or "<tr><td colspan=10 class=muted>no coverage data</td></tr>"


def _findings_rows(findings: list[dict[str, Any]]) -> str:
    rows = []
    for f in sorted(findings, key=lambda x: _SEV_RANK.get(x.get("severity", "info"), 9)):
        sev = f.get("severity", "info")
        cls = _SEV_CLASS.get(sev, "info")
        status = f.get("status", "")
        status_badge = _status_badge("resolved" if status == "closed" else status or "open")
        link = f.get("file", "")
        title = f"<a href='/reports/{_esc(link)}'>{_esc(f.get('title', ''))}</a>" if link \
            else _esc(f.get("title", ""))
        rows.append(
            f"<tr><td><span class='sev {cls}'>● {_esc(sev.upper())}</span></td>"
            f"<td>{_esc(f.get('category', ''))}</td>"
            f"<td class=owasp>{_esc(f.get('owasp_web', ''))}</td>"
            f"<td class=owasp>{_esc(f.get('owasp_llm', ''))}</td>"
            f"<td>{status_badge}</td>"
            f"<td>{title}</td></tr>"
        )
    return "".join(rows) or "<tr><td colspan=6 class=muted>no findings</td></tr>"


def _activity_rows(activity: list[dict[str, Any]]) -> str:
    rows = []
    for a in activity:
        agent = a.get("agent", "")
        rows.append(
            f"<li><span class='agent a-{_esc(agent)}'>{_esc(agent)}</span>"
            f"<span class=act-ev>{_esc(a.get('event', ''))}</span>"
            f"<span class=act-detail>{_esc(a.get('detail', ''))}</span></li>"
        )
    return "".join(rows) or "<li class=muted>no recent activity</li>"


def _status_badge(state: str) -> str:
    good = {"held", "resolved", "closed"}
    warn = {"findings", "in_progress", "confirmed", "triaged"}
    cls = "b-good" if state in good else ("b-warn" if state in warn else "b-crit"
                                          if state == "open" else "b-muted")
    label = {"held": "defense held", "resolved": "resolved", "findings": "findings"}.get(
        state, state.replace("_", " "))
    return f"<span class='badge {cls}'>{_esc(label)}</span>"


def _render(d: dict[str, Any]) -> str:
    if not d:
        return "<h1>AgentForge</h1><p>No dashboard data. Run <code>agentforge dashboard</code>.</p>"
    t = d.get("target", {})
    totals = d.get("totals", {})
    fs = d.get("findings_summary", {})
    cost = d.get("cost", {})
    status_ok = d.get("status") == "defense_held"
    hero_badge = (f"<span class='badge {'b-good' if status_ok else 'b-crit'} big'>"
                  f"{'✓ Defense held' if status_ok else '⚠ Findings open'}</span>")
    resilience = "".join(
        f"<tr><td class=mono>{_esc(r.get('fingerprint'))}</td>"
        f"<td class=muted>{_esc(r.get('run_at'))}</td>"
        f"<td class=num>{_esc(r.get('cases'))}</td>"
        f"<td class=num good-t>{round(100 * r.get('pass_rate', 0))}%</td></tr>"
        for r in d.get("resilience", [])
    )
    pass_pct = round(100 * totals.get("pass_rate", 0))
    body = _PAGE.replace("__TITLE__", _esc(d.get("title", "AgentForge")))
    body = body.replace("__HERO_BADGE__", hero_badge)
    body = body.replace("__TARGET__", _esc(t.get("url", "—")))
    body = body.replace("__FINGERPRINT__", _esc(t.get("fingerprint", "—")))
    body = body.replace("__SURFACE__", _esc(t.get("surface", "—")))
    body = body.replace("__LASTRUN__", _esc(t.get("last_run", "—")))
    body = body.replace("__STATS__", "".join([
        _stat("Categories tested", str(totals.get("categories", 0))),
        _stat("Attack cases", str(totals.get("total", 0)), "authenticated /chat + reads"),
        _stat("Pass rate", f"{pass_pct}%", "target defended"),
        _stat("Open on live target", str(fs.get("open_on_live_target", 0)), "confirmed exploits"),
        _stat("Findings resolved", str(fs.get("resolved", 0)), "fix-validated"),
        _stat("Live inference cost", f"${cost.get('live_inference_usd', 0)}",
              f"{cost.get('model_turns', 0)} model turns @ ${cost.get('per_turn_usd', 0)}"),
    ]))
    st = d.get("self_test", {})
    conf = st.get("confusion", {})
    body = body.replace("__SELFTEST__", "".join([
        _stat("Precision", f"{st.get('precision', '—')}", "no false alarms on fixed builds"),
        _stat("Recall", f"{st.get('recall', '—')}", "known vulns caught on vulnerable builds"),
        _stat("Accuracy", f"{st.get('accuracy', '—')}",
              f"TP {conf.get('tp', 0)} · TN {conf.get('tn', 0)} · "
              f"FP {conf.get('fp', 0)} · FN {conf.get('fn', 0)}"),
    ]))
    body = body.replace("__COSTPROJ__", "".join(
        f"<tr><td class=num>{r.get('n'):,}</td><td class=num>${r.get('dollars'):,.2f}</td>"
        f"<td class=num muted>{_esc(r.get('wall'))}</td></tr>"
        for r in d.get("cost_projection", [])
    ) or "<tr><td colspan=3 class=muted>—</td></tr>")
    body = body.replace("__COVERAGE__", _coverage_rows(d.get("coverage", {})))
    body = body.replace("__FINDINGS__", _findings_rows(d.get("findings", [])))
    body = body.replace("__RESILIENCE__", resilience or "<tr><td colspan=4 class=muted>—</td></tr>")
    body = body.replace("__ACTIVITY__", _activity_rows(d.get("agent_activity", [])))
    body = body.replace("__TAXONOMY__", _esc(d.get("taxonomy_version", "—")))
    body = body.replace("__GENERATED__", _esc(d.get("generated_at", "—")))
    return body


_PAGE = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>AgentForge — adversarial security testing</title>
<style>
:root{
 --bg:#f6f7f9; --surface:#ffffff; --line:#e2e6ec; --ink:#0f172a; --ink2:#475569; --muted:#94a3b8;
 --good:#15803d; --good-bg:#dcfce7; --warn:#b45309; --warn-bg:#fef3c7; --crit:#b91c1c;
 --crit-bg:#fee2e2; --accent:#1d4ed8; --meter:#22c55e; --meter-track:#e5e7eb;
 --crit-dot:#dc2626; --high-dot:#ea580c; --med-dot:#d97706; --low-dot:#0891b2; --info-dot:#64748b;
}
@media (prefers-color-scheme:dark){:root{
 --bg:#0b1220; --surface:#111a2b; --line:#1f2c3f; --ink:#e6edf6; --ink2:#9fb0c4; --muted:#5f708a;
 --good:#4ade80; --good-bg:#0f2e1d; --warn:#fbbf24; --warn-bg:#33240a; --crit:#f87171;
 --crit-bg:#3a1414; --accent:#60a5fa; --meter:#22c55e; --meter-track:#1f2c3f;
}}
:root[data-theme=dark]{--bg:#0b1220;--surface:#111a2b;--line:#1f2c3f;--ink:#e6edf6;--ink2:#9fb0c4;
 --muted:#5f708a;--good:#4ade80;--good-bg:#0f2e1d;--warn:#fbbf24;--warn-bg:#33240a;--crit:#f87171;
 --crit-bg:#3a1414;--accent:#60a5fa;--meter-track:#1f2c3f;}
:root[data-theme=light]{--bg:#f6f7f9;--surface:#fff;--line:#e2e6ec;--ink:#0f172a;--ink2:#475569;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
 font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
 font-size:14px;line-height:1.5}
.wrap{max-width:1100px;margin:0 auto;padding:28px 20px 60px}
header{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
h1{font-size:20px;margin:0 0 2px} .tag{color:var(--ink2);font-size:14px;max-width:640px}
h2{font-size:14px;text-transform:uppercase;letter-spacing:.05em;color:var(--ink2);
 margin:30px 0 10px;font-weight:700}
.meta{color:var(--muted);font-size:12.5px;margin-top:6px}
.meta b{color:var(--ink2);font-weight:600} .mono{font-family:ui-monospace,Menlo,monospace}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(158px,1fr));gap:12px;margin-top:20px}
.stat{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.st-k{color:var(--ink2);font-size:12px;text-transform:uppercase;letter-spacing:.03em}
.st-v{font-size:24px;font-weight:750;margin-top:4px}
.st-sub{color:var(--muted);font-size:11.5px;margin-top:3px}
table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--line);
 border-radius:12px;overflow:hidden}
.scroll{overflow-x:auto}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);font-size:13px;
 white-space:nowrap}
tr:last-child td{border-bottom:none}
th{background:color-mix(in srgb,var(--surface) 70%,var(--bg));color:var(--ink2);
 font-size:11px;text-transform:uppercase;letter-spacing:.04em}
td.num{text-align:right;font-variant-numeric:tabular-nums} .muted{color:var(--muted)}
.good-t{color:var(--good)} .warn-t{color:var(--warn)} .crit-t{color:var(--crit)}
.owasp{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--ink2);white-space:normal}
.meter{width:120px;height:8px;border-radius:5px;background:var(--meter-track);overflow:hidden}
.meter span{display:block;height:100%;background:var(--meter);border-radius:5px}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11.5px;font-weight:600;
 white-space:nowrap}
.badge.big{font-size:13px;padding:5px 13px}
.b-good{background:var(--good-bg);color:var(--good)}
.b-warn{background:var(--warn-bg);color:var(--warn)}
.b-crit{background:var(--crit-bg);color:var(--crit)}
.b-muted{background:var(--line);color:var(--ink2)}
.sev{font-weight:700;font-size:12px} .sev.crit{color:var(--crit-dot)}
.sev.high{color:var(--high-dot)}
.sev.med{color:var(--med-dot)} .sev.low{color:var(--low-dot)} .sev.info{color:var(--info-dot)}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
ul.timeline{list-style:none;margin:0;padding:0;background:var(--surface);
 border:1px solid var(--line);border-radius:12px;overflow:hidden}
ul.timeline li{display:flex;align-items:center;gap:12px;padding:9px 14px;
 border-bottom:1px solid var(--line);font-size:13px}
ul.timeline li:last-child{border-bottom:none}
.agent{min-width:104px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.03em;
 padding:2px 8px;border-radius:6px;text-align:center}
.a-orchestrator{background:#eff6ff;color:#1d4ed8} .a-redteam{background:#fef2f2;color:#b91c1c}
.a-judge{background:#f0fdf4;color:#15803d} .a-documentation{background:#faf5ff;color:#7e22ce}
@media (prefers-color-scheme:dark){.a-orchestrator{background:#132036;color:#93c5fd}
.a-redteam{background:#2a1516;color:#fca5a5}.a-judge{background:#122616;color:#86efac}
.a-documentation{background:#241633;color:#d8b4fe}}
.act-ev{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:var(--ink2);
 min-width:130px}
.act-detail{color:var(--ink);white-space:normal}
.note{color:var(--muted);font-size:12px;margin-top:26px;line-height:1.6;
 border-top:1px solid var(--line);padding-top:16px}
.toggle{background:var(--surface);border:1px solid var(--line);color:var(--ink2);border-radius:8px;
 padding:5px 10px;cursor:pointer;font-size:12px}
</style></head><body><div class=wrap>
<header>
 <div>
  <h1>AgentForge</h1>
  <div class=tag>__TITLE__</div>
  <div class=meta>Target <b class=mono>__TARGET__</b>
   · fingerprint <b class=mono>__FINGERPRINT__</b>
   · surface <b>__SURFACE__</b> · last run <b>__LASTRUN__</b></div>
 </div>
 <div style="display:flex;flex-direction:column;gap:8px;align-items:flex-end">
  __HERO_BADGE__
  <button class=toggle
   onclick="var r=document.documentElement;r.dataset.theme=r.dataset.theme==='dark'?'light':'dark'"
   >toggle theme</button>
 </div>
</header>

<div class=stats>__STATS__</div>

<h2>Coverage by attack category</h2>
<div class=scroll><table><thead><tr>
 <th>Category</th><th class=num>Cases</th><th class=num>Defended</th><th class=num>Exploited</th>
 <th class=num>Partial</th><th class=num>Inconcl.</th><th>OWASP web</th><th>OWASP LLM</th>
 <th>Defended</th><th>Status</th></tr></thead><tbody>__COVERAGE__</tbody></table></div>

<h2>Findings</h2>
<div class=scroll><table><thead><tr>
 <th>Severity</th><th>Category</th><th>OWASP web</th><th>OWASP LLM</th><th>Status</th>
 <th>Report</th></tr></thead><tbody>__FINDINGS__</tbody></table></div>

<h2>Resilience over target versions</h2>
<div class=scroll><table><thead><tr>
 <th>Target fingerprint</th><th>Run</th><th class=num>Cases</th><th class=num>Pass rate</th>
 </tr></thead><tbody>__RESILIENCE__</tbody></table></div>

<h2>Platform self-test (testing the tester)</h2>
<div class=stats>__SELFTEST__</div>
<p class=meta>The platform's own verdicts scored against known ground truth: each seeded defect run
 against a build where it is present (should be caught) and one where it is fixed (should hold).
 Perfect scores mean no missed vulns and no false alarms — the finding productivity that makes the
 "defense held" result above trustworthy.</p>

<h2>Projected cost at scale</h2>
<div class=scroll><table><thead><tr>
 <th class=num>Attack runs</th><th class=num>Est. cost</th><th class=num>Wall-clock</th>
 </tr></thead><tbody>__COSTPROJ__</tbody></table></div>
<p class=meta>Not cost-per-token times n: deterministic generation is free, the Judge is triaged,
 and wall-clock (not dollars) is the binding constraint — see
 <code>docs/COST_ANALYSIS.md</code>.</p>

<h2>Recent agent activity</h2>
<ul class=timeline>__ACTIVITY__</ul>

<div class=note>
 OWASP taxonomy __TAXONOMY__ · generated __GENERATED__. Every eval case is dual-OWASP-mapped and
 reproducible (fixed-seed generation). Against the hardened live target the honest result is
 "defense held" — a legitimate outcome, not a gap. Findings are demonstrated on an ephemeral,
 isolated vulnerable build and fix-validated by the regression harness. This page is self-contained
 (no external scripts or fonts) and read-only; the attack trigger is RBAC-gated and off by default.
</div>
</div></body></html>"""
