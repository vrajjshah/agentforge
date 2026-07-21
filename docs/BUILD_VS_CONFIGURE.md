# Build vs. configure — what was written, what was adopted, and why

Every capability in this platform was one of three decisions: **adopt** something that exists,
**build** it, or **build a thin seam** over something adopted so it can be swapped later. The
default was adopt. What follows is the record of where that default was overridden, and the reason
each time — because "we wrote it ourselves" is a cost, and it needs a justification stronger than
preference.

The pattern that recurs: **adopt the plumbing, build the judgement.** Orchestration, tracing,
hosting, and crypto are solved problems with better implementations than anything written here in a
week. What is *not* solved is deciding whether a clinical AI's answer left its patient scope — and
that is where the code went.

## Adopted

| Capability | Chosen | Why not build |
|---|---|---|
| Agent orchestration / state machine | **LangGraph** | A campaign is a state graph with conditional edges and a halt condition. Hand-rolling that is a week of work to arrive somewhere worse, and the assignment's own framing is multi-agent orchestration, not scheduler design. |
| Data contracts + validation | **Pydantic v2** | The contracts are the integration surface between agents. Pydantic gives validation, JSON-Schema export, and strict unknown-field rejection for free; a bespoke validator would have been the single most pointless file in the repo. |
| HTTP client / server | **httpx + FastAPI** | Unremarkable, correct, and `ASGITransport` is what makes the ephemeral-build tests hermetic without a network. |
| JWT / JWKS verification | **PyJWT (`pyjwt[crypto]`)** | Signature verification is cryptography. Writing it is the classic way to ship an `alg=none` bypass. Adopted wholesale, including JWKS fetching and key rotation. |
| Tracing | **Langfuse** | Traces, nested spans, and a UI for LLM calls. Building an observability backend to demonstrate observability would be a strange use of the week. Pinned `>=3,<4` — v4 removed `start_as_current_span`. |
| Model access | **Anthropic SDK (Bedrock) + boto3 `converse`** | Two SDKs because the models need two: Claude via `AnthropicBedrock`, Llama via raw `bedrock-runtime.converse`. Both adopted; neither wrapped beyond a thin call site. |
| Hosting | **Railway** | The deliverable is a deployed dashboard, not a deployment pipeline. |
| Persistence | **SQLite** | Fits the data volume by three orders of magnitude (measured: `docs/LOAD_TEST.md`). Postgres is a 1K-scale decision, not a today decision. |

## Built

| Capability | Why nothing off the shelf fit |
|---|---|
| **Mutation engine** (`mutation/`) | Fuzzers mutate bytes; this mutates *semantics* — an attack sequence keeping its meaning while changing encoding, header forgery, path shape, or turn order, deterministically from a fixed seed so a run reproduces byte-identically on another machine. No general fuzzer expresses "the same IDOR, page-keyed instead of document-keyed". |
| **Judge verdict ladder** (`agents/judge.py`) | The core claim of the platform. Deterministic rungs first, one narrow LLM rung last, and a hard invariant that a confirmed exploit is never labelled DEFENDED. Generic LLM-as-judge libraries score *quality* on a 1–5 scale; this needs a boolean safety oracle that is independent of the attacker by construction and cheap by default. |
| **Check-pack boundary** (`checkpacks/`) | The domain knowledge — what counts as safe on which route, for which principal, what PHI looks like, what "in scope" means. This is the part that is genuinely specific to a clinical co-pilot, and keeping it behind one interface is what keeps the core target-agnostic. |
| **Append-only event ledger** (`stores/ledger.py`) | Thin over SQLite, but the two properties that matter are not off-the-shelf: a **least-privilege writer table** (each agent may append only its own event types) and **PHI masking on every write path**. Roughly 100 lines, and both properties are gate-ledgered. |
| **OIDC flow orchestration** (`auth/oidc.py`) | The *crypto* is PyJWT; the *flow* is ours, because Authlib and friends assume a Flask/Django session and a cookie model this service does not have. What is built is the state machine: single-use flow state, double-submit `state` cookie, PKCE pair, and deny-by-default RBAC. Verification itself was never hand-rolled. |
| **Eval dataset format + coverage matrix** | Needed dual OWASP axes (web + LLM), a per-case reproduction manifest, and — added after a live run made it necessary — the distinction between *defended*, *held back for target safety*, and *target unavailable*. No existing scanner report format carries that third axis. |

## Built as a thin seam (adopt-later)

| Seam | What it buys |
|---|---|
| `TargetAdapter` (`adapters/base.py`) | The core never speaks HTTP to the co-pilot directly. Testing a different target is a new adapter + check-pack; the engine is untouched. It is also where the immutable allow-list lives, so "attack only this origin" is structural rather than a convention. |
| `CheckPack` (`checkpacks/base.py`) | See above — the domain seam. |
| `EventLedger` / `VulnDB` interfaces | Narrow on purpose: `append` / `events` / `write` / `get`. That narrowness is the Postgres swap, and it is the reason the 10K-scale plan in `ARCHITECTURE.md` is a paragraph and not a rewrite. |
| `LlmComplianceCheck` (a `Callable`) | The Judge's paid rung is a function type, not a class hierarchy. Tests inject a stub; production injects Bedrock; the calibration harness injects the real one and scores it. Same seam, three uses. |

## Two decisions worth defending explicitly

**Building the mutation engine instead of using an LLM to generate attacks.** The tempting version
of this project generates every attack with a model. It would be less reproducible, far more
expensive, and — the real objection — unfalsifiable: when the model generates both the attack and
the notion of success, a run cannot be re-run to check the finding. Deterministic generation is the
bulk of the attack surface here, and a model is used only where determinism genuinely cannot reach:
seeding novel `/chat` phrasings, and the one semantic Judge rung. Both are opt-in, batched, and
cost-capped. The measured consequence is in `docs/LOAD_TEST.md` — the deterministic pipeline runs at
~568 attacks/second, and a single paid rung call costs ~1.3 s.

**Not adopting an off-the-shelf DAST scanner as the engine.** A scanner would have produced findings
faster. It would also have produced the findings in `docs/SCAN_TRIAGE.md`: fourteen pattern matches,
two of which mattered, none of which knew what a patient scope is. The thing that is hard about
red-teaming a clinical AI is not sending requests — it is deciding whether the answer that came back
was a breach. That is what was built.
