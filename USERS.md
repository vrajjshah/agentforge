# Users — who AgentForge serves, and why automation is the right call

AgentForge is a continuous adversarial-evaluation platform for teams that ship AI systems into
high-stakes settings. Its first customer is a hospital's **AI Clinical Co-Pilot**, but the users
below generalize to any org running an LLM agent against sensitive data.

## Primary users

### 1. The Application Security Engineer (the platform's operator)
- **Job:** keep an AI system safe under adversarial pressure — before *and* after every deploy.
- **Workflow:** define the target adapter + check-pack once; let the Orchestrator run coverage-
  driven campaigns; triage the confirmed findings the Documentation agent files; approve fixes.
- **What they get:** reproducible exploits with minimal repro steps, a coverage matrix showing
  *where testing is thin*, and a regression suite that fails on the security property (not a status
  code) so a "fixed" bug can't quietly return.

### 2. The Clinical-System Engineering Lead (owns the co-pilot / the fixes)
- **Job:** ship features fast without regressing safety on a system physicians depend on.
- **Workflow:** receives a `VulnReport` — unique id, severity, **clinical impact**, minimal
  reproducible sequence, observed vs expected, recommended remediation — reproducible by an
  engineer who wasn't present. Fixes on a branch; the platform validates the fix and adds a
  regression drill. The must-fix loop is **discover → propose fix → human-approve → validate →
  regress → close**.

### 3. The Security/Compliance Reviewer — the "hospital CISO" (the accept/reject authority)
- **Job:** decide whether to trust this platform with continuous testing of systems physicians
  depend on. Reads the threat model, the AI-use disclosure, the auth model (which agent uses which
  credential against which target), the gate ledger, and the cost analysis.
- **What they need:** honest degradation, human gates on irreversible actions, PHI kept out of
  logs/traces, and every gate proven to actually fire. The deliverable that matters is the one they
  could **defend in front of a CISO** — that is the design north star.

### 4. The Orchestrator agent itself (a non-human consumer)
The observability layer "is not just for humans — it is the data substrate the Orchestrator
reads." The event ledger's coverage matrix and finding-rate-per-dollar *are* the platform's own
inputs for deciding what to test next and when to halt.

## Why automation is the right solution (not a manual pentest or a static list)

1. **Attackers adapt continuously; a one-time pentest is a photograph of a moving target.** The
   co-pilot is hardened in parallel (a moving target — fingerprinted every run). Only a system that
   re-runs on every version change catches a regression the day it lands, not at the next quarterly
   audit.
2. **The failure mode is invisible to a human reviewing the UI.** Every seed defect shares one
   shape — *the visible state stays plausible while the record underneath is wrong* (a badge said
   "adjusted"; the chart said otherwise). A human eye on a screen cannot catch a cross-patient leak
   or a forged attribution; a deterministic boolean ("did patient B's DOB appear?") can, every time.
3. **Reproducibility is the whole point, and humans are bad at it.** Manual prompting produces
   findings that are hard to reproduce and fixes validated once and never retested. Deterministic,
   fixed-seed generation makes an eval run byte-identical between machines; a confirmed exploit
   becomes a permanent regression drill.
4. **Scale and cost need a machine.** 100K live attacks is ~$7.1K and ~50 h of target inference —
   only worth spending under a coverage-driven Orchestrator with a cost circuit-breaker, not a human
   clicking through payload lists.
5. **Consistency across runs and versions** — the same criteria, applied by a tool-less Judge whose
   oracle is a versioned policy, is the only way to say "the target got *more* resilient" and mean
   it. A human grader drifts; a frozen ground-truth set with drift detection does not.

**Automation does not remove the human — it puts the human where judgment matters:** approving a
critical finding, approving a fix merge, and calibrating the Judge. Everything deterministic runs
without them; everything irreversible waits for them.

## Static payload lists (Garak, canned jailbreak corpora) are a seed, not the product

We **reuse** probe corpora as seed cases, but a static list has no autonomous mutation, no coverage-
driven prioritization, and no clinical success criteria (cross-patient PHI, the confirm-to-chart
write path). Those three — adaptive hunt + clinical judging + coverage orchestration — have no
off-the-shelf answer, which is why the custom agents are justified (see `README` build-vs-configure).
