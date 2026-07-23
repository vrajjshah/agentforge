# Notice — scope of the licence, and of the reports

AgentForge is **MIT** ([LICENSE](LICENSE)). These notes were previously appended to `LICENSE`
itself, which stopped automated licence detection from recognising the MIT text; they live here
instead so the licence file is exactly the licence.

## What the licence covers

It covers the AgentForge platform in this repository. It does **not** cover the system under test:
the Clinical Co-Pilot and its OpenEMR fork live in a
[separate repository](https://github.com/vrajjshah/clinical-copilot) under their own licence
(OpenEMR is GPL-3.0-or-later), and no code from it is vendored here. The only coupling between the
two is an HTTP `TargetAdapter` and a check-pack describing the target's policy.

## The `reports/` directory

`reports/` contains vulnerability reproductions produced against an application I owned and
operated, in a sandbox seeded with synthetic patients only — **no real PHI, no real patients**.

That deployment has since been decommissioned and every finding is fixed and regression-guarded, so
the reproductions target nothing that exists; they are published as evidence of the work. This is
the ordinary disclosure lifecycle — **gate while the system is live, publish once it is closed** —
and it is described in full in [reports/README.md](reports/README.md).

The live dashboard now reflects that same decision: it runs with `AGENTFORGE_PUBLIC_REPORTS=1`, so
it no longer withholds what this repository publishes. The gate itself is unchanged in code and
still tested (`uv run pytest tests/test_web_gating.py`), it opens reads only — never the mutating
run trigger — and it governs again the moment anything is redeployed.

Running these reproductions, or anything derived from them, against a system you are not authorised
to test is your responsibility, not a use this licence grants.
