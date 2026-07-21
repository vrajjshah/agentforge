"""The docs must tell one story. A number that disagrees with itself discredits every other number.

`docs/EXPLOIT_LEDGER.md` is the declared single source of truth for the seeded ground truth: eight
defects, six fixed on the deployed HEAD, two open by design. Those counts were restated by hand in
four other places and had already drifted — THREAT_MODEL said "four of the six" in one paragraph and
"six ... of eight" in another, inside the same document. This test is the cheap check that catches
the next drift.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_LEDGER = _ROOT / "docs" / "EXPLOIT_LEDGER.md"


def _ledger_counts() -> tuple[int, int, int]:
    """(total, fixed, open) read from the ledger's own table — not from prose."""
    rows = [ln for ln in _LEDGER.read_text().splitlines()
            if ln.startswith("| `") and "|" in ln[3:]]
    fixed = sum(1 for r in rows if "**fixed**" in r)
    opened = sum(1 for r in rows if "**open" in r)
    return len(rows), fixed, opened


def test_the_ledger_table_is_the_source_of_truth() -> None:
    total, fixed, opened = _ledger_counts()
    assert (total, fixed, opened) == (8, 6, 2), (
        f"the ledger table now says {total} seeds / {fixed} fixed / {opened} open. That is allowed "
        "— but every restatement below must be updated to match, and so must this expectation."
    )


def test_no_document_contradicts_the_ledger_counts() -> None:
    """Any 'N of the M ... fixed' claim must agree with the table.

    Scanned over whitespace-collapsed text rather than line by line: the claim that actually drifted
    had "six of the eight named" on one line and "fixed on the deployed HEAD" on the next, so a
    per-line check sailed straight past it. Scoped to a proximity window so that "Every one of the
    eight seed defects shares one shape" — a sentence about all eight, not a count of the fixed
    ones — does not trip it.
    """
    total, fixed, _ = _ledger_counts()
    words = {"two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8}
    claim = re.compile(r"\b(\w+) of the (\w+)\b(?=.{0,120}?\bfixed\b)", re.I | re.S)
    offenders = []
    for path in (_ROOT / "README.md", _ROOT / "ARCHITECTURE.md", _ROOT / "THREAT_MODEL.md",
                 _ROOT / "src" / "agentforge" / "seeds" / "seeds.py", _LEDGER):
        text = " ".join(path.read_text().split())
        for a, b in claim.findall(text):
            got = (words.get(a.lower()), words.get(b.lower()))
            if None in got:
                continue                       # not a numeric claim
            if got != (fixed, total):
                offenders.append(f"{path.name} claims '{a} of the {b}'")
    assert not offenders, (
        f"the ledger says {fixed} of {total} are fixed; these disagree: " + "; ".join(offenders))


def test_seed_module_states_the_same_totals() -> None:
    total, fixed, _ = _ledger_counts()
    doc = (_ROOT / "src" / "agentforge" / "seeds" / "seeds.py").read_text()[:600]
    assert f"{total} real" in doc, "the seeds module must state the ledger's total"
    assert "Six of the eight are already fixed" in doc
