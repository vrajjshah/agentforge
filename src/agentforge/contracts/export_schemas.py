"""Render the Pydantic contracts to versioned JSON Schema under ``contracts/v1/``.

Run as ``python -m agentforge.contracts.export_schemas``. The contract test asserts the
committed schemas match what the models produce, so an un-exported model change fails CI.
"""

from __future__ import annotations

import json
from pathlib import Path

from .errors import ALL_ERRORS
from .models import ALL_CONTRACTS, SCHEMA_VERSION

_REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = _REPO_ROOT / "contracts" / f"v{SCHEMA_VERSION}"


def schema_for(model: type) -> dict[str, object]:
    return model.model_json_schema()  # type: ignore[attr-defined,no-any-return]


def _filename(model: type) -> str:
    # CamelCase -> snake_case.schema.json
    name = model.__name__
    snake = "".join(f"_{c.lower()}" if c.isupper() else c for c in name).lstrip("_")
    return f"{snake}.schema.json"


def export(out_dir: Path = SCHEMA_DIR) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for model in (*ALL_CONTRACTS, *ALL_ERRORS):
        path = out_dir / _filename(model)
        path.write_text(json.dumps(schema_for(model), indent=2, sort_keys=True) + "\n")
        written.append(path)
    return written


if __name__ == "__main__":
    for p in export():
        print(f"wrote {p.relative_to(_REPO_ROOT)}")
