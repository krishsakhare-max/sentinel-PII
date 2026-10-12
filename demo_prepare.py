"""Create non-confidential demo inputs and verify local prerequisites."""

from __future__ import annotations

import hashlib
from pathlib import Path

from attack_lab.fixtures import build_scenario
from diagnostics import main as run_diagnostics


def main() -> int:
    if run_diagnostics() != 0:
        return 1
    output = Path(__file__).resolve().parent / "demo_cache"
    output.mkdir(exist_ok=True)
    for scenario_id in ("ordinary_pii", "incomplete_extraction"):
        scenario = build_scenario(scenario_id)
        target = output / scenario.filename
        target.write_bytes(scenario.data)
        digest = hashlib.sha256(scenario.data).hexdigest()
        print(f"Prepared {target.name}: SHA-256 {digest}")
    print("Demo fixtures are synthetic and demo_cache/ is excluded from source control.")
    print("Warm Presidio/spaCy inside Streamlit by running Ordinary personal information in Attack Lab.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
