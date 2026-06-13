"""Load the attack library from a YAML file."""

from __future__ import annotations

from pathlib import Path

import yaml

from ..models import Attack


def load_attacks(path: str | Path) -> list[Attack]:
    """Read a YAML file with a list of attacks and validate them as Attack objects."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("The attacks file must contain a YAML list.")
    return [Attack(**item) for item in data]
