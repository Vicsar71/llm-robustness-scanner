"""Load the target configuration from a YAML file."""

from __future__ import annotations

from pathlib import Path

import yaml

from .models import TargetConfig


def load_target_config(path: str | Path) -> TargetConfig:
    """Read a target YAML file and validate it as a TargetConfig."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return TargetConfig(**data)
