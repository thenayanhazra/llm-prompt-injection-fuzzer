"""Load run configuration from YAML files."""

from __future__ import annotations

from pathlib import Path

import yaml

from injection_fuzzer.models import RunConfig


def load_config(path: Path) -> RunConfig:
    """Parse a YAML config file into a RunConfig."""
    raw = yaml.safe_load(path.read_text())
    return RunConfig(
        provider=raw["provider"],
        model=raw["model"],
        api_key=raw.get("api_key", ""),
        base_url=raw.get("base_url", ""),
        system_prompt=raw.get("system_prompt", RunConfig.system_prompt),
        categories=raw.get("categories", []),
        timeout_seconds=raw.get("timeout_seconds", 30.0),
        max_concurrent=raw.get("max_concurrent", 5),
        temperature=raw.get("temperature", 0.0),
    )
