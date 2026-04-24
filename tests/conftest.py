"""Shared fixtures: paths + a ProbeContext factory."""
from __future__ import annotations

from pathlib import Path

import pytest

from src.config_loader import load_consumer_config, load_defaults, merge_defaults
from src.probes.base import ProbeContext

_REPO_ROOT = Path(__file__).resolve().parent.parent
_FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return _FIXTURES


@pytest.fixture
def make_context():
    def _build(fixture_name: str) -> ProbeContext:
        repo = _FIXTURES / fixture_name
        cfg = load_consumer_config(repo / ".agent-redblue" / "config.yml")
        defaults = load_defaults()
        merged = merge_defaults(cfg, defaults)
        return ProbeContext(
            repo_root=repo,
            config=merged,
            defaults=defaults,
            scan_paths=[repo],
            probe_output_dir=_REPO_ROOT / ".tmp-tests",
        )

    return _build
