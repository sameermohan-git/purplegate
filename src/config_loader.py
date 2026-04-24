"""Loads + validates consumer config and allowlist."""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

import yaml
from jsonschema import validate

_ROOT = Path(__file__).resolve().parent.parent
_DEFAULTS_PATH = _ROOT / "config" / "defaults.yml"
_CONFIG_SCHEMA_PATH = _ROOT / "config" / "schemas" / "config.schema.json"


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def load_defaults() -> dict[str, Any]:
    return _load_yaml(_DEFAULTS_PATH)


def load_consumer_config(config_path: Path) -> dict[str, Any]:
    """Load + schema-validate the consumer's .purplegate/config.yml.

    Raises FileNotFoundError if the file is absent — the orchestrator catches
    that and falls back to defaults.
    """
    if not config_path.exists():
        raise FileNotFoundError(f"config not found: {config_path}")
    cfg = _load_yaml(config_path)
    schema = json.loads(_CONFIG_SCHEMA_PATH.read_text())
    validate(instance=cfg, schema=schema)
    return cfg


class AllowlistEntry:
    __slots__ = ("finding_id", "reason", "expires", "acknowledged_by")

    def __init__(self, data: dict[str, Any]) -> None:
        self.finding_id = data.get("finding_id", "")
        self.reason = data.get("reason", "")
        self.expires = data.get("expires")
        self.acknowledged_by = data.get("acknowledged_by", "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "reason": self.reason,
            "expires": str(self.expires) if self.expires else None,
            "acknowledged_by": self.acknowledged_by,
        }


class AllowlistError(ValueError):
    """Raised when an allowlist entry fails policy checks."""


def load_allowlist(
    allowlist_path: Path,
    *,
    max_expiry_days: int = 365,
    min_reason_length: int = 20,
    today: date | None = None,
) -> list[AllowlistEntry]:
    """Load the allowlist + enforce policy.

    Raises AllowlistError on any invalid entry. The gate treats that as fatal
    — a bad allowlist fails CI with a specific error, not a silent skip.
    """
    if not allowlist_path.exists():
        return []
    data = yaml.safe_load(allowlist_path.read_text()) or []
    if not isinstance(data, list):
        raise AllowlistError(f"{allowlist_path}: allowlist must be a YAML list")

    today = today or date.today()
    entries: list[AllowlistEntry] = []

    for i, raw in enumerate(data):
        if not isinstance(raw, dict):
            raise AllowlistError(f"{allowlist_path}#{i}: entry must be a mapping")

        entry = AllowlistEntry(raw)
        errors: list[str] = []

        if not entry.finding_id:
            errors.append("missing finding_id")
        if not entry.reason or len(entry.reason) < min_reason_length:
            errors.append(f"reason must be at least {min_reason_length} characters")
        if not entry.acknowledged_by:
            errors.append("missing acknowledged_by")
        if not entry.expires:
            errors.append("missing expires (every entry requires an expiry)")
        else:
            exp = entry.expires if isinstance(entry.expires, date) else date.fromisoformat(str(entry.expires))
            days_ahead = (exp - today).days
            if days_ahead < 0:
                errors.append(f"expires {entry.expires} is already past — renew with a new justification")
            elif days_ahead > max_expiry_days:
                errors.append(f"expires {entry.expires} is more than {max_expiry_days} days out")

        if errors:
            bullets = "; ".join(errors)
            raise AllowlistError(
                f"{allowlist_path}#{i} ({entry.finding_id or '<no-id>'}): {bullets}"
            )

        entries.append(entry)

    return entries


def merge_defaults(consumer: dict[str, Any], defaults: dict[str, Any]) -> dict[str, Any]:
    """Shallow-merge consumer config over defaults — consumer wins.

    Deep-merge would be nicer but adds invisible behavior; stay obvious for now.
    """
    out = dict(defaults)
    for k, v in consumer.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = {**out[k], **v}
        else:
            out[k] = v
    return out
