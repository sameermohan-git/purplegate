"""Blue-team: evaluates red-team findings against defense context + allowlist."""

from src.blueteam.evaluator import apply_blueteam

__all__ = ["apply_blueteam"]
