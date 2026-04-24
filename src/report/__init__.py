"""Report generation (SARIF, Markdown, JSON) + severity gate."""

from src.report.gate import enforce_gate
from src.report.markdown import render_markdown
from src.report.sarif import render_sarif

__all__ = ["render_sarif", "render_markdown", "enforce_gate"]
