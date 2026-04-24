"""Prompt-injection probe — scaffold only.

Full implementation lives in a sibling PR (task #13) and wraps `promptfoo`
with the `owasp:llm` preset + Lakera Mosscap + Gandalf corpora, running each
payload against the configured endpoints and judging responses via an
isolated Claude call.

The scaffold module exposes the correct class so the orchestrator can wire
it, but returns an empty finding list when LLM is not configured.
"""
from __future__ import annotations

import logging

from src.models import Finding, Probe
from src.probes.base import BaseProbe

log = logging.getLogger(__name__)


class PromptInjectionProbe(BaseProbe):
    name = Probe.PROMPT_INJECTION

    def run(self) -> list[Finding]:
        if self.ctx.llm_provider == "none" or not self.ctx.llm_api_key:
            log.info("Prompt-injection probe: LLM provider=%s; skipping.", self.ctx.llm_provider)
            return []

        from src.judge.judge import run_prompt_injection

        return run_prompt_injection(self.ctx)
