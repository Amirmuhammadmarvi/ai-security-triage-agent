"""
LLM client abstraction.

Wraps any OpenAI-compatible Chat Completions endpoint (OpenAI, Azure OpenAI,
local models via Ollama/LM Studio, OpenRouter, etc.) behind a small interface.
The provider/base URL and model are configured purely through environment
variables so no secrets ever live in the code.

    OPENAI_API_KEY   - your API key (required for live mode)
    OPENAI_BASE_URL  - optional, defaults to https://api.openai.com/v1
    LLM_MODEL        - optional, defaults to gpt-4o-mini
"""

from __future__ import annotations

import os
from typing import Any


class LLMConfigError(RuntimeError):
    """Raised when the LLM client is used without the required configuration."""


class LLMClient:
    """Thin wrapper around an OpenAI-compatible Chat Completions API."""

    def __init__(self, model: str | None = None, base_url: str | None = None):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.base_url = base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self.model = model or os.getenv("LLM_MODEL", "gpt-4o-mini")
        self._client = None

    @property
    def available(self) -> bool:
        """True when an API key is present, i.e. live mode is possible."""
        return bool(self.api_key)

    def _ensure_client(self):
        if self._client is not None:
            return
        if not self.api_key:
            raise LLMConfigError(
                "No OPENAI_API_KEY found. Set it in your environment or run with "
                "--demo to use the offline deterministic pipeline."
            )
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover
            raise LLMConfigError(
                "The 'openai' package is not installed. Run: pip install -r requirements.txt"
            ) from exc
        self._client = OpenAI(api_key=self.api_key, base_url=self.base_url)

    def chat(self, messages: list[dict[str, Any]], tools: list[dict] | None = None):
        """Send one Chat Completions request and return the raw response."""
        self._ensure_client()
        kwargs: dict[str, Any] = {"model": self.model, "messages": messages}
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        return self._client.chat.completions.create(**kwargs)
