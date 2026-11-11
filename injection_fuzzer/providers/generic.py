"""Generic HTTP provider for custom LLM endpoints.

Sends an OpenAI-compatible payload by default.  Customize via config or
subclass for non-standard APIs.
"""

from __future__ import annotations

from typing import Any

import httpx

from injection_fuzzer.models import RunConfig
from injection_fuzzer.providers.base import Provider


class GenericProvider(Provider):
    """Sends OpenAI-shaped requests to any URL.  Use ``base_url`` in config."""

    def __init__(self, config: RunConfig) -> None:
        super().__init__(config)
        if not config.base_url:
            raise ValueError("generic provider requires base_url in config")
        self._url = config.base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            timeout=config.timeout_seconds,
            headers={
                "Authorization": f"Bearer {config.api_key}" if config.api_key else "",
                "Content-Type": "application/json",
            },
        )

    async def send(
        self,
        messages: list[dict[str, str]],
        system_prompt: str,
    ) -> tuple[str, dict[str, Any]]:
        full_messages = [{"role": "system", "content": system_prompt}] + messages
        body = {
            "model": self.config.model,
            "messages": full_messages,
            "temperature": self.config.temperature,
            "max_tokens": 1024,
        }
        resp = await self._client.post(self._url, json=body)
        resp.raise_for_status()
        data = resp.json()
        # Try OpenAI shape first, fall back to raw text
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError):
            text = data.get("text", data.get("response", str(data)))
        return text or "", data

    async def close(self) -> None:
        await self._client.aclose()
