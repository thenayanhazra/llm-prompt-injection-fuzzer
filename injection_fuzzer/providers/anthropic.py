"""Anthropic Messages API provider."""

from __future__ import annotations

from typing import Any

import httpx

from injection_fuzzer.models import RunConfig
from injection_fuzzer.providers.base import Provider


class AnthropicProvider(Provider):
    def __init__(self, config: RunConfig) -> None:
        super().__init__(config)
        base = config.base_url or "https://api.anthropic.com"
        self._url = f"{base.rstrip('/')}/v1/messages"
        self._client = httpx.AsyncClient(
            timeout=config.timeout_seconds,
            headers={
                "x-api-key": config.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
        )

    async def send(
        self,
        messages: list[dict[str, str]],
        system_prompt: str,
    ) -> tuple[str, dict[str, Any]]:
        body = {
            "model": self.config.model,
            "system": system_prompt,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": 1024,
        }
        resp = await self._client.post(self._url, json=body)
        resp.raise_for_status()
        data = resp.json()
        # Extract text from content blocks
        text_parts = [
            block["text"]
            for block in data.get("content", [])
            if block.get("type") == "text"
        ]
        return "\n".join(text_parts), data

    async def close(self) -> None:
        await self._client.aclose()
