"""OpenAI-compatible provider (also works for Azure, vLLM, Ollama, etc.)."""

from __future__ import annotations

from typing import Any

import httpx

from injection_fuzzer.models import RunConfig
from injection_fuzzer.providers.base import Provider


class OpenAIProvider(Provider):
    def __init__(self, config: RunConfig) -> None:
        super().__init__(config)
        base = config.base_url or "https://api.openai.com/v1"
        self._url = f"{base.rstrip('/')}/chat/completions"
        self._client = httpx.AsyncClient(
            timeout=config.timeout_seconds,
            headers={
                "Authorization": f"Bearer {config.api_key}",
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
        text = data["choices"][0]["message"]["content"] or ""
        return text, data

    async def close(self) -> None:
        await self._client.aclose()
