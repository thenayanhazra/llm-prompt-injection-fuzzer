"""Abstract base for LLM API providers."""

from __future__ import annotations

import abc
from typing import Any

from injection_fuzzer.models import RunConfig


class Provider(abc.ABC):
    """Send messages to an LLM endpoint and return the text response."""

    def __init__(self, config: RunConfig) -> None:
        self.config = config

    @abc.abstractmethod
    async def send(
        self,
        messages: list[dict[str, str]],
        system_prompt: str,
    ) -> tuple[str, dict[str, Any]]:
        """Send a conversation to the model.

        Returns:
            (response_text, raw_response_dict)
        """
        ...

    @abc.abstractmethod
    async def close(self) -> None:
        ...
