"""Provider factory — maps provider name to implementation."""

from __future__ import annotations

from injection_fuzzer.models import RunConfig
from injection_fuzzer.providers.base import Provider


def make_provider(config: RunConfig) -> Provider:
    name = config.provider.lower()
    if name == "openai":
        from injection_fuzzer.providers.openai import OpenAIProvider
        return OpenAIProvider(config)
    elif name == "anthropic":
        from injection_fuzzer.providers.anthropic import AnthropicProvider
        return AnthropicProvider(config)
    elif name == "generic":
        from injection_fuzzer.providers.generic import GenericProvider
        return GenericProvider(config)
    else:
        raise ValueError(
            f"Unknown provider '{name}'. Choose from: openai, anthropic, generic"
        )
