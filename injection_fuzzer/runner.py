"""Async test runner — sends payloads to the provider and collects results."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator

from injection_fuzzer.evaluator import evaluate, evaluate_error
from injection_fuzzer.models import Payload, Report, Result, RunConfig
from injection_fuzzer.providers.base import Provider
from injection_fuzzer.providers.factory import make_provider


async def _run_single(
    provider: Provider,
    payload: Payload,
    system_prompt: str,
) -> Result:
    """Execute one payload and return the scored result."""
    try:
        start = time.perf_counter()
        response_text, _raw = await provider.send(payload.messages, system_prompt)
        elapsed_ms = (time.perf_counter() - start) * 1000
        result = evaluate(payload, response_text, elapsed_ms)
        result.raw_response = _raw
        return result
    except Exception as exc:  # noqa: BLE001 - any provider error is recorded as a result
        return evaluate_error(payload, str(exc))


async def run_payloads(
    config: RunConfig,
    payloads: list[Payload],
) -> AsyncIterator[Result]:
    """Run all payloads with bounded concurrency, yielding results as they complete."""
    provider = make_provider(config)
    semaphore = asyncio.Semaphore(config.max_concurrent)

    async def _bounded(p: Payload) -> Result:
        async with semaphore:
            sys_prompt = p.system_prompt or config.system_prompt
            return await _run_single(provider, p, sys_prompt)

    tasks = [asyncio.create_task(_bounded(p)) for p in payloads]

    for coro in asyncio.as_completed(tasks):
        result = await coro
        yield result

    await provider.close()


async def run(config: RunConfig, payloads: list[Payload]) -> Report:
    """Run all payloads and return a complete report."""
    results: list[Result] = []
    async for result in run_payloads(config, payloads):
        results.append(result)
    # Sort by original payload order
    payload_order = {p.id: i for i, p in enumerate(payloads)}
    results.sort(key=lambda r: payload_order.get(r.payload.id, 999))
    return Report(config=config, results=results)
