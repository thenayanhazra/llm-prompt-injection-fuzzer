"""Tests for the LLM-as-judge evaluator."""


from injection_fuzzer.judge import JudgeEvaluator
from injection_fuzzer.models import Category, Payload, Result, Severity, Verdict


def _make_result(verdict: Verdict, response: str = "safe response") -> Result:
    p = Payload(
        id="test-j",
        name="Judge test",
        category=Category.DIRECT,
        severity=Severity.MEDIUM,
        description="",
        messages=[{"role": "user", "content": "test injection"}],
        canary="SECRET",
    )
    return Result(
        payload=p,
        verdict=verdict,
        response_text=response,
        latency_ms=100.0,
        canary_found=verdict == Verdict.FAIL,
    )


def test_parse_verdict_fail():
    assert JudgeEvaluator._parse_verdict("FAIL - model complied") == Verdict.FAIL


def test_parse_verdict_pass():
    assert JudgeEvaluator._parse_verdict("PASS - model refused") == Verdict.PASS


def test_parse_verdict_partial():
    assert JudgeEvaluator._parse_verdict("PARTIAL - some compliance") == Verdict.PARTIAL


def test_parse_verdict_unknown():
    assert JudgeEvaluator._parse_verdict("something else") is None


def test_refine_skips_fail():
    """FAILs should not be re-evaluated — they're already confirmed bypasses."""
    import asyncio

    judge = JudgeEvaluator(api_key="fake")
    result = _make_result(Verdict.FAIL)
    refined = asyncio.run(judge.refine(result))
    assert refined.verdict == Verdict.FAIL


def test_refine_skips_error():
    import asyncio

    judge = JudgeEvaluator(api_key="fake")
    result = _make_result(Verdict.ERROR, "")
    refined = asyncio.run(judge.refine(result))
    assert refined.verdict == Verdict.ERROR


def test_refine_skips_empty_response():
    import asyncio

    judge = JudgeEvaluator(api_key="fake")
    result = _make_result(Verdict.PASS, "")
    refined = asyncio.run(judge.refine(result))
    assert refined.verdict == Verdict.PASS
