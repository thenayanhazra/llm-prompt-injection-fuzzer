"""Tests for the injection fuzzer core logic."""

import pytest

from injection_fuzzer.evaluator import evaluate, evaluate_error
from injection_fuzzer.models import Category, Payload, Report, RunConfig, Severity, Verdict
from injection_fuzzer.payloads.corpus import load_all_payloads, load_payloads

# ---------------------------------------------------------------------------
# Payload corpus
# ---------------------------------------------------------------------------


def test_load_all_payloads_non_empty():
    payloads = load_all_payloads()
    assert len(payloads) > 20


def test_all_payloads_have_unique_ids():
    payloads = load_all_payloads()
    ids = [p.id for p in payloads]
    assert len(ids) == len(set(ids)), f"Duplicate IDs: {[x for x in ids if ids.count(x) > 1]}"


def test_all_payloads_have_canary():
    for p in load_all_payloads():
        assert p.canary, f"Payload {p.id} has empty canary"


def test_all_payloads_have_messages():
    for p in load_all_payloads():
        assert len(p.messages) > 0, f"Payload {p.id} has no messages"


def test_filter_by_category():
    direct = load_payloads(["direct"])
    assert all(p.category == Category.DIRECT for p in direct)
    assert len(direct) > 0

    indirect = load_payloads(["indirect"])
    assert all(p.category == Category.INDIRECT for p in indirect)


def test_filter_empty_returns_all():
    assert len(load_payloads([])) == len(load_all_payloads())
    assert len(load_payloads(None)) == len(load_all_payloads())


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------


def _make_payload(canary: str = "TEST_CANARY", pid: str = "test-001") -> Payload:
    return Payload(
        id=pid,
        name="Test",
        category=Category.DIRECT,
        severity=Severity.MEDIUM,
        description="A test payload",
        messages=[{"role": "user", "content": "test"}],
        canary=canary,
    )


def test_evaluate_pass():
    p = _make_payload("SECRET_123")
    r = evaluate(p, "I cannot do that. Here is a helpful response instead.", 100.0)
    assert r.verdict == Verdict.PASS
    assert not r.canary_found


def test_evaluate_fail_exact():
    p = _make_payload("SECRET_123")
    r = evaluate(p, "Sure! SECRET_123", 50.0)
    assert r.verdict == Verdict.FAIL
    assert r.canary_found


def test_evaluate_fail_case_insensitive():
    p = _make_payload("SECRET_123")
    r = evaluate(p, "here it is: secret_123 done", 50.0)
    assert r.verdict == Verdict.FAIL
    assert r.canary_found


def test_evaluate_error():
    p = _make_payload()
    r = evaluate_error(p, "Connection refused")
    assert r.verdict == Verdict.ERROR
    assert r.provider_error == "Connection refused"


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def test_report_metrics():
    p1 = _make_payload(pid="t1")
    p2 = _make_payload(pid="t2")
    p3 = _make_payload(pid="t3")

    from injection_fuzzer.models import Result

    results = [
        Result(payload=p1, verdict=Verdict.PASS, response_text="ok", latency_ms=10, canary_found=False),
        Result(payload=p2, verdict=Verdict.FAIL, response_text="canary", latency_ms=20, canary_found=True),
        Result(payload=p3, verdict=Verdict.ERROR, response_text="", latency_ms=0, canary_found=False, provider_error="timeout"),
    ]

    config = RunConfig(provider="openai", model="test", api_key="x")
    report = Report(config=config, results=results)

    assert report.total == 3
    assert report.passed == 1
    assert report.failed == 1
    assert report.errors == 1
    # Bypass rate: 1 fail / 2 testable (total - errors)
    assert report.bypass_rate == pytest.approx(0.5)


def test_report_by_category():
    p1 = _make_payload(pid="t1")
    p1.category = Category.DIRECT
    p2 = _make_payload(pid="t2")
    p2.category = Category.INDIRECT

    from injection_fuzzer.models import Result

    results = [
        Result(payload=p1, verdict=Verdict.PASS, response_text="", latency_ms=10, canary_found=False),
        Result(payload=p2, verdict=Verdict.FAIL, response_text="", latency_ms=10, canary_found=True),
    ]
    config = RunConfig(provider="openai", model="test", api_key="x")
    report = Report(config=config, results=results)

    cats = report.by_category()
    assert "direct" in cats
    assert "indirect" in cats
    assert cats["direct"]["pass"] == 1
    assert cats["indirect"]["fail"] == 1
