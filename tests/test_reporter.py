"""Tests for report generation."""

import json
from pathlib import Path

from injection_fuzzer.models import (
    Category,
    Payload,
    Report,
    Result,
    RunConfig,
    Severity,
    Verdict,
)
from injection_fuzzer.reporter import to_json, write_html, write_json


def _sample_report() -> Report:
    p = Payload(
        id="test-001",
        name="Test payload",
        category=Category.DIRECT,
        severity=Severity.HIGH,
        description="A test",
        messages=[{"role": "user", "content": "test"}],
        canary="CANARY",
    )
    results = [
        Result(payload=p, verdict=Verdict.FAIL, response_text="CANARY found",
               latency_ms=123.4, canary_found=True),
    ]
    config = RunConfig(provider="openai", model="gpt-4o", api_key="x")
    return Report(config=config, results=results)


def test_to_json_structure():
    data = to_json(_sample_report())
    assert "meta" in data
    assert "summary" in data
    assert "results" in data
    assert data["summary"]["total"] == 1
    assert data["summary"]["failed"] == 1
    assert data["summary"]["bypass_rate"] == 1.0


def test_write_json(tmp_path: Path):
    path = tmp_path / "report.json"
    write_json(_sample_report(), path)
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["summary"]["total"] == 1


def test_write_html(tmp_path: Path):
    path = tmp_path / "report.html"
    write_html(_sample_report(), path)
    assert path.exists()
    html = path.read_text()
    assert "Injection Fuzzer Report" in html
    assert "test-001" in html
