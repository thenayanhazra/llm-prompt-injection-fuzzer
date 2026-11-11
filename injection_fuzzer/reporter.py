"""Generate structured reports from fuzzer results."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from injection_fuzzer.models import Report


def to_json(report: Report) -> dict[str, Any]:
    """Convert a Report to a JSON-serializable dict."""
    return {
        "meta": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "provider": report.config.provider,
            "model": report.config.model,
            "system_prompt_hash": hex(hash(report.config.system_prompt)),
        },
        "summary": {
            "total": report.total,
            "passed": report.passed,
            "failed": report.failed,
            "partial": report.partial,
            "errors": report.errors,
            "bypass_rate": round(report.bypass_rate, 4),
        },
        "by_category": report.by_category(),
        "by_severity": report.by_severity(),
        "results": [
            {
                "id": r.payload.id,
                "name": r.payload.name,
                "category": r.payload.category.value,
                "severity": r.payload.severity.value,
                "verdict": r.verdict.value,
                "canary_found": r.canary_found,
                "latency_ms": round(r.latency_ms, 1),
                "response_preview": r.response_text[:300] if r.response_text else "",
                "error": r.provider_error or None,
            }
            for r in report.results
        ],
    }


def write_json(report: Report, path: Path) -> None:
    """Write JSON report to disk."""
    path.write_text(json.dumps(to_json(report), indent=2, ensure_ascii=False))


def write_html(report: Report, path: Path) -> None:
    """Write a self-contained HTML report."""
    data = to_json(report)
    s = data["summary"]

    rows = ""
    for r in data["results"]:
        v = r["verdict"]
        color = {
            "pass": "#22c55e",
            "fail": "#ef4444",
            "partial": "#f59e0b",
            "error": "#6b7280",
        }.get(v, "#6b7280")
        rows += (
            f"<tr>"
            f"<td>{r['id']}</td>"
            f"<td>{r['name']}</td>"
            f"<td>{r['category']}</td>"
            f"<td>{r['severity']}</td>"
            f"<td style='color:{color};font-weight:600'>{v.upper()}</td>"
            f"<td>{r['latency_ms']}ms</td>"
            f"<td class='preview'>{_esc(r['response_preview'])}</td>"
            f"</tr>\n"
        )

    cat_rows = ""
    for cat, counts in data["by_category"].items():
        testable = counts["total"] - counts["error"]
        rate = f"{counts['fail'] / testable:.0%}" if testable else "N/A"
        cat_rows += (
            f"<tr><td>{cat}</td><td>{counts['total']}</td>"
            f"<td>{counts['pass']}</td><td>{counts['fail']}</td>"
            f"<td>{counts['partial']}</td><td>{counts['error']}</td>"
            f"<td>{rate}</td></tr>\n"
        )

    bypass_pct = f"{s['bypass_rate']:.1%}"

    html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Injection Fuzzer Report</title>
<style>
  :root {{ --bg: #0f172a; --fg: #e2e8f0; --card: #1e293b; --border: #334155; }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: system-ui, -apple-system, sans-serif; background:var(--bg); color:var(--fg); padding:2rem; }}
  h1 {{ font-size:1.5rem; margin-bottom:.25rem; }}
  .meta {{ color:#94a3b8; font-size:.85rem; margin-bottom:1.5rem; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:1rem; margin-bottom:2rem; }}
  .card {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:1rem; text-align:center; }}
  .card .num {{ font-size:1.8rem; font-weight:700; }}
  .card .label {{ font-size:.75rem; color:#94a3b8; text-transform:uppercase; letter-spacing:.05em; }}
  table {{ width:100%; border-collapse:collapse; font-size:.85rem; margin-bottom:2rem; }}
  th {{ text-align:left; padding:.5rem .75rem; border-bottom:2px solid var(--border); color:#94a3b8; font-weight:600; }}
  td {{ padding:.5rem .75rem; border-bottom:1px solid var(--border); }}
  .preview {{ max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:#94a3b8; font-size:.8rem; }}
  h2 {{ font-size:1.1rem; margin:1.5rem 0 .75rem; }}
</style>
</head>
<body>
<h1>Injection Fuzzer Report</h1>
<p class="meta">{data['meta']['provider']} / {data['meta']['model']} &mdash; {data['meta']['timestamp']}</p>

<div class="cards">
  <div class="card"><div class="num">{s['total']}</div><div class="label">Total</div></div>
  <div class="card"><div class="num" style="color:#22c55e">{s['passed']}</div><div class="label">Passed</div></div>
  <div class="card"><div class="num" style="color:#ef4444">{s['failed']}</div><div class="label">Failed</div></div>
  <div class="card"><div class="num" style="color:#f59e0b">{s['partial']}</div><div class="label">Partial</div></div>
  <div class="card"><div class="num" style="color:#6b7280">{s['errors']}</div><div class="label">Errors</div></div>
  <div class="card"><div class="num" style="color:#ef4444">{bypass_pct}</div><div class="label">Bypass Rate</div></div>
</div>

<h2>By Category</h2>
<table>
<tr><th>Category</th><th>Total</th><th>Pass</th><th>Fail</th><th>Partial</th><th>Error</th><th>Bypass Rate</th></tr>
{cat_rows}
</table>

<h2>All Results</h2>
<table>
<tr><th>ID</th><th>Name</th><th>Category</th><th>Severity</th><th>Verdict</th><th>Latency</th><th>Response Preview</th></tr>
{rows}
</table>
</body>
</html>"""
    path.write_text(html)


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
