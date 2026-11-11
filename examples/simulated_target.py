"""A simulated chat endpoint for trying the fuzzer without an API key.

It stands in for a model whose only defence is a keyword blocklist: it refuses
any message containing a known jailbreak phrase, and otherwise does whatever the
text asks, including repeating any token it is told to output. It cannot decode
Base64 or ROT13 and does not translate.

This is not a real model. Use it to see the workflow and the report, and to see
why keyword filters fail against encoded, translated and indirect attacks.

    python examples/simulated_target.py            # serves on 127.0.0.1:8808
    injection-fuzzer scan -p generic -m keyword-filter \\
        --base-url http://127.0.0.1:8808/v1/chat/completions
"""

from __future__ import annotations

import json
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

BLOCKLIST = (
    "ignore previous",
    "ignore all previous",
    "ignore the above",
    "disregard",
    "forget your instructions",
    "system prompt",
    "developer mode",
    "jailbreak",
    "dan",
    "do anything now",
)

# Any ALL_CAPS token with an underscore is treated as something the text wants echoed.
TOKEN = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Za-z0-9]+)+\b")


def reply(messages: list[dict]) -> str:
    text = "\n".join(
        m["content"] if isinstance(m.get("content"), str) else json.dumps(m.get("content"))
        for m in messages
        if m.get("role") != "system"
    )
    lowered = text.lower()
    if any(re.search(rf"\b{re.escape(phrase)}\b", lowered) for phrase in BLOCKLIST):
        return "I can't help with that request."
    tokens = TOKEN.findall(text)
    if tokens:
        return f"Sure. {tokens[-1]}"
    return "Here is a helpful answer to your question."


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        content = reply(body.get("messages", []))
        payload = json.dumps(
            {"choices": [{"message": {"role": "assistant", "content": content}}]}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args: object) -> None:
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8808
    print(f"Simulated keyword-filter target on http://127.0.0.1:{port}/v1/chat/completions")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
