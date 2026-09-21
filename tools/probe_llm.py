#!/usr/bin/env python3
"""Throwaway probe: what does the newsletter's LLM server actually answer?

Not part of the pipeline; used to confirm the reasoning-model behaviour
described on the card (content: null with thinking on, prose with it off).
"""
from __future__ import annotations

import json
import os
import urllib.request

BASE = os.environ.get("CYBERWATCH_LLM_BASE_URL", "http" + "://localhost:8001/v1")


def post(path: str, payload: dict | None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        BASE.rstrip("/") + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST" if data else "GET",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def main() -> int:
    try:
        models = post("/models", None)
    except Exception as exc:  # noqa: BLE001
        print("models: ERR", type(exc).__name__, exc)
        return 1
    names = [m.get("id") for m in models.get("data", []) if isinstance(m, dict)]
    print("models:", names)
    if not names:
        return 1
    model = names[0]

    messages = [
        {"role": "system", "content": "Answer in one sentence."},
        {"role": "user", "content": "Summarise: Cisco ISE lets unauthenticated attackers bypass auth via crafted API requests."},
    ]

    for label, extra in [
        ("thinking on (default)", {}),
        ("thinking off", {"chat_template_kwargs": {"enable_thinking": False}}),
    ]:
        payload = {"model": model, "messages": messages, "max_tokens": 200, **extra}
        try:
            body = post("/chat/completions", payload)
        except Exception as exc:  # noqa: BLE001
            print(f"{label}: ERR", type(exc).__name__, exc)
            continue
        choice = body["choices"][0]
        print(
            f"{label}: finish={choice.get('finish_reason')!r} "
            f"tokens={body.get('usage', {}).get('completion_tokens')} "
            f"content={choice['message'].get('content')!r}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
