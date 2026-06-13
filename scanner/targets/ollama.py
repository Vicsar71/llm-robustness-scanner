"""Adapter for local models served by Ollama.

Talks to Ollama's REST API (http://localhost:11434 by default) via the
/api/generate endpoint.
"""

from __future__ import annotations

import httpx

from .base import Target


class OllamaTarget(Target):
    """Target: a model running locally in Ollama."""

    def __init__(
        self,
        model: str,
        system_prompt: str = "",
        host: str = "http://localhost:11434",
        temperature: float = 0.0,
        timeout: float = 300.0,
    ) -> None:
        self.model = model
        self.name = f"ollama:{model}"
        self.system_prompt = system_prompt
        self.host = host.rstrip("/")
        self.temperature = temperature
        self.timeout = timeout

    def generate(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": self.system_prompt,
            "stream": False,
            # temperature 0 = responses as deterministic as possible, so the
            # scan is reproducible across runs.
            "options": {"temperature": self.temperature},
        }
        resp = httpx.post(
            f"{self.host}/api/generate", json=payload, timeout=self.timeout
        )
        resp.raise_for_status()
        return resp.json().get("response", "")
