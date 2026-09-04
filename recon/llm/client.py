"""Minimal client for a remote OpenAI-compatible chat endpoint.

The endpoint is a single config value (``RECON_LLM_BASE_URL`` etc.) so it can be
repointed - to a remote model, a local model, whatever - with no code
change. The client only ever *reads*: it sends the correlated Asset Graph and
returns analysis text. It cannot trigger scans or modify anything.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import httpx

from recon.config import get_settings


class LLMError(RuntimeError):
    pass


@dataclass
class LLMResult:
    content: str
    model: str
    usage: dict


class LLMClient:
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
        max_tokens: int | None = None,
    ) -> None:
        s = get_settings()
        self.base_url = (base_url or s.llm_base_url).rstrip("/")
        self.api_key = api_key if api_key is not None else s.llm_api_key
        self.model = model or s.llm_model
        self.timeout = timeout or s.llm_timeout_seconds
        self.max_tokens = s.llm_max_tokens if max_tokens is None else max_tokens

    async def chat(
        self, system: str, user: str, *, temperature: float = 0.2, json_mode: bool = False
    ) -> LLMResult:
        payload: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
        }
        if self.max_tokens and self.max_tokens > 0:
            payload["max_tokens"] = self.max_tokens
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/chat/completions", json=payload, headers=headers
                )
        except httpx.HTTPError as exc:
            raise LLMError(f"LLM endpoint unreachable: {exc}") from exc

        if resp.status_code >= 400:
            raise LLMError(f"LLM endpoint returned {resp.status_code}: {resp.text[:400]}")
        try:
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"unexpected LLM response shape: {exc}") from exc
        return LLMResult(
            content=content,
            model=data.get("model", self.model),
            usage=data.get("usage", {}),
        )
