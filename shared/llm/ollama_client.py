"""Ollama local LLM client — async HTTP wrapper with tool-calling support.

Used by the ReAct executor for autonomous attack skill execution.
Gemini handles planning + analysis; Ollama handles MCP tool execution.
"""

import json
import os
from typing import Any

import aiohttp

from shared.utils import get_logger

logger = get_logger(__name__)

DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")
DEFAULT_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
DEFAULT_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "120"))


class OllamaClient:
    """Async client for Ollama REST API with tool-use (function calling) support.

    Ollama exposes an OpenAI-compatible ``/api/chat`` endpoint that supports
    ``tools`` for models with function-calling capability (qwen2.5, llama3.1,
    mistral, etc.).
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.1,
    ) -> dict[str, Any]:
        """Send a chat completion request.

        Args:
            messages: ``[{"role": "system"|"user"|"assistant"|"tool", "content": ...}]``
            tools: Ollama tool definitions (OpenAI function-calling format).
            temperature: Sampling temperature (low = deterministic).

        Returns:
            Full Ollama response dict.  The assistant message lives at
            ``response["message"]`` and may contain ``tool_calls``.
        """
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if tools:
            payload["tools"] = tools

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.post(
                f"{self.base_url}/api/chat",
                json=payload,
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    raise RuntimeError(f"Ollama API error ({resp.status}): {body}")
                return await resp.json()

    async def is_available(self) -> bool:
        """Return True if the Ollama server is reachable."""
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=5)
            ) as session:
                async with session.get(f"{self.base_url}/api/tags") as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def list_models(self) -> list[str]:
        """Return names of locally available models."""
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=5)
            ) as session:
                async with session.get(f"{self.base_url}/api/tags") as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()
                    return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Helper: convert MCP tool schema → Ollama/OpenAI function format
    # ------------------------------------------------------------------

    @staticmethod
    def mcp_tools_to_ollama(mcp_tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Convert PlaywrightMCPServer tool definitions to Ollama format.

        MCP format::

            {"name": "...", "description": "...", "input_schema": {...}}

        Ollama/OpenAI format::

            {"type": "function", "function": {"name": "...", "description": "...", "parameters": {...}}}
        """
        ollama_tools: list[dict[str, Any]] = []
        for t in mcp_tools:
            schema = t.get("input_schema", {})
            ollama_tools.append(
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t.get("description", ""),
                        "parameters": {
                            "type": schema.get("type", "object"),
                            "properties": schema.get("properties", {}),
                            "required": schema.get("required", []),
                        },
                    },
                }
            )
        return ollama_tools
