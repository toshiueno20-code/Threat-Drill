"""Gemini API client wrapper.

VULNERABILITIES:
- [LLM01] No prompt injection filtering on user input
- [LLM02] Model output returned without sanitization — can leak sensitive data
- [LLM05] Raw model output rendered without escaping
- [LLM10] No rate limiting, no token budget, no timeout
"""

import json
from typing import Any

import httpx

from app.config import GEMINI_API_KEY, GEMINI_MODEL, SYSTEM_PROMPT


class GeminiChat:
    """Stateful chat wrapper around Gemini API."""

    def __init__(self):
        self.history: list[dict[str, str]] = []
        self.api_key = GEMINI_API_KEY
        self.model = GEMINI_MODEL
        # [VULN: LLM10 - No conversation length limit]
        # [VULN: LLM10 - No token budget tracking]

    async def send_message(self, user_message: str) -> str:
        """Send a message to Gemini and return the response.

        VULNERABILITIES:
        - No input validation or sanitization
        - No prompt injection detection
        - No output filtering
        - Unlimited conversation history (memory exhaustion)
        """
        # [VULN: LLM01 - User input passed directly without any filtering]
        self.history.append({"role": "user", "parts": [{"text": user_message}]})

        payload = {
            "contents": [
                {"role": "user", "parts": [{"text": SYSTEM_PROMPT}]},
                {"role": "model", "parts": [{"text": "了解しました。"}]},
                *self.history,
            ],
            "generationConfig": {
                "temperature": 0.9,
                "topP": 0.95,
                "topK": 40,
                # [VULN: LLM10 - No maxOutputTokens limit]
                "maxOutputTokens": 65536,
            },
            # [VULN: LLM01 - No safety settings configured]
        }

        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(url, json=payload)
                data = response.json()

            if "candidates" in data and data["candidates"]:
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                # [VULN: LLM02/LLM05 - No output sanitization — raw model output]
                self.history.append({"role": "model", "parts": [{"text": text}]})
                return text

            if "error" in data:
                return f"APIエラー: {data['error'].get('message', 'Unknown error')}"

            return "応答を生成できませんでした。"

        except httpx.TimeoutException:
            return "タイムアウトしました。もう一度お試しください。"
        except Exception as e:
            # [VULN: A09 - Detailed error messages expose internals]
            return f"エラーが発生しました: {type(e).__name__}: {str(e)}"

    def get_history(self) -> list[dict]:
        """Return full conversation history.

        [VULN: LLM02 - Exposes full history including system prompt context]
        """
        return self.history

    def clear_history(self) -> None:
        self.history = []


class ToolExecutor:
    """AI tool execution — deliberately overpowered.

    VULNERABILITIES:
    - [LLM06] Excessive agency — AI can execute system commands
    - [A03]   Command injection via tool arguments
    """

    TOOLS = {
        "search_database": {
            "description": "Search the internal database",
            "parameters": {"query": "SQL query to execute"},
        },
        "send_email": {
            "description": "Send an email to anyone",
            "parameters": {"to": "email", "subject": "subject", "body": "body"},
        },
        "execute_command": {
            "description": "Execute a system command",
            "parameters": {"command": "shell command"},
        },
        "read_file": {
            "description": "Read any file on the system",
            "parameters": {"path": "file path"},
        },
        "write_file": {
            "description": "Write content to any file",
            "parameters": {"path": "file path", "content": "file content"},
        },
        "http_request": {
            "description": "Make HTTP requests to any URL",
            "parameters": {"url": "target URL", "method": "GET/POST"},
        },
    }

    @classmethod
    async def execute(cls, tool_name: str, args: dict[str, Any]) -> str:
        """Execute a tool by name.

        [VULN: LLM06 - No permission checks, no sandboxing, no approval flow]
        [VULN: A03   - Arguments used without sanitization]
        """
        if tool_name == "search_database":
            query = args.get("query", "")
            # [VULN: A03 - SQL injection — query passed directly]
            return f"[SIMULATED] Executed SQL: {query}\nResults: 42 rows returned"

        if tool_name == "execute_command":
            command = args.get("command", "")
            # [VULN: A03/LLM06 - Command injection, no sandboxing]
            return f"[SIMULATED] Executed: {command}\nOutput: command completed"

        if tool_name == "read_file":
            path = args.get("path", "")
            # [VULN: A01 - Path traversal, no access control]
            return f"[SIMULATED] Read file: {path}\nContent: [file contents here]"

        if tool_name == "send_email":
            return f"[SIMULATED] Email sent to {args.get('to', '?')}"

        if tool_name == "write_file":
            return f"[SIMULATED] Written to {args.get('path', '?')}"

        if tool_name == "http_request":
            # [VULN: A10 - SSRF via AI-controlled HTTP requests]
            return f"[SIMULATED] HTTP {args.get('method','GET')} to {args.get('url', '?')}"

        return f"Unknown tool: {tool_name}"
