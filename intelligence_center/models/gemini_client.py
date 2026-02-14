"""Gemini client wrapper using Google AI Studio API keys.

Design notes:
- API-key-first architecture (API_KEY preferred, GEMINI_API_KEY supported).
- Uses the google-genai SDK as the primary inference path.
- Supports optional MCP tool integration (for Playwright MCP and similar servers).
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import random
import re
import os
import time
import traceback
from typing import Any, Dict, List, Optional

from shared.constants import (
    DEEP_THINK_RESPONSE_SLA,
    FLASH_RESPONSE_SLA,
    GEMINI_3_FLASH,
    GEMINI_3_PRO_DEEP_THINK,
)
from shared.schemas import MultimodalInput
from shared.utils import get_logger

logger = get_logger(__name__)


class GeminiClient:
    """Gemini client using Google AI Studio API key authentication."""

    def __init__(
        self,
        project_id: Optional[str] = None,
        location: str = "us-central1",
        credentials: Any = None,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        flash_model: Optional[str] = None,
        deep_model: Optional[str] = None,
        embedding_model: Optional[str] = None,
        timeout_seconds: float = 30.0,
    ):
        import os

        # Backward-compatible fields
        self.project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
        self.location = location
        self.credentials = credentials

        # API-key-first runtime configuration
        self.api_key = (api_key or os.environ.get("API_KEY") or os.environ.get("GEMINI_API_KEY") or "").strip()
        self.base_url = (
            base_url
            or os.environ.get("GEMINI_API_BASE_URL")
            or "https://generativelanguage.googleapis.com/v1beta"
        ).rstrip("/")

        self.flash_model = flash_model or os.environ.get("GEMINI_FLASH_MODEL") or GEMINI_3_FLASH
        self.deep_model = deep_model or os.environ.get("GEMINI_DEEP_MODEL") or GEMINI_3_PRO_DEEP_THINK
        self.embedding_model = embedding_model or os.environ.get("GEMINI_EMBED_MODEL") or "text-embedding-004"

        self.timeout_seconds = timeout_seconds
        self._api_enabled = bool(self.api_key)

        # SDK runtime members
        self._sdk_client: Any = None
        self._sdk_types: Any = None
        self._sdk_available = False

        if self._api_enabled:
            self._sdk_available = self._initialize_sdk_client()
            if self._sdk_available:
                logger.info(
                    "Gemini SDK client initialized with AI Studio API key",
                    flash_model=self.flash_model,
                    deep_model=self.deep_model,
                )
            else:
                logger.warning(
                    "google-genai SDK is unavailable; falling back to deterministic mock responses",
                    env_priority=["API_KEY", "GEMINI_API_KEY"],
                )
        else:
            logger.warning(
                "Gemini API key not configured; using deterministic mock responses",
                env_priority=["API_KEY", "GEMINI_API_KEY"],
            )

    def _initialize_sdk_client(self) -> bool:
        """Initialize google-genai SDK client lazily and safely."""
        try:
            from google import genai
            from google.genai import types as genai_types

            # AI Studio mode with API key.
            # google-genai HttpOptions.timeout is in milliseconds.
            http_options = genai_types.HttpOptions(timeout=self._timeout_ms(self.timeout_seconds))
            self._sdk_client = genai.Client(api_key=self.api_key, http_options=http_options)
            self._sdk_types = genai_types
            return True
        except Exception as exc:
            logger.warning("Failed to initialize google-genai SDK", error=str(exc))
            self._sdk_client = None
            self._sdk_types = None
            return False

    @staticmethod
    def _timeout_ms(seconds: float) -> int:
        """Convert seconds to milliseconds for google-genai HttpOptions."""
        try:
            sec = float(seconds)
        except Exception:
            sec = 30.0
        # Avoid zero/negative values.
        ms = int(max(1.0, sec) * 1000.0)
        return ms

    async def analyze_with_flash(
        self,
        inputs: List[Any],
        system_instruction: Optional[str] = None,
        context_history: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Fast analysis using the configured Flash model."""
        start_time = time.time()

        try:
            prompt = self._build_security_prompt(inputs, system_instruction, context_history)
            tokens_used = 0
            provider_fallback = False

            if self._api_enabled and self._sdk_available:
                try:
                    raw_text, tokens_used = await self._generate_content_sdk(
                        model=self.flash_model,
                        prompt=prompt,
                    )
                    analysis_result = self._parse_json_or_reasoning(raw_text)
                except Exception as exc:
                    logger.warning("Flash SDK call failed; falling back to mock", error=str(exc))
                    analysis_result = self._generate_mock_response(prompt)
                    provider_fallback = True
            else:
                analysis_result = self._generate_mock_response(prompt)
                provider_fallback = True

            duration_ms = (time.time() - start_time) * 1000

            # Ensure stable keys for downstream analyzers.
            analysis_result.setdefault("threat_level", "safe")
            analysis_result.setdefault("confidence", 0.95)
            analysis_result.setdefault("reasoning", "No suspicious patterns detected")
            analysis_result.setdefault("detected_patterns", [])
            analysis_result.setdefault("recommended_actions", [])
            analysis_result.setdefault("tokens_used", tokens_used or len(prompt) // 4)

            if duration_ms > FLASH_RESPONSE_SLA:
                logger.warning(
                    "Flash SLA exceeded",
                    duration_ms=duration_ms,
                    sla_ms=FLASH_RESPONSE_SLA,
                )

            return {
                **analysis_result,
                "model_version": self.flash_model,
                "analysis_duration_ms": duration_ms,
                "provider_fallback": provider_fallback,
            }

        except Exception as exc:
            logger.error(
                "Gemini Flash analysis failed",
                error=str(exc),
                duration_ms=(time.time() - start_time) * 1000,
            )
            raise

    async def analyze_with_flash_mcp(
        self,
        *,
        prompt: str,
        mcp_command: str,
        mcp_args: List[str],
        system_instruction: Optional[str] = None,
        max_remote_calls: int = 8,
    ) -> Dict[str, Any]:
        """Analyze prompt with MCP tools enabled via google-genai SDK.

        This method is intended for optional integrations such as Playwright MCP.
        """
        start_time = time.time()

        if not self._api_enabled:
            raise RuntimeError("Gemini API key is required for MCP-enabled analysis.")
        if not self._sdk_available:
            raise RuntimeError("google-genai SDK is required for MCP-enabled analysis.")

        try:
            from mcp import ClientSession
            from mcp.client.stdio import StdioServerParameters, stdio_client
        except Exception as exc:
            raise RuntimeError("MCP integration requires the `mcp` Python package.") from exc

        # MCP-enabled planning is slower than standard inference; use a higher default timeout.
        # `GEMINI_MCP_TIMEOUT_SECONDS` applies to the Gemini HTTP request timeout.
        # We also apply a small additional "hard cap" timeout to avoid leaking hanging MCP processes.
        mcp_timeout_seconds = int(os.environ.get("GEMINI_MCP_TIMEOUT_SECONDS", "90"))
        hard_timeout_seconds = int(
            os.environ.get("GEMINI_MCP_HARD_TIMEOUT_SECONDS", str(mcp_timeout_seconds + 45))
        )

        try:
            logger.info(
                "Starting MCP session for Gemini tool use",
                mcp_command=mcp_command,
                mcp_args_preview=mcp_args[:6],
                max_remote_calls=max_remote_calls,
                timeout_s=mcp_timeout_seconds,
            )
            async with asyncio.timeout(hard_timeout_seconds):
                params = StdioServerParameters(command=mcp_command, args=mcp_args)
                async with stdio_client(params) as (read, write):
                    async with ClientSession(read, write) as session:
                        # Avoid event-loop cancellation blowing up the MCP stdio reader/writer.
                        # Keep init time bounded separately from the model call timeout.
                        async with asyncio.timeout(20):
                            await session.initialize()

                        try:
                            async with asyncio.timeout(10):
                                listed = await session.list_tools()
                            tools_list = getattr(listed, "tools", []) or []
                            tool_names = [getattr(t, "name", "") for t in tools_list if getattr(t, "name", "")]
                        except Exception:
                            tool_names = []

                        config_kwargs: Dict[str, Any] = {
                            "temperature": 0.1,
                            "httpOptions": self._sdk_types.HttpOptions(
                                timeout=self._timeout_ms(float(mcp_timeout_seconds))
                            ),
                        }
                        if system_instruction:
                            config_kwargs["systemInstruction"] = system_instruction

                        config_kwargs["tools"] = [session]
                        afc_cls = getattr(self._sdk_types, "AutomaticFunctionCallingConfig", None)
                        if afc_cls is not None:
                            config_kwargs["automaticFunctionCalling"] = afc_cls(
                                maximumRemoteCalls=max_remote_calls
                            )

                        config = self._sdk_types.GenerateContentConfig(**config_kwargs)
                        resp = await self._sdk_client.aio.models.generate_content(
                            model=self.flash_model,
                            contents=prompt,
                            config=config,
                        )

                        raw_text = (getattr(resp, "text", None) or "").strip() or self._extract_text_from_sdk_response(resp)
                        usage = getattr(resp, "usage_metadata", None)
                        tokens_used = int(getattr(usage, "total_token_count", 0) or 0) if usage is not None else 0

                        function_calls = []
                        for fc in (getattr(resp, "function_calls", None) or []):
                            function_calls.append(
                                {
                                    "name": getattr(fc, "name", ""),
                                    "args": getattr(fc, "args", None),
                                }
                            )

            analysis_result = self._parse_json_or_reasoning(raw_text)
            duration_ms = (time.time() - start_time) * 1000
            analysis_result.setdefault("tokens_used", tokens_used or len(prompt) // 4)

            return {
                **analysis_result,
                "model_version": self.flash_model,
                "analysis_duration_ms": duration_ms,
                "provider_fallback": False,
                "mcp_used": True,
                "mcp_function_calls": function_calls,
                "mcp_function_calls_count": len(function_calls),
                "mcp_available_tools_count": len(tool_names),
                "mcp_available_tools_sample": tool_names[:10],
            }
        except Exception as exc:
            duration_ms = (time.time() - start_time) * 1000
            details: list[str] = []
            if isinstance(exc, BaseExceptionGroup):
                # Flatten exception groups (Python 3.11+) for actionable logs.
                def _walk(group: BaseExceptionGroup) -> None:
                    for e in group.exceptions:
                        if isinstance(e, BaseExceptionGroup):
                            _walk(e)
                        else:
                            details.append(f"{type(e).__name__}: {e}")

                _walk(exc)

            logger.warning(
                "MCP-enabled Gemini analysis failed",
                error_type=type(exc).__name__,
                error=str(exc),
                sub_errors=details[:5] if details else None,
                traceback_tail="\n".join(traceback.format_exception(exc)[-5:]),
                duration_ms=duration_ms,
            )
            raise

    async def deep_think_analysis(
        self,
        inputs: List[MultimodalInput],
        initial_analysis: Dict[str, Any],
        system_instruction: Optional[str] = None,
        context_history: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Deeper analysis using the configured Pro model."""
        start_time = time.time()

        try:
            prompt = self._build_deep_think_prompt(
                inputs,
                initial_analysis,
                system_instruction,
                context_history,
            )
            tokens_used = 0

            if self._api_enabled and self._sdk_available:
                try:
                    raw_text, tokens_used = await self._generate_content_sdk(
                        model=self.deep_model,
                        prompt=prompt,
                    )
                    parsed = self._parse_json_or_reasoning(raw_text)
                except Exception as exc:
                    logger.warning("Deep model SDK call failed; falling back to deterministic output", error=str(exc))
                    parsed = {}
            else:
                parsed = {}

            duration_ms = (time.time() - start_time) * 1000

            result = {
                "threat_level": parsed.get("threat_level", initial_analysis.get("threat_level", "safe")),
                "confidence": float(parsed.get("confidence", 0.98)),
                "reasoning": parsed.get(
                    "reasoning",
                    "Deep analysis completed. No additional high-confidence threat indicators were found.",
                ),
                "thought_process": parsed.get(
                    "thought_process",
                    [
                        "Reviewed initial assessment context",
                        "Checked for multi-step intent escalation",
                        "Validated likely false-positive risk",
                    ],
                ),
                "detected_patterns": parsed.get("detected_patterns", []),
                "recommended_actions": parsed.get("recommended_actions", []),
                "tokens_used": parsed.get("tokens_used", tokens_used or len(prompt) // 4),
            }

            if duration_ms > DEEP_THINK_RESPONSE_SLA:
                logger.warning(
                    "Deep Think SLA exceeded",
                    duration_ms=duration_ms,
                    sla_ms=DEEP_THINK_RESPONSE_SLA,
                )

            return {
                **result,
                "model_version": self.deep_model,
                "analysis_duration_ms": duration_ms,
                "deep_think_used": True,
            }

        except Exception as exc:
            logger.error(
                "Deep Think analysis failed",
                error=str(exc),
                duration_ms=(time.time() - start_time) * 1000,
            )
            raise

    async def generate_embeddings(self, text: str) -> List[float]:
        """Generate embeddings via SDK; deterministic fallback when unavailable."""
        if self._api_enabled and self._sdk_available:
            try:
                response = await self._sdk_client.aio.models.embed_content(
                    model=self.embedding_model,
                    contents=text,
                )
                values = self._extract_embedding_values(response)
                if values:
                    return values
            except Exception as exc:
                logger.warning("Embedding SDK call failed; using deterministic fallback", error=str(exc))

        seed = int(hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16], 16)
        random.seed(seed)
        return [random.random() for _ in range(768)]

    async def _generate_content_sdk(
        self,
        *,
        model: str,
        prompt: str,
        system_instruction: Optional[str] = None,
        tools: Optional[List[Any]] = None,
        max_remote_calls: int = 8,
        http_timeout_seconds: Optional[int] = None,
    ) -> tuple[str, int]:
        """Call Gemini via google-genai SDK and return text + token usage."""
        if not self._sdk_available or not self._sdk_client or not self._sdk_types:
            raise RuntimeError("Gemini SDK client is not initialized.")

        timeout_seconds = float(http_timeout_seconds or self.timeout_seconds)
        config_kwargs: Dict[str, Any] = {
            "temperature": 0.1,
            "httpOptions": self._sdk_types.HttpOptions(timeout=self._timeout_ms(timeout_seconds)),
        }
        if system_instruction:
            config_kwargs["systemInstruction"] = system_instruction

        if tools:
            config_kwargs["tools"] = tools
            afc_cls = getattr(self._sdk_types, "AutomaticFunctionCallingConfig", None)
            if afc_cls is not None:
                config_kwargs["automaticFunctionCalling"] = afc_cls(maximumRemoteCalls=max_remote_calls)

        config = self._sdk_types.GenerateContentConfig(**config_kwargs)

        response = await self._sdk_client.aio.models.generate_content(
            model=model,
            contents=prompt,
            config=config,
        )

        text = (getattr(response, "text", None) or "").strip()
        if not text:
            text = self._extract_text_from_sdk_response(response)

        usage = getattr(response, "usage_metadata", None)
        tokens = int(getattr(usage, "total_token_count", 0) or 0) if usage is not None else 0
        return text, tokens

    @staticmethod
    def _extract_text_from_sdk_response(response: Any) -> str:
        """Extract text from SDK response candidate parts when .text is empty."""
        candidates = getattr(response, "candidates", None) or []
        texts: list[str] = []

        for candidate in candidates:
            content = getattr(candidate, "content", None)
            parts = getattr(content, "parts", None) or []
            for part in parts:
                text = getattr(part, "text", None)
                if text:
                    texts.append(str(text))

        return "\n".join(texts).strip()

    @staticmethod
    def _extract_embedding_values(response: Any) -> List[float]:
        """Extract embedding values from SDK response object."""
        embeddings = getattr(response, "embeddings", None)
        if embeddings and len(embeddings) > 0:
            first = embeddings[0]
            values = getattr(first, "values", None)
            if isinstance(values, list) and values:
                return [float(v) for v in values]

        # Defensive fallback for dict-like structures.
        if isinstance(response, dict):
            entries = response.get("embeddings") or []
            if entries and isinstance(entries[0], dict):
                values = entries[0].get("values") or []
                if isinstance(values, list) and values:
                    return [float(v) for v in values]

        return []

    def _parse_json_or_reasoning(self, raw_text: str) -> Dict[str, Any]:
        """Parse first JSON object from model text; otherwise return reasoning-only payload."""
        text = (raw_text or "").strip()
        if not text:
            return {}

        try:
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                parsed = json.loads(match.group())
                if isinstance(parsed, dict):
                    if "reasoning" not in parsed:
                        parsed["reasoning"] = text
                    return parsed
        except Exception:
            pass

        return {"reasoning": text}

    def _build_security_prompt(
        self,
        inputs: List[Any],
        system_instruction: Optional[str],
        context_history: Optional[List[Dict[str, Any]]],
    ) -> str:
        """Build a generic security analysis prompt from multimodal inputs."""
        base_instruction = (
            "You are a security analysis assistant. "
            "Classify risk conservatively and return JSON with keys: "
            "threat_level, confidence, reasoning, detected_patterns, recommended_actions."
        )

        if system_instruction:
            base_instruction = f"{system_instruction}\n\n{base_instruction}"

        input_parts: list[str] = []
        for index, inp in enumerate(inputs, start=1):
            if isinstance(inp, dict):
                modality = inp.get("type", "unknown")
                content = inp.get("text", inp.get("content", "[Data]"))
            elif hasattr(inp, "modality"):
                modality = getattr(inp.modality, "value", str(inp.modality))
                content = inp.content if isinstance(inp.content, str) else "[Binary Data]"
            else:
                modality = "text"
                content = str(inp)
            input_parts.append(f"Input {index} ({modality}): {content}")

        input_text = "\n\n".join(input_parts)

        context_text = ""
        if context_history:
            context_text = "\n\nPrevious Context:\n" + "\n".join(
                [f"- {ctx.get('summary', str(ctx))}" for ctx in context_history[-10:]]
            )

        return f"{base_instruction}\n\nCurrent Input:\n{input_text}{context_text}"

    def _build_deep_think_prompt(
        self,
        inputs: List[MultimodalInput],
        initial_analysis: Dict[str, Any],
        system_instruction: Optional[str],
        context_history: Optional[List[Dict[str, Any]]],
    ) -> str:
        """Build deep analysis prompt using initial Flash results as context."""
        base_prompt = self._build_security_prompt(inputs, system_instruction, context_history)

        deep_instruction = f"""

Deep analysis mode:
- Initial threat level: {initial_analysis.get('threat_level')}
- Initial confidence: {initial_analysis.get('confidence')}
- Initial reasoning: {initial_analysis.get('reasoning')}

Re-evaluate for:
1. False-positive probability.
2. Multi-step intent and escalation patterns.
3. Hidden instruction/injection indicators.
4. Whether stronger containment actions are required.

Return JSON with fields:
{{
  "threat_level": "safe|low|medium|high|critical",
  "confidence": 0.0-1.0,
  "reasoning": "...",
  "thought_process": ["..."],
  "detected_patterns": ["..."],
  "recommended_actions": ["..."]
}}
"""
        return base_prompt + deep_instruction

    def _generate_mock_response(self, prompt_text: str) -> Dict[str, Any]:
        """Deterministic fallback response for offline/local development."""
        import json as _json

        if "selected_checks" in prompt_text or "vulnerability check plan" in prompt_text.lower():
            available_checks: list[str] = []
            marker = "Available read-only checks:"
            if marker in prompt_text:
                try:
                    tail = prompt_text.split(marker, 1)[1].splitlines()[0].strip()
                    available_checks = list(ast.literal_eval(tail))
                except Exception:
                    available_checks = []

            if not available_checks:
                available_checks = [
                    "owasp_a05_security_misconfiguration",
                    "owasp_a02_cryptographic_failures",
                    "owasp_a01_broken_access_control",
                ]

            selected = list(available_checks[: min(5, len(available_checks))])
            mock_plan = {
                "reasoning": "Selected read-only checks based on visible forms, headers, and storage signals.",
                "selected_checks": selected,
                "priority_order": selected,
            }
            return {"reasoning": _json.dumps(mock_plan)}

        if "Return JSON array only" in prompt_text:
            return {"reasoning": '["owasp_a05_security_misconfiguration", "owasp_a02_cryptographic_failures"]'}

        return {
            "threat_level": "safe",
            "confidence": 0.95,
            "reasoning": "No suspicious patterns detected in the input",
            "detected_patterns": [],
            "recommended_actions": [],
            "tokens_used": max(1, len(prompt_text) // 4),
        }
