"""Red-team orchestration focused on safe vulnerability assessment planning.

Policy constraints:
1. AI may generate a vulnerability check plan.
2. AI must not autonomously execute security skills.
3. Skill execution requires explicit per-request user approval in router/agent layers.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import uuid
from dataclasses import asdict
from datetime import datetime
from typing import Any, TypeVar
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

from shared.schemas import ThreatLevel
from shared.utils import get_logger
from intelligence_center.models import GeminiClient
from red_teaming.mcp_server.playwright_mcp import PlaywrightMCPServer
from red_teaming.skills import ReconData, SkillResult, get_registry

logger = get_logger(__name__)

T = TypeVar("T")


class VulnerabilityCheckPlan(BaseModel):
    """Gemini-generated read-only vulnerability check plan."""

    plan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str
    reasoning: str = ""
    selected_checks: list[str] = Field(default_factory=list)
    priority_order: list[str] = Field(default_factory=list)
    safety_policy: str = (
        "Read-only checks only. No exploit payloads, destructive actions, or unauthorized access attempts."
    )
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class RedTeamReport(BaseModel):
    """Consolidated red-team report for static and dynamic assessment phases."""

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str
    started_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    finished_at: str | None = None
    static_result: dict[str, Any] | None = None

    # New terminology
    vulnerability_check_plan: VulnerabilityCheckPlan | None = None
    check_results: list[SkillResult] = Field(default_factory=list)

    # Backward compatibility for existing API/UI clients
    attack_plan: VulnerabilityCheckPlan | None = None
    attack_results: list[SkillResult] = Field(default_factory=list)

    # Score is intentionally optional. Dynamic assessment is plan-only by policy, so
    # a numeric score is often misleading unless explicit checks were executed.
    overall_score: float | None = None
    summary: str = ""
    assessment_metadata: dict[str, Any] = Field(default_factory=dict)

    def sync_legacy_fields(self) -> None:
        """Keep legacy fields aligned for backward compatibility."""
        self.attack_plan = self.vulnerability_check_plan
        self.attack_results = list(self.check_results)

    def calculate_score(self) -> float | None:
        """Compute a simple score only when checks were executed.

        Dynamic assessment defaults to plan-only, so this returns None when no
        check results exist.
        """
        if not self.check_results:
            self.overall_score = None
            return None
        deductions = {
            ThreatLevel.CRITICAL: 25,
            ThreatLevel.HIGH: 15,
            ThreatLevel.MEDIUM: 7,
            ThreatLevel.LOW: 3,
        }
        score = 100.0
        for result in self.check_results:
            if result.success:
                score -= deductions.get(result.severity, 5)
        self.overall_score = max(score, 0.0)
        return self.overall_score


class AttackOrchestrator:
    """Compatibility wrapper for red-team routes.

    The class name is preserved to avoid wide refactors, but behavior is now
    policy-safe: it creates vulnerability check plans and does not execute skills.
    """

    def __init__(self, gemini_client: GeminiClient):
        self.gemini_client = gemini_client

    def _clone_gemini_client(self) -> GeminiClient:
        """Create a fresh GeminiClient for isolated event-loop execution."""
        return GeminiClient(
            api_key=getattr(self.gemini_client, "api_key", None),
            base_url=getattr(self.gemini_client, "base_url", None),
            flash_model=getattr(self.gemini_client, "flash_model", None),
            deep_model=getattr(self.gemini_client, "deep_model", None),
            embedding_model=getattr(self.gemini_client, "embedding_model", None),
            project_id=getattr(self.gemini_client, "project_id", None),
            location=getattr(self.gemini_client, "location", "us-central1"),
        )

    async def _run_in_subprocess_capable_thread(self, coro_factory: Callable[[], Awaitable[T]]) -> T:
        """Run async work in a dedicated event loop that supports subprocess (Windows Proactor)."""

        def _runner() -> T:
            if os.name == "nt":
                loop = asyncio.ProactorEventLoop()
            else:
                loop = asyncio.new_event_loop()

            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(coro_factory())
            finally:
                try:
                    loop.close()
                finally:
                    try:
                        asyncio.set_event_loop(None)
                    except Exception:
                        pass

        return await asyncio.to_thread(_runner)

    @staticmethod
    def _is_playwright_supported_in_loop() -> bool:
        """Return False on Windows selector loop where subprocess is unsupported."""
        if os.name != "nt":
            return True

        try:
            loop = asyncio.get_running_loop()
            loop_name = loop.__class__.__name__.lower()
            # Playwright requires subprocess support which Windows selector loop lacks.
            return "selector" not in loop_name
        except Exception:
            return False

    @staticmethod
    def _safe_error_text(exc: Exception, max_len: int = 500) -> str:
        """Convert exception text to ASCII-safe text for logger sinks."""
        raw = f"{type(exc).__name__}: {exc}"
        safe = raw.encode("ascii", errors="backslashreplace").decode("ascii")
        return safe[:max_len]

    @staticmethod
    def _env_flag(name: str, default: bool = False) -> bool:
        """Read boolean flag from environment variables."""
        raw = os.environ.get(name, "true" if default else "false").strip().lower()
        return raw in {"1", "true", "yes", "on"}

    @staticmethod
    def _parse_mcp_args(raw: str) -> list[str]:
        """Split MCP arg string while preserving quoted values."""
        if not raw.strip():
            return []
        return shlex.split(raw, posix=(os.name != "nt"))

    async def _maybe_generate_plan_with_mcp(
        self,
        target_url: str,
        available_checks: list[str],
        static_context: str,
        *,
        allow_mcp_tools: bool,
        approved_by: str,
        metadata_out: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Optionally generate a plan using Gemini SDK + Playwright MCP."""
        if not allow_mcp_tools:
            logger.info("Gemini Playwright MCP planning disabled: explicit per-request user approval is required")
            return None
        settings_enable = False
        settings_command = "npx"
        settings_args = "@playwright/mcp@latest --headless --isolated --output-dir .playwright-mcp"
        settings_max_calls = 8

        try:
            from gatekeeper.config import settings as gatekeeper_settings

            settings_enable = bool(gatekeeper_settings.enable_gemini_playwright_mcp)
            settings_command = str(gatekeeper_settings.playwright_mcp_command)
            settings_args = str(gatekeeper_settings.playwright_mcp_args)
            settings_max_calls = int(gatekeeper_settings.gemini_mcp_max_remote_calls)
        except Exception:
            pass

        mcp_enabled = settings_enable or self._env_flag("ENABLE_GEMINI_PLAYWRIGHT_MCP", default=False)
        if not mcp_enabled:
            logger.info("Gemini Playwright MCP planning disabled")
            return None

        use_thread = False
        if not self._is_playwright_supported_in_loop():
            try:
                loop = asyncio.get_running_loop()
                loop_name = loop.__class__.__name__
            except Exception:
                loop_name = "unknown"
            logger.info(
                "Gemini Playwright MCP will run in dedicated Proactor loop (server loop lacks subprocess support)",
                loop=loop_name,
                os_name=os.name,
            )
            use_thread = True
        if not getattr(self.gemini_client, "_api_enabled", False):
            logger.info("Gemini Playwright MCP skipped: API key is not configured")
            return None

        mcp_command = os.environ.get("PLAYWRIGHT_MCP_COMMAND", settings_command).strip() or "npx"
        mcp_args_raw = os.environ.get(
            "PLAYWRIGHT_MCP_ARGS",
            settings_args,
        )
        mcp_args = self._parse_mcp_args(mcp_args_raw)
        try:
            max_remote_calls = int(os.environ.get("GEMINI_MCP_MAX_REMOTE_CALLS", str(settings_max_calls)))
        except ValueError:
            max_remote_calls = settings_max_calls

        host = urlparse(target_url).hostname or ""
        prompt = (
            "You are a security assessment planner.\n"
            "Use Playwright MCP tools for read-only reconnaissance and planning.\n"
            "Policy constraints:\n"
            "- Read-only checks only.\n"
            "- No exploit payloads, no attack instructions, no destructive actions.\n"
            "- Do not submit forms, click destructive UI, or modify application state.\n"
            f"- Stay scoped to the target host: {host or 'unknown'}.\n\n"
            f"Target URL: {target_url}\n"
            f"{static_context}\n"
            f"Available read-only checks: {available_checks}\n\n"
            "Collect high-level signals (page purpose, auth surface, form/input presence, storage/cookie indicators)\n"
            "and return JSON only:\n"
            '{"reasoning":"why these checks","selected_checks":["name"],"priority_order":["name"]}'
        )

        async def _call() -> dict[str, Any]:
            client = self._clone_gemini_client() if use_thread else self.gemini_client
            logger.info(
                "Attempting Gemini SDK + Playwright MCP planning",
                target_url=target_url,
                approved_by=approved_by or None,
                mcp_command=mcp_command,
                mcp_args_preview=mcp_args[:6],
                max_remote_calls=max_remote_calls,
            )
            response = await client.analyze_with_flash_mcp(
                prompt=prompt,
                mcp_command=mcp_command,
                mcp_args=mcp_args,
                max_remote_calls=max_remote_calls,
            )

            parsed = self._extract_plan_json(str(response.get("reasoning", "")))
            if isinstance(response.get("selected_checks"), list):
                parsed.setdefault("selected_checks", response.get("selected_checks"))
            if isinstance(response.get("priority_order"), list):
                parsed.setdefault("priority_order", response.get("priority_order"))

            if metadata_out is not None:
                metadata_out["ai"] = {
                    "enabled": bool(getattr(client, "_api_enabled", False) and getattr(client, "_sdk_available", False)),
                    "api_key_configured": bool(getattr(client, "_api_enabled", False)),
                    "sdk_available": bool(getattr(client, "_sdk_available", False)),
                    "engine": "gemini_sdk_mcp",
                    "model_version": response.get("model_version"),
                    "provider_fallback": bool(response.get("provider_fallback")),
                    "analysis_duration_ms": response.get("analysis_duration_ms"),
                    "tokens_used": response.get("tokens_used"),
                    "mcp_used": bool(response.get("mcp_used")),
                    "mcp_function_calls_count": response.get("mcp_function_calls_count"),
                    "mcp_function_calls": response.get("mcp_function_calls"),
                    "mcp_available_tools_count": response.get("mcp_available_tools_count"),
                    "mcp_available_tools_sample": response.get("mcp_available_tools_sample"),
                    "mcp_max_remote_calls": max_remote_calls,
                }

            logger.info(
                "Generated vulnerability check plan using Gemini SDK + Playwright MCP",
                model=response.get("model_version"),
                max_remote_calls=max_remote_calls,
            )
            return parsed

        try:
            if use_thread:
                return await self._run_in_subprocess_capable_thread(_call)
            return await _call()
        except Exception as exc:
            logger.warning(
                "Gemini Playwright MCP planning failed; falling back to standard Gemini planning",
                error_type=type(exc).__name__,
                error=self._safe_error_text(exc),
            )
            return None

    async def _collect_recon(
        self,
        target_url: str,
        *,
        allow_browser_automation: bool,
        metadata_out: dict[str, Any],
    ) -> ReconData:
        """Collect recon via Playwright when approved, otherwise fallback to HTTP recon."""
        if not allow_browser_automation:
            logger.info("Playwright recon disabled: explicit per-request user approval is required")
            metadata_out["recon"] = {"method": "http_fallback", "approved": False}
            return await self._run_recon_http_fallback(target_url)

        async def _run() -> ReconData:
            server = PlaywrightMCPServer(headless=True)
            tool_calls: list[dict[str, Any]] = []
            try:
                await server.start()
                logger.info("Dynamic recon using Playwright", target_url=target_url)
                recon = await self._run_recon(server, target_url, tool_calls_out=tool_calls)
                metadata_out["recon"] = {
                    "method": "playwright",
                    "approved": True,
                    "tool_calls_count": len(tool_calls),
                    "tool_calls": tool_calls,
                }
                return recon
            finally:
                try:
                    await server.stop()
                except Exception as stop_error:
                    logger.warning("Failed to stop Playwright server", error=self._safe_error_text(stop_error))

        try:
            if self._is_playwright_supported_in_loop():
                return await _run()

            try:
                loop = asyncio.get_running_loop()
                loop_name = loop.__class__.__name__
            except Exception:
                loop_name = "unknown"

            logger.warning(
                "Playwright recon will run in dedicated Proactor loop (server loop lacks subprocess support)",
                loop=loop_name,
                os_name=os.name,
            )
            return await self._run_in_subprocess_capable_thread(_run)
        except Exception as exc:
            logger.warning(
                "Playwright recon unavailable; falling back to HTTP recon",
                error_type=type(exc).__name__,
                error=self._safe_error_text(exc),
            )
            metadata_out["recon"] = {
                "method": "http_fallback",
                "approved": True,
                "fallback_reason": self._safe_error_text(exc),
            }

        return await self._run_recon_http_fallback(target_url)

    async def _run_recon_http_fallback(self, target_url: str) -> ReconData:
        """HTTP-only recon fallback for environments where Playwright cannot run."""
        logger.info("Dynamic recon using HTTP fallback", target_url=target_url)
        html = ""
        text = ""

        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=15.0, verify=False) as client:
                response = await client.get(target_url)
                html = response.text or ""
        except Exception as exc:
            logger.warning(
                "HTTP fallback recon failed to fetch target",
                target_url=target_url,
                error=self._safe_error_text(exc),
            )

        text = self._html_to_text(html)
        inputs = self._extract_inputs_from_html(html)
        forms = self._extract_forms_from_html(html)

        return ReconData(
            url=target_url,
            html=html,
            text=text,
            inputs=inputs,
            forms=forms,
            cookies=[],
            local_storage={},
        )

    @staticmethod
    def _html_to_text(html: str) -> str:
        """Convert HTML to rough plain text for planning context."""
        if not html:
            return ""
        no_script = re.sub(r"<script[\s\S]*?</script>", " ", html, flags=re.IGNORECASE)
        no_style = re.sub(r"<style[\s\S]*?</style>", " ", no_script, flags=re.IGNORECASE)
        no_tags = re.sub(r"<[^>]+>", " ", no_style)
        return re.sub(r"\s+", " ", no_tags).strip()

    @staticmethod
    def _parse_tag_attrs(raw_attrs: str) -> dict[str, str]:
        """Parse HTML tag attributes from a raw tag chunk."""
        attrs: dict[str, str] = {}
        for match in re.finditer(r'([a-zA-Z_:][-\w:.]*)\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)', raw_attrs):
            key = match.group(1).lower()
            value = match.group(2).strip().strip("'\"")
            attrs[key] = value
        return attrs

    def _extract_inputs_from_html(self, html: str) -> list[dict[str, str]]:
        """Extract input-like elements from static HTML."""
        if not html:
            return []
        inputs: list[dict[str, str]] = []
        pattern = re.compile(r"<(input|textarea|select)\b([^>]*)>", flags=re.IGNORECASE)
        for tag_match in pattern.finditer(html):
            tag = tag_match.group(1).lower()
            attrs = self._parse_tag_attrs(tag_match.group(2))
            inputs.append(
                {
                    "tag": tag.upper(),
                    "type": attrs.get("type", "text" if tag == "input" else tag),
                    "name": attrs.get("name", ""),
                    "id": attrs.get("id", ""),
                    "placeholder": attrs.get("placeholder", ""),
                }
            )
        return inputs

    def _extract_forms_from_html(self, html: str) -> list[dict[str, Any]]:
        """Extract basic form metadata from static HTML."""
        if not html:
            return []

        forms: list[dict[str, Any]] = []
        form_pattern = re.compile(r"<form\b([^>]*)>([\s\S]*?)</form>", flags=re.IGNORECASE)

        for index, match in enumerate(form_pattern.finditer(html)):
            attrs = self._parse_tag_attrs(match.group(1))
            inner = match.group(2) or ""
            input_count = len(re.findall(r"<(input|textarea|select)\b", inner, flags=re.IGNORECASE))
            has_csrf = bool(
                re.search(
                    r'name\s*=\s*["\']?(csrf|token|_token|xsrf)["\']?',
                    inner,
                    flags=re.IGNORECASE,
                )
            )
            forms.append(
                {
                    "index": index,
                    "action": attrs.get("action", ""),
                    "method": attrs.get("method", "get"),
                    "hasCsrfToken": has_csrf,
                    "inputCount": input_count,
                }
            )

        return forms

    async def run_static_scan(self, github_url: str) -> dict[str, Any]:
        """Run GitHub static security scan via static analyzer."""
        from static_analyzer.github_integration.repo_analyzer import GitHubRepositoryAnalyzer
        from static_analyzer.vulnerability_scanner.ai_app_scanner import AIAppSecurityScanner

        logger.info("Static scan requested", github_url=github_url)
        analyzer = GitHubRepositoryAnalyzer(gemini_client=self.gemini_client)
        app_config = await analyzer.analyze_repository(github_url)
        scanner = AIAppSecurityScanner(self.gemini_client)
        audit_result = await scanner.scan_repository(repo_url=github_url, config=app_config)
        result = asdict(audit_result)
        ai_status = str(result.get("ai_status", "disabled"))
        ai_enabled = ai_status == "enabled"

        scan_metadata = {
            "total_files_scanned": len(app_config.all_files),
            "analysis_engine": (
                "gemini_flash_plus_rules"
                if ai_status == "enabled"
                else "provider_fallback_rules"
                if ai_status == "provider_fallback"
                else "rules_only_fallback"
            ),
            "ai_enabled": ai_enabled,
            "ai_status": ai_status,
            "classified_files": {
                "system_prompts": len(app_config.system_prompts),
                "tool_definitions": len(app_config.tool_definitions),
                "config_files": len(app_config.config_files),
                "code_files": len(app_config.code_files),
                "rag_configs": len(app_config.rag_configs),
                "api_keys_files": len(app_config.api_keys_files),
            },
        }
        classified_total = sum(scan_metadata["classified_files"].values())

        if scan_metadata["total_files_scanned"] == 0:
            assessment_quality = "insufficient_coverage"
            coverage_message = (
                "No supported source files were scanned. "
                "The security score is not a reliable indicator."
            )
        elif classified_total == 0:
            assessment_quality = "limited_coverage"
            coverage_message = (
                "Files were scanned, but no AI-relevant files were classified. "
                "Checks completed with limited coverage."
            )
        else:
            assessment_quality = "normal_coverage"
            coverage_message = "Static checks completed with classified AI-relevant files."

        result["scan_metadata"] = scan_metadata
        result["vulnerabilities_count"] = len(result.get("vulnerabilities", []))
        result["assessment_quality"] = assessment_quality
        result["coverage_message"] = coverage_message

        logger.info(
            "Static scan completed",
            score=result.get("overall_score"),
            vulnerabilities=result["vulnerabilities_count"],
            total_files_scanned=scan_metadata["total_files_scanned"],
            classified_files=classified_total,
            assessment_quality=assessment_quality,
        )
        return result

    async def run_dynamic_attack(self, target_url: str) -> RedTeamReport:
        """Backward-compatible entry point; now returns a dynamic assessment plan only."""
        return await self.run_dynamic_assessment(target_url)

    async def run_dynamic_checks(
        self,
        target_url: str,
        *,
        selected_checks: list[str] | None = None,
        allow_browser_automation: bool = False,
        approved_by: str = "",
    ) -> RedTeamReport:
        """Execute approved read-only skills against a live target.

        Policy constraints:
        - Only registered read-only skills are available (see red_teaming.skills).
        - Caller must enforce explicit per-request human approval (router layer).
        """
        report = RedTeamReport(target_url=target_url)
        report.assessment_metadata = {
            "approvals": {
                "approved_by": approved_by or None,
                "allow_browser_automation": bool(allow_browser_automation),
                "allow_mcp_tools": False,
            },
            "ai": {
                "enabled": False,
                "engine": "disabled",
                "mcp_used": False,
            },
            "execution": {
                "mode": "dynamic_checks",
                "selected_checks": list(selected_checks or []),
            },
        }

        if not allow_browser_automation:
            raise PermissionError("Dynamic checks execution requires browser automation approval.")

        async def _run() -> RedTeamReport:
            # Single browser session for all checks for consistent evidence + speed.
            server = PlaywrightMCPServer(headless=True)
            tool_calls: list[dict[str, Any]] = []
            try:
                await server.start()
                recon = await self._run_recon(server, target_url, tool_calls_out=tool_calls)
                report.assessment_metadata["recon"] = {
                    "method": "playwright",
                    "approved": True,
                    "tool_calls_count": len(tool_calls),
                    "tool_calls": tool_calls,
                }

                registry = get_registry()
                available = registry.names()
                to_run = selected_checks or available
                # Filter to registry to avoid accidental execution of unregistered code paths.
                to_run = [name for name in to_run if name in registry]
                if not to_run:
                    to_run = available

                report.assessment_metadata["execution"]["selected_checks"] = list(to_run)

                for name in to_run:
                    skill = registry.get(name)
                    if skill is None:
                        continue
                    try:
                        result = await skill.execute(server, target_url, recon=recon)
                    except Exception as exc:
                        result = SkillResult(
                            skill_name=name,
                            success=False,
                            severity=ThreatLevel.LOW,
                            error=self._safe_error_text(exc),
                        )
                    report.check_results.append(result)

                report.sync_legacy_fields()
                report.calculate_score()
                report.finished_at = datetime.utcnow().isoformat()
                report.summary = _build_summary(report)
                return report
            finally:
                try:
                    await server.stop()
                except Exception as stop_error:
                    logger.warning("Failed to stop Playwright server", error=self._safe_error_text(stop_error))

        # On Windows selector loop, Playwright subprocess APIs fail; run in a dedicated Proactor loop.
        if self._is_playwright_supported_in_loop():
            return await _run()
        try:
            loop = asyncio.get_running_loop()
            loop_name = loop.__class__.__name__
        except Exception:
            loop_name = "unknown"
        logger.warning(
            "Dynamic checks will run in dedicated Proactor loop (server loop lacks subprocess support)",
            loop=loop_name,
            os_name=os.name,
        )
        return await self._run_in_subprocess_capable_thread(_run)

    async def run_dynamic_assessment(
        self,
        target_url: str,
        *,
        allow_browser_automation: bool = False,
        allow_mcp_tools: bool = False,
        approved_by: str = "",
    ) -> RedTeamReport:
        """Build recon + vulnerability check plan without executing skills."""
        report = RedTeamReport(target_url=target_url)
        report.assessment_metadata = {
            "approvals": {
                "approved_by": approved_by or None,
                "allow_browser_automation": bool(allow_browser_automation),
                "allow_mcp_tools": bool(allow_mcp_tools),
            },
            "ai": {},
        }
        logger.info("Dynamic recon phase started", target_url=target_url)
        recon = await self._collect_recon(
            target_url,
            allow_browser_automation=allow_browser_automation,
            metadata_out=report.assessment_metadata,
        )

        logger.info("Generating vulnerability check plan")
        plan = await self._generate_vulnerability_check_plan(
            recon=recon,
            static_findings=None,
            allow_mcp_tools=allow_mcp_tools,
            approved_by=approved_by,
            metadata_out=report.assessment_metadata,
        )
        report.vulnerability_check_plan = plan
        report.sync_legacy_fields()

        logger.info(
            "Plan created; autonomous execution is disabled by policy",
            planned_checks=len(plan.priority_order),
        )

        report.calculate_score()
        report.finished_at = datetime.utcnow().isoformat()
        report.summary = _build_summary(report)

        logger.info("Dynamic assessment completed", report_id=report.report_id)
        return report

    async def run_full_red_team(
        self,
        target_url: str,
        github_url: str | None = None,
        *,
        allow_browser_automation: bool = False,
        allow_mcp_tools: bool = False,
        approved_by: str = "",
    ) -> dict[str, Any]:
        """Run static scan and dynamic assessment planning in one call."""
        combined: dict[str, Any] = {
            "red_team_id": str(uuid.uuid4()),
            "started_at": datetime.utcnow().isoformat(),
            "static": None,
            "dynamic": None,
        }

        static_findings: dict[str, Any] | None = None

        if github_url:
            try:
                combined["static"] = await self.run_static_scan(github_url)
                static_findings = combined["static"]
            except Exception as exc:
                logger.error("Static scan failed", error=str(exc))
                combined["static"] = {"error": str(exc)}

        try:
            report = await self._run_dynamic_assessment_with_context(
                target_url,
                static_findings,
                allow_browser_automation=allow_browser_automation,
                allow_mcp_tools=allow_mcp_tools,
                approved_by=approved_by,
            )
            combined["dynamic"] = report.model_dump()
        except Exception as exc:
            logger.error("Dynamic assessment failed", error=str(exc))
            combined["dynamic"] = {"error": str(exc)}

        combined["finished_at"] = datetime.utcnow().isoformat()
        return combined

    async def _run_dynamic_assessment_with_context(
        self,
        target_url: str,
        static_findings: dict[str, Any] | None = None,
        *,
        allow_browser_automation: bool = False,
        allow_mcp_tools: bool = False,
        approved_by: str = "",
    ) -> RedTeamReport:
        """Build dynamic assessment plan with optional static analysis context."""
        report = RedTeamReport(target_url=target_url)
        report.assessment_metadata = {
            "approvals": {
                "approved_by": approved_by or None,
                "allow_browser_automation": bool(allow_browser_automation),
                "allow_mcp_tools": bool(allow_mcp_tools),
            },
            "ai": {},
        }
        logger.info("Dynamic recon phase started", target_url=target_url)
        recon = await self._collect_recon(
            target_url,
            allow_browser_automation=allow_browser_automation,
            metadata_out=report.assessment_metadata,
        )

        logger.info("Generating vulnerability check plan", has_static_context=bool(static_findings))
        plan = await self._generate_vulnerability_check_plan(
            recon,
            static_findings,
            allow_mcp_tools=allow_mcp_tools,
            approved_by=approved_by,
            metadata_out=report.assessment_metadata,
        )
        report.vulnerability_check_plan = plan
        report.sync_legacy_fields()

        report.calculate_score()
        report.finished_at = datetime.utcnow().isoformat()
        report.summary = _build_summary(report)

        return report

    async def _run_recon(
        self,
        server: PlaywrightMCPServer,
        target_url: str,
        *,
        tool_calls_out: list[dict[str, Any]] | None = None,
    ) -> ReconData:
        """Collect structured reconnaissance data in a single page session."""
        async def call(tool: str, inp: dict[str, Any]) -> dict[str, Any]:
            if tool_calls_out is not None:
                tool_calls_out.append({"tool": tool, "input_keys": list(inp.keys())})
            return await server.call_tool(tool, inp)

        await call("browser_navigate", {"url": target_url})

        html = (await call("browser_get_html", {})).get("result", "")
        text = (await call("browser_get_text", {})).get("result", "")

        # Lightweight UI evidence (base64 returned by tool is intentionally discarded).
        try:
            await call("browser_screenshot", {})
        except Exception:
            pass

        inputs = json.loads(
            (
                await call(
                    "browser_evaluate_js",
                    {
                        "script": (
                            "() => JSON.stringify([...document.querySelectorAll("
                            "  'input, textarea, [contenteditable]')]"
                            "  .map(el => ({tag:el.tagName, type:el.type, name:el.name,"
                            "    id:el.id, placeholder:el.placeholder||''})))"
                        )
                    },
                )
            ).get("result", "[]")
        )

        forms = json.loads(
            (
                await call(
                    "browser_evaluate_js",
                    {
                        "script": (
                            "() => JSON.stringify([...document.querySelectorAll('form')].map((f,i) => ({"
                            "  index:i, action:f.action, method:f.method,"
                            "  hasCsrfToken:!![...f.elements].some(e =>"
                            "    /csrf|token|_token|xsrf/.test((e.name||'').toLowerCase())),"
                            "  inputCount:f.elements.length"
                            "})))"
                        )
                    },
                )
            ).get("result", "[]")
        )

        cookies = json.loads((await call("browser_get_cookies", {})).get("result", "[]"))
        local_storage = json.loads(
            (await call("browser_get_local_storage", {})).get("result", "{}")
        )

        return ReconData(
            url=target_url,
            html=html,
            text=text,
            inputs=inputs,
            forms=forms,
            cookies=cookies,
            local_storage=local_storage,
        )

    async def _generate_vulnerability_check_plan(
        self,
        recon: ReconData,
        static_findings: dict[str, Any] | None = None,
        *,
        allow_mcp_tools: bool = False,
        approved_by: str = "",
        metadata_out: dict[str, Any] | None = None,
    ) -> VulnerabilityCheckPlan:
        """Generate a prioritized read-only vulnerability check plan."""
        available = get_registry().names()

        static_context = ""
        if static_findings:
            vulnerabilities = static_findings.get("vulnerabilities", [])
            static_context = (
                "\nStatic analysis context:\n"
                f"- Reported vulnerabilities: {len(vulnerabilities)}\n"
            )
            if vulnerabilities:
                vuln_summary = ", ".join(v.get("type", "unknown") for v in vulnerabilities[:10])
                static_context += f"- Top vulnerability types: {vuln_summary}\n"

        mcp_plan = await self._maybe_generate_plan_with_mcp(
            target_url=recon.url,
            available_checks=available,
            static_context=static_context,
            allow_mcp_tools=allow_mcp_tools,
            approved_by=approved_by,
            metadata_out=metadata_out,
        )
        if isinstance(mcp_plan, dict) and mcp_plan:
            selected = _normalise_plan_names(mcp_plan.get("selected_checks"), available)
            priority = _normalise_plan_names(mcp_plan.get("priority_order"), available)

            if not selected:
                selected = list(available)
            if not priority:
                priority = list(selected)

            for name in selected:
                if name not in priority:
                    priority.append(name)

            return VulnerabilityCheckPlan(
                target_url=recon.url,
                reasoning=str(mcp_plan.get("reasoning", "") or "Generated with Gemini SDK + Playwright MCP"),
                selected_checks=selected,
                priority_order=priority,
            )

        prompt = (
            "You are a security assessment planner.\n"
            "Create a prioritized vulnerability check plan for a web application.\n"
            "Policy constraints:\n"
            "- Output read-only checks only.\n"
            "- Do not include exploit payloads or attack instructions.\n"
            "- Do not include destructive or unauthorized actions.\n\n"
            "Dynamic recon summary:\n"
            f"- Target URL: {recon.url}\n"
            f"- Visible text (first 500 chars): {recon.text[:500]}\n"
            f"- Input fields: {len(recon.inputs)}\n"
            f"- Forms: {len(recon.forms)}\n"
            f"- Cookies: {len(recon.cookies)}\n"
            f"- Local storage keys: {list(recon.local_storage.keys())}\n"
            f"{static_context}\n"
            f"Available read-only checks: {available}\n\n"
            "Return JSON only:\n"
            '{"reasoning":"why these checks","selected_checks":["name"],"priority_order":["name"]}'
        )

        response = await self.gemini_client.analyze_with_flash([{"type": "text", "text": prompt}])
        if metadata_out is not None:
            metadata_out["ai"] = {
                "enabled": bool(
                    getattr(self.gemini_client, "_api_enabled", False)
                    and getattr(self.gemini_client, "_sdk_available", False)
                ),
                "api_key_configured": bool(getattr(self.gemini_client, "_api_enabled", False)),
                "sdk_available": bool(getattr(self.gemini_client, "_sdk_available", False)),
                "engine": "gemini_sdk",
                "model_version": response.get("model_version"),
                "provider_fallback": bool(response.get("provider_fallback")),
                "analysis_duration_ms": response.get("analysis_duration_ms"),
                "tokens_used": response.get("tokens_used"),
                "mcp_used": False,
            }

        reasoning_text = str(response.get("reasoning", ""))
        parsed = self._extract_plan_json(reasoning_text)

        if isinstance(response.get("selected_checks"), list):
            parsed.setdefault("selected_checks", response.get("selected_checks"))
        if isinstance(response.get("priority_order"), list):
            parsed.setdefault("priority_order", response.get("priority_order"))

        selected = _normalise_plan_names(parsed.get("selected_checks"), available)
        priority = _normalise_plan_names(parsed.get("priority_order"), available)

        if not selected:
            selected = list(available)
        if not priority:
            priority = list(selected)

        # Ensure priority includes all selected checks.
        for name in selected:
            if name not in priority:
                priority.append(name)

        return VulnerabilityCheckPlan(
            target_url=recon.url,
            reasoning=str(parsed.get("reasoning", "") or reasoning_text or "Default: evaluate all checks"),
            selected_checks=selected,
            priority_order=priority,
        )

    @staticmethod
    def _extract_plan_json(reasoning: str) -> dict[str, Any]:
        """Extract the first JSON object from model reasoning text."""
        if not reasoning:
            return {}
        try:
            match = re.search(r"\{.*\}", reasoning, re.DOTALL)
            if not match:
                return {}
            data = json.loads(match.group())
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}


def _normalise_plan_names(values: Any, available: list[str]) -> list[str]:
    """Filter and de-duplicate plan names while preserving order."""
    if not isinstance(values, list):
        return []

    available_set = set(available)
    output: list[str] = []
    for value in values:
        name = str(value)
        if name in available_set and name not in output:
            output.append(name)
    return output


def _build_summary(report: RedTeamReport) -> str:
    """Build a concise report summary for logs and API output."""
    total = len(report.check_results)
    confirmed = sum(1 for r in report.check_results if r.success)
    critical = sum(1 for r in report.check_results if r.success and r.severity == ThreatLevel.CRITICAL)
    high = sum(1 for r in report.check_results if r.success and r.severity == ThreatLevel.HIGH)

    lines = [
        f"Vulnerability Assessment Report - {report.report_id}",
        f"Target: {report.target_url}",
        f"Executed checks: {total} | Confirmed findings: {confirmed} | Critical: {critical} | High: {high}",
        "",
    ]

    for result in report.check_results:
        tag = "FINDING" if result.success else "PASS"
        lines.append(
            f"  [{tag}] {result.skill_name:<35} {result.severity.value:<10} {len(result.evidence)} evidence item(s)"
        )

    if total == 0:
        lines.append("No skills were executed automatically. User approval is required per execution request.")

    return "\n".join(lines)
