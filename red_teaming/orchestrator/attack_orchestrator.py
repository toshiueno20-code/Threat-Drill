"""Red-team orchestration focused on safe vulnerability assessment planning.

Policy constraints:
1. AI may generate a vulnerability check plan.
2. AI must not autonomously execute security skills.
3. Skill execution requires explicit per-request user approval in router/agent layers.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from shared.schemas import ThreatLevel
from shared.utils import get_logger
from intelligence_center.models import GeminiClient
from red_teaming.mcp_server.playwright_mcp import PlaywrightMCPServer
from red_teaming.skills import ReconData, SkillResult, get_registry

logger = get_logger(__name__)


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

    overall_score: float = 100.0
    summary: str = ""

    def sync_legacy_fields(self) -> None:
        """Keep legacy fields aligned for backward compatibility."""
        self.attack_plan = self.vulnerability_check_plan
        self.attack_results = list(self.check_results)

    def calculate_score(self) -> float:
        """Deduct from 100 for each confirmed finding by severity."""
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
        logger.info("Static scan completed", score=result.get("overall_score"))
        return result

    async def run_dynamic_attack(self, target_url: str) -> RedTeamReport:
        """Backward-compatible entry point; now returns a dynamic assessment plan only."""
        return await self.run_dynamic_assessment(target_url)

    async def run_dynamic_assessment(self, target_url: str) -> RedTeamReport:
        """Build recon + vulnerability check plan without executing skills."""
        report = RedTeamReport(target_url=target_url)

        server = PlaywrightMCPServer(headless=True)
        await server.start()

        try:
            logger.info("Dynamic recon phase started", target_url=target_url)
            recon = await self._run_recon(server, target_url)

            logger.info("Generating vulnerability check plan")
            plan = await self._generate_vulnerability_check_plan(recon=recon, static_findings=None)
            report.vulnerability_check_plan = plan
            report.sync_legacy_fields()

            logger.info(
                "Plan created; autonomous execution is disabled by policy",
                planned_checks=len(plan.priority_order),
            )

            report.calculate_score()
            report.finished_at = datetime.utcnow().isoformat()
            report.summary = _build_summary(report)
        finally:
            await server.stop()

        logger.info("Dynamic assessment completed", report_id=report.report_id)
        return report

    async def run_full_red_team(
        self,
        target_url: str,
        github_url: str | None = None,
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
            report = await self._run_dynamic_assessment_with_context(target_url, static_findings)
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
    ) -> RedTeamReport:
        """Build dynamic assessment plan with optional static analysis context."""
        report = RedTeamReport(target_url=target_url)

        server = PlaywrightMCPServer(headless=True)
        await server.start()

        try:
            logger.info("Dynamic recon phase started", target_url=target_url)
            recon = await self._run_recon(server, target_url)

            logger.info("Generating vulnerability check plan", has_static_context=bool(static_findings))
            plan = await self._generate_vulnerability_check_plan(recon, static_findings)
            report.vulnerability_check_plan = plan
            report.sync_legacy_fields()

            report.calculate_score()
            report.finished_at = datetime.utcnow().isoformat()
            report.summary = _build_summary(report)
        finally:
            await server.stop()

        return report

    async def _run_recon(self, server: PlaywrightMCPServer, target_url: str) -> ReconData:
        """Collect structured reconnaissance data in a single page session."""
        await server.call_tool("browser_navigate", {"url": target_url})

        html = (await server.call_tool("browser_get_html", {})).get("result", "")
        text = (await server.call_tool("browser_get_text", {})).get("result", "")

        inputs = json.loads(
            (
                await server.call_tool(
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
                await server.call_tool(
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

        cookies = json.loads((await server.call_tool("browser_get_cookies", {})).get("result", "[]"))
        local_storage = json.loads(
            (await server.call_tool("browser_get_local_storage", {})).get("result", "{}")
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
    ) -> VulnerabilityCheckPlan:
        """Generate a prioritized read-only vulnerability check plan."""
        available = get_registry().names()

        static_context = ""
        if static_findings:
            vulnerabilities = static_findings.get("vulnerabilities", [])
            security_score = static_findings.get("security_score", static_findings.get("overall_score", "N/A"))
            static_context = (
                "\nStatic analysis context:\n"
                f"- Security score: {security_score}\n"
                f"- Reported vulnerabilities: {len(vulnerabilities)}\n"
            )
            if vulnerabilities:
                vuln_summary = ", ".join(v.get("type", "unknown") for v in vulnerabilities[:10])
                static_context += f"- Top vulnerability types: {vuln_summary}\n"

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
        f"Target: {report.target_url} | Score: {report.overall_score}/100",
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
