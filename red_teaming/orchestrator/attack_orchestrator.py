"""Attack Orchestrator — unified static (GitHub) + dynamic (URL) red-team flow.

Architecture (v2 — Gemini plans, Local LLM executes)
-----------------------------------------------------
1. [Recon]    Navigate once → collect structured ``ReconData``.
2. [Plan]     Gemini 3 Flash → ``AttackPlan`` (ordered skill list).
3. [Execute]  Local LLM (Ollama) ReAct loop → autonomous MCP tool usage.
              Falls back to legacy hardcoded skills if Ollama unavailable.
4. [Analyze]  Gemini analyzes results → vulnerability assessment.
5. [Report]   Aggregate results → score → ``RedTeamReport``.

Separation of concerns:
  - Gemini  = Planning + Analysis (no direct attack execution)
  - Ollama  = Autonomous attack execution via ReAct + MCP tools
  - Skills  = Knowledge layer (payloads, criteria, instructions)
  - MCP     = Playwright browser automation (capability layer)
"""

import json
import re
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from shared.schemas import ThreatLevel
from shared.utils import get_logger
from shared.llm import OllamaClient
from intelligence_center.models import GeminiClient
from red_teaming.mcp_server.playwright_mcp import PlaywrightMCPServer
from red_teaming.skills import get_registry, SkillResult, ReconData
from red_teaming.skills.knowledge import SKILL_INDEX, get_skill, list_skills
from red_teaming.agents.react_executor import ReActExecutor

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Pydantic v2 report models
# ---------------------------------------------------------------------------


class AttackPlan(BaseModel):
    """Gemini-generated attack plan."""

    plan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str
    reasoning: str = ""
    selected_attacks: list[str] = Field(default_factory=list)
    priority_order: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class RedTeamReport(BaseModel):
    """Consolidated red-team report — static + dynamic phases."""

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str
    started_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    finished_at: str | None = None
    static_result: dict[str, Any] | None = None
    attack_plan: AttackPlan | None = None
    attack_results: list[SkillResult] = Field(default_factory=list)
    overall_score: float = 100.0
    summary: str = ""

    def calculate_score(self) -> float:
        """Deduct from 100 per confirmed vulnerability severity."""
        deductions = {
            ThreatLevel.CRITICAL: 25,
            ThreatLevel.HIGH: 15,
            ThreatLevel.MEDIUM: 7,
            ThreatLevel.LOW: 3,
        }
        score = 100.0
        for r in self.attack_results:
            if r.success:
                score -= deductions.get(r.severity, 5)
        self.overall_score = max(score, 0.0)
        return self.overall_score


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class AttackOrchestrator:
    """Orchestrates the full red-team pipeline.

    Architecture v2:
      - Gemini: planning + post-attack analysis
      - Ollama (local LLM): autonomous skill execution via ReAct + MCP
      - Fallback: legacy hardcoded skill execution if Ollama unavailable
    """

    def __init__(
        self,
        gemini_client: GeminiClient,
        ollama_client: OllamaClient | None = None,
    ):
        self.gemini_client = gemini_client
        self.ollama_client = ollama_client or OllamaClient()
        self.react_executor = ReActExecutor(self.ollama_client)

    # --- Public API ---------------------------------------------------------

    async def run_static_scan(self, github_url: str) -> dict[str, Any]:
        """GitHub static security scan — delegates to existing static_analyzer."""
        from static_analyzer.github_integration.repo_analyzer import GitHubRepositoryAnalyzer
        from static_analyzer.vulnerability_scanner.ai_app_scanner import AIAppSecurityScanner

        logger.info("Static scan", github_url=github_url)
        analyzer = GitHubRepositoryAnalyzer(github_url, gemini_client=self.gemini_client)
        app_config = await analyzer.analyze_repository()
        scanner = AIAppSecurityScanner(app_config)
        result = await scanner.scan()
        logger.info("Static scan done", score=result.get("security_score"))
        return result

    async def run_dynamic_attack(self, target_url: str) -> RedTeamReport:
        """Full dynamic attack: recon → plan (Gemini) → execute (Ollama ReAct) → analyze (Gemini).

        Falls back to legacy hardcoded skill execution if Ollama is unavailable.
        """
        report = RedTeamReport(target_url=target_url)

        server = PlaywrightMCPServer(headless=True)
        await server.start()

        # Check if Ollama is available for ReAct execution
        use_react = await self.ollama_client.is_available()
        if use_react:
            logger.info("Ollama available — using ReAct executor (autonomous mode)")
        else:
            logger.info("Ollama unavailable — falling back to legacy hardcoded skills")

        try:
            # 1. Recon — single pass
            logger.info("Recon phase", url=target_url)
            recon = await self._run_recon(server, target_url)

            # 2. Attack plan via Gemini (planning only — no execution)
            logger.info("Planning via Gemini")
            plan = await self._generate_attack_plan(recon, static_findings=None)
            report.attack_plan = plan

            # 3. Execute skills
            if use_react:
                # v2: Ollama ReAct executor — autonomous MCP usage
                await self._execute_react(server, plan, target_url, report)
            else:
                # v1 fallback: legacy hardcoded skills
                await self._execute_legacy(server, plan, target_url, recon, report)

            # 4. Score + summary
            report.calculate_score()
            report.finished_at = datetime.utcnow().isoformat()
            report.summary = _build_summary(report)

            # 5. Post-attack analysis via Gemini
            if report.attack_results:
                analysis = await self._analyze_results(report)
                if analysis:
                    report.summary += f"\n\n--- Gemini Analysis ---\n{analysis}"

        finally:
            await server.stop()

        logger.info("Dynamic attack complete", report_id=report.report_id, score=report.overall_score)
        return report

    async def _execute_react(
        self,
        server: PlaywrightMCPServer,
        plan: AttackPlan,
        target_url: str,
        report: RedTeamReport,
    ) -> None:
        """Execute skills via Ollama ReAct executor (autonomous mode)."""
        for skill_id in plan.priority_order:
            skill_knowledge = get_skill(skill_id)
            if skill_knowledge is None:
                logger.warning("Unknown skill in plan (knowledge)", skill=skill_id)
                continue

            logger.info("ReAct executing skill", skill=skill_id)
            try:
                react_result = await self.react_executor.execute_skill(
                    skill_id, target_url, server
                )
                # Convert ReAct result to SkillResult
                severity_map = {
                    "critical": ThreatLevel.CRITICAL,
                    "high": ThreatLevel.HIGH,
                    "medium": ThreatLevel.MEDIUM,
                    "low": ThreatLevel.LOW,
                }
                report.attack_results.append(
                    SkillResult(
                        skill_name=skill_id,
                        success=react_result.get("success", False),
                        severity=severity_map.get(
                            skill_knowledge.get("severity", "medium"),
                            ThreatLevel.MEDIUM,
                        ),
                        evidence=react_result.get("evidence", []),
                        timeline=[],
                        duration_ms=react_result.get("duration_ms", 0),
                    )
                )
                logger.info(
                    "ReAct skill done",
                    skill=skill_id,
                    success=react_result.get("success"),
                    iterations=react_result.get("iterations"),
                )
            except Exception as e:
                logger.error("ReAct skill failed", skill=skill_id, error=str(e))
                report.attack_results.append(
                    SkillResult(
                        skill_name=skill_id,
                        success=False,
                        severity=ThreatLevel.LOW,
                        error=str(e),
                    )
                )

    async def _execute_legacy(
        self,
        server: PlaywrightMCPServer,
        plan: AttackPlan,
        target_url: str,
        recon: ReconData,
        report: RedTeamReport,
    ) -> None:
        """Execute skills via legacy hardcoded Python logic (fallback)."""
        registry = get_registry()
        for skill_name in plan.priority_order:
            skill_instance = registry.get(skill_name)
            if skill_instance is None:
                logger.warning("Unknown skill in plan (legacy)", skill=skill_name)
                continue

            logger.info("Legacy executing skill", skill=skill_name)
            try:
                await server.call_tool("browser_navigate", {"url": target_url})
                result = await skill_instance.execute(server, target_url, recon=recon)
                report.attack_results.append(result)
                logger.info("Legacy skill done", skill=skill_name, success=result.success)
            except Exception as e:
                logger.error("Legacy skill failed", skill=skill_name, error=str(e))
                report.attack_results.append(
                    SkillResult(
                        skill_name=skill_name,
                        success=False,
                        severity=ThreatLevel.LOW,
                        error=str(e),
                    )
                )

    async def _analyze_results(self, report: RedTeamReport) -> str:
        """Gemini post-attack analysis — summarize findings and recommend fixes."""
        findings = []
        for r in report.attack_results:
            if r.success:
                findings.append(f"- {r.skill_name} ({r.severity.value}): {', '.join(r.evidence[:3])}")

        if not findings:
            return ""

        prompt = (
            "あなたはセキュリティアナリストです。以下のペネトレーションテスト結果を分析してください。\n\n"
            f"対象: {report.target_url}\n"
            f"スコア: {report.overall_score}/100\n\n"
            "検出された脆弱性:\n"
            + "\n".join(findings)
            + "\n\n"
            "各脆弱性の影響度と推奨される修正方法を簡潔に述べてください。"
        )

        try:
            result = await self.gemini_client.analyze_with_flash(
                [{"type": "text", "text": prompt}]
            )
            return result.get("reasoning", "")
        except Exception as e:
            logger.warning("Gemini analysis failed", error=str(e))
            return ""

    async def run_full_red_team(
        self,
        target_url: str,
        github_url: str | None = None,
    ) -> dict[str, Any]:
        """Combined static + dynamic in one call.

        When both GitHub URL and target URL are provided, static analysis
        results are used to inform the dynamic attack planning for more
        effective attack scenarios.
        """
        combined: dict[str, Any] = {
            "red_team_id": str(uuid.uuid4()),
            "started_at": datetime.utcnow().isoformat(),
            "static": None,
            "dynamic": None,
        }

        static_findings: dict[str, Any] | None = None

        # 1. Static analysis (GitHub) - if provided
        if github_url:
            try:
                logger.info("Running static analysis", github_url=github_url)
                combined["static"] = await self.run_static_scan(github_url)
                static_findings = combined["static"]
            except Exception as e:
                logger.error("Static scan failed", error=str(e))
                combined["static"] = {"error": str(e)}

        # 2. Dynamic attack (informed by static findings if available)
        try:
            report = await self._run_dynamic_attack_with_context(
                target_url, static_findings
            )
            combined["dynamic"] = report.model_dump()
        except Exception as e:
            logger.error("Dynamic attack failed", error=str(e))
            combined["dynamic"] = {"error": str(e)}

        combined["finished_at"] = datetime.utcnow().isoformat()
        return combined

    async def _run_dynamic_attack_with_context(
        self,
        target_url: str,
        static_findings: dict[str, Any] | None = None,
    ) -> RedTeamReport:
        """Dynamic attack with optional static analysis context."""
        report = RedTeamReport(target_url=target_url)

        server = PlaywrightMCPServer(headless=True)
        await server.start()

        use_react = await self.ollama_client.is_available()

        try:
            # 1. Recon
            logger.info("Recon phase", url=target_url)
            recon = await self._run_recon(server, target_url)

            # 2. Attack plan via Gemini (with static context)
            logger.info("Planning via Gemini", has_static_context=static_findings is not None)
            plan = await self._generate_attack_plan(recon, static_findings)
            report.attack_plan = plan

            # 3. Execute: ReAct (Ollama) or legacy fallback
            if use_react:
                await self._execute_react(server, plan, target_url, report)
            else:
                await self._execute_legacy(server, plan, target_url, recon, report)

            # 4. Score + summary
            report.calculate_score()
            report.finished_at = datetime.utcnow().isoformat()
            report.summary = _build_summary(report)

            # 5. Post-attack analysis via Gemini
            if report.attack_results:
                analysis = await self._analyze_results(report)
                if analysis:
                    report.summary += f"\n\n--- Gemini Analysis ---\n{analysis}"

        finally:
            await server.stop()

        logger.info("Dynamic attack complete", report_id=report.report_id, score=report.overall_score)
        return report

    # --- Internal -----------------------------------------------------------

    async def _run_recon(self, server: PlaywrightMCPServer, target_url: str) -> ReconData:
        """Gather structured reconnaissance in a single page visit."""
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

        cookies = json.loads(
            (await server.call_tool("browser_get_cookies", {})).get("result", "[]")
        )
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

    async def _generate_attack_plan(
        self,
        recon: ReconData,
        static_findings: dict[str, Any] | None = None,
    ) -> AttackPlan:
        """Gemini Flash picks which skills to run and in what order.

        Args:
            recon: Dynamic reconnaissance data from the target page
            static_findings: Optional static analysis results from GitHub scan
        """
        # Use knowledge-layer skill index for planning
        available = list_skills()
        skill_summaries = "\n".join(
            f"  - {s['id']}: {s['name']} [{s['severity']}] — {s['description']}"
            for s in SKILL_INDEX
        )

        # Build context from static findings if available
        static_context = ""
        if static_findings:
            vulnerabilities = static_findings.get("vulnerabilities", [])
            security_score = static_findings.get("security_score", "N/A")
            static_context = (
                f"\n--- 静的分析結果 (GitHub) ---\n"
                f"セキュリティスコア: {security_score}\n"
                f"検出された脆弱性: {len(vulnerabilities)}件\n"
            )
            if vulnerabilities:
                vuln_summary = ", ".join(
                    v.get("type", "unknown") for v in vulnerabilities[:10]
                )
                static_context += f"脆弱性タイプ: {vuln_summary}\n"

        prompt = (
            f"あなたはThreat DrillのRedTeam攻撃プランナーです。\n"
            f"対象アプリの情報から最も効果的な攻撃の組み合わせと優先順位を決定してください。\n\n"
            f"--- 動的分析結果 (ページ情報) ---\n"
            f"対象URL: {recon.url}\n"
            f"ページテキスト(冒頭500文字): {recon.text[:500]}\n"
            f"入力フィールド数: {len(recon.inputs)}\n"
            f"フォーム数: {len(recon.forms)}\n"
            f"Cookie数: {len(recon.cookies)}\n"
            f"localStorage キー: {list(recon.local_storage.keys())}\n"
            f"{static_context}\n"
            f"利用可能なスキル:\n{skill_summaries}\n\n"
            f"静的分析と動的分析の両方を考慮して、攻撃計画を立ててください。\n"
            f"以下JSON形式で回答(他のテキスト不要):\n"
            f'{{"reasoning":"なぜこれらを選んだか","selected_attacks":["name",...],"priority_order":["最優先",...]}}\n'
        )

        # TODO: 実際のVertex AI SDKを使用
        result = await self.gemini_client.analyze_with_flash(
            [{"type": "text", "text": prompt}]
        )

        # Parse — fallback to full skill list
        reasoning = result.get("reasoning", "")
        try:
            m = re.search(r"\{.*\}", reasoning, re.DOTALL)
            plan_data: dict[str, Any] = json.loads(m.group()) if m else {}
        except Exception:
            plan_data = {}

        return AttackPlan(
            target_url=recon.url,
            reasoning=plan_data.get("reasoning", reasoning or "Default: run all skills"),
            selected_attacks=plan_data.get("selected_attacks", available),
            priority_order=plan_data.get("priority_order", available),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_summary(report: RedTeamReport) -> str:
    total = len(report.attack_results)
    confirmed = sum(1 for r in report.attack_results if r.success)
    critical = sum(1 for r in report.attack_results if r.success and r.severity == ThreatLevel.CRITICAL)
    high = sum(1 for r in report.attack_results if r.success and r.severity == ThreatLevel.HIGH)

    lines = [
        f"Red Team Report — {report.report_id}",
        f"Target: {report.target_url}  |  Score: {report.overall_score}/100",
        f"Executed: {total}  |  Confirmed: {confirmed}  |  Critical: {critical}  |  High: {high}",
        "",
    ]
    for r in report.attack_results:
        tag = "VULN" if r.success else "OK  "
        lines.append(f"  [{tag}] {r.skill_name:<25} {r.severity.value:<10} {len(r.evidence)} findings")

    return "\n".join(lines)
