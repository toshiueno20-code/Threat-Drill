"""Attack Orchestrator — unified static (GitHub) + dynamic (URL) red-team flow.

Architecture
------------
1. [Recon]   Navigate once → collect structured ``ReconData``.
2. [Plan]    Feed recon into Gemini 3 Flash → ``AttackPlan`` (ordered skill list).
3. [Execute] Run each skill in priority order, passing recon so skills skip
             redundant page-fetches.
4. [Report]  Aggregate ``SkillResult`` list → score → ``RedTeamReport``.

All data-transfer objects are Pydantic v2 ``BaseModel`` so the router can
serialise them with a single ``model_dump()`` call.
"""

import json
import re
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from shared.schemas import ThreatLevel
from shared.utils import get_logger
from intelligence_center.models import GeminiClient
from red_teaming.mcp_server.playwright_mcp import PlaywrightMCPServer, validate_localhost_url
from red_teaming.skills import get_registry, SkillResult, ReconData

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
    """Orchestrates the full red-team pipeline via the Skill registry."""

    def __init__(self, gemini_client: GeminiClient):
        self.gemini_client = gemini_client

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
        """Full dynamic attack: recon → plan → skills → report."""
        validate_localhost_url(target_url)
        report = RedTeamReport(target_url=target_url)

        server = PlaywrightMCPServer(headless=True)
        await server.start()

        try:
            # 1. Recon — single pass, data shared with every skill
            logger.info("Recon phase", url=target_url)
            recon = await self._run_recon(server, target_url)

            # 2. Attack plan via Gemini
            logger.info("Planning via Gemini")
            plan = await self._generate_attack_plan(recon)
            report.attack_plan = plan

            # 3. Execute skills in priority order
            registry = get_registry()
            for skill_name in plan.priority_order:
                skill_instance = registry.get(skill_name)
                if skill_instance is None:
                    logger.warning("Unknown skill in plan", skill=skill_name)
                    continue

                logger.info("Running skill", skill=skill_name)
                try:
                    await server.call_tool("browser_navigate", {"url": target_url})
                    result = await skill_instance.execute(server, target_url, recon=recon)
                    report.attack_results.append(result)
                    logger.info("Skill done", skill=skill_name, success=result.success)
                except Exception as e:
                    logger.error("Skill failed", skill=skill_name, error=str(e))
                    report.attack_results.append(
                        SkillResult(
                            skill_name=skill_name,
                            success=False,
                            severity=ThreatLevel.LOW,
                            error=str(e),
                        )
                    )

            # 4. Score + summary
            report.calculate_score()
            report.finished_at = datetime.utcnow().isoformat()
            report.summary = _build_summary(report)

        finally:
            await server.stop()

        logger.info("Dynamic attack complete", report_id=report.report_id, score=report.overall_score)
        return report

    async def run_full_red_team(
        self,
        target_url: str,
        github_url: str | None = None,
    ) -> dict[str, Any]:
        """Combined static + dynamic in one call."""
        combined: dict[str, Any] = {
            "red_team_id": str(uuid.uuid4()),
            "started_at": datetime.utcnow().isoformat(),
            "static": None,
            "dynamic": None,
        }

        if github_url:
            try:
                combined["static"] = await self.run_static_scan(github_url)
            except Exception as e:
                logger.error("Static scan failed", error=str(e))
                combined["static"] = {"error": str(e)}

        try:
            report = await self.run_dynamic_attack(target_url)
            combined["dynamic"] = report.model_dump()
        except Exception as e:
            logger.error("Dynamic attack failed", error=str(e))
            combined["dynamic"] = {"error": str(e)}

        combined["finished_at"] = datetime.utcnow().isoformat()
        return combined

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

    async def _generate_attack_plan(self, recon: ReconData) -> AttackPlan:
        """Gemini Flash picks which skills to run and in what order."""
        available = get_registry().names()

        prompt = (
            f"あなたはAegisFlowのRedTeam攻撃プランナーです。\n"
            f"対象アプリの情報から最も効果的な攻撃の組み合わせと優先順位を決定してください。\n\n"
            f"対象URL: {recon.url}\n"
            f"ページテキスト(冒頭500文字): {recon.text[:500]}\n"
            f"入力フィールド数: {len(recon.inputs)}\n"
            f"フォーム数: {len(recon.forms)}\n"
            f"Cookie数: {len(recon.cookies)}\n"
            f"localStorage キー: {list(recon.local_storage.keys())}\n\n"
            f"利用可能なスキル: {available}\n\n"
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
