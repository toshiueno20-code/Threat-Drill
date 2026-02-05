"""Attack Orchestrator — unified static (GitHub) + dynamic (URL) red-team flow.

Flow:
    1. [Static] GitHub URL → clone → content-based scan → vuln report
    2. [Dynamic] Target URL → Gemini attack-plan → Playwright MCP execution → results
    3. Consolidated report (per-attack detail + aggregate score)

Gemini 3 is used to:
    - Plan which attacks are most relevant for the discovered app stack
    - Classify attack success/failure after execution
    - Generate new attack variants from prior results
"""

import json
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from shared.schemas import ThreatLevel
from shared.utils import get_logger
from intelligence_center.models import GeminiClient
from red_teaming.mcp_server.playwright_mcp import PlaywrightMCPServer, validate_localhost_url
from red_teaming.mcp_server.attack_tools import ATTACK_REGISTRY, AttackResult

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


class AttackPlan:
    """Gemini-generated attack plan for a target."""

    def __init__(
        self,
        plan_id: str,
        target_url: str,
        reasoning: str,
        selected_attacks: List[str],
        priority_order: List[str],
    ):
        self.plan_id = plan_id
        self.target_url = target_url
        self.reasoning = reasoning
        self.selected_attacks = selected_attacks
        self.priority_order = priority_order
        self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "target_url": self.target_url,
            "reasoning": self.reasoning,
            "selected_attacks": self.selected_attacks,
            "priority_order": self.priority_order,
            "created_at": self.created_at,
        }


class RedTeamReport:
    """Consolidated red-team report covering static + dynamic phases."""

    def __init__(self, report_id: str, target_url: str):
        self.report_id = report_id
        self.target_url = target_url
        self.started_at = datetime.utcnow().isoformat()
        self.finished_at: Optional[str] = None
        self.static_result: Optional[Dict[str, Any]] = None
        self.attack_plan: Optional[AttackPlan] = None
        self.attack_results: List[AttackResult] = []
        self.overall_score: float = 100.0  # 100 = secure; deductions per finding
        self.summary: str = ""

    def calculate_score(self) -> float:
        """Deduce from 100 based on confirmed attack severities."""
        score = 100.0
        deductions = {
            ThreatLevel.CRITICAL: 25,
            ThreatLevel.HIGH: 15,
            ThreatLevel.MEDIUM: 7,
            ThreatLevel.LOW: 3,
        }
        for result in self.attack_results:
            if result.success:
                score -= deductions.get(result.severity, 5)
        self.overall_score = max(score, 0.0)
        return self.overall_score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "target_url": self.target_url,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "static_result": self.static_result,
            "attack_plan": self.attack_plan.to_dict() if self.attack_plan else None,
            "attack_results": [r.to_dict() for r in self.attack_results],
            "overall_score": self.overall_score,
            "summary": self.summary,
        }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class AttackOrchestrator:
    """Orchestrates the full red-team pipeline.

    Args:
        gemini_client: GeminiClient instance for AI-driven planning / analysis
    """

    def __init__(self, gemini_client: GeminiClient):
        self.gemini_client = gemini_client

    # --- Public API ---------------------------------------------------------

    async def run_static_scan(self, github_url: str) -> Dict[str, Any]:
        """Run GitHub static security scan via the existing static_analyzer.

        Delegates to GitHubRepositoryAnalyzer + AIAppSecurityScanner.
        Returns the scan result dict (same as /static-analysis/scan response).
        """
        from static_analyzer.github_integration.repo_analyzer import GitHubRepositoryAnalyzer
        from static_analyzer.vulnerability_scanner.ai_app_scanner import AIAppSecurityScanner

        logger.info("Orchestrator: starting static scan", github_url=github_url)

        analyzer = GitHubRepositoryAnalyzer(github_url, gemini_client=self.gemini_client)
        app_config = await analyzer.analyze_repository()
        scanner = AIAppSecurityScanner(app_config)
        scan_result = await scanner.scan()

        logger.info("Orchestrator: static scan complete", score=scan_result.get("security_score"))
        return scan_result

    async def run_dynamic_attack(self, target_url: str) -> RedTeamReport:
        """Execute the full dynamic red-team attack flow against target_url.

        Steps:
            1. Validate localhost-only
            2. Recon the target page
            3. Use Gemini to create an attack plan
            4. Execute attacks via Playwright MCP
            5. Compile report
        """
        # Guard
        validate_localhost_url(target_url)

        report = RedTeamReport(
            report_id=str(uuid.uuid4()),
            target_url=target_url,
        )

        server = PlaywrightMCPServer(headless=True)
        await server.start()

        try:
            # --- Recon -------------------------------------------------------
            logger.info("Orchestrator: starting recon", url=target_url)
            await server.call_tool("browser_navigate", {"url": target_url})
            html = (await server.call_tool("browser_get_html", {})).get("result", "")
            text = (await server.call_tool("browser_get_text", {})).get("result", "")

            # --- Attack Planning (Gemini) ------------------------------------
            logger.info("Orchestrator: generating attack plan via Gemini")
            plan = await self._generate_attack_plan(target_url, html, text)
            report.attack_plan = plan

            # --- Attack Execution --------------------------------------------
            for attack_type in plan.priority_order:
                attack_cls = ATTACK_REGISTRY.get(attack_type)
                if attack_cls is None:
                    logger.warning("Unknown attack type in plan", attack_type=attack_type)
                    continue

                logger.info("Orchestrator: executing attack", attack_type=attack_type)
                try:
                    # Re-navigate to target before each attack
                    await server.call_tool("browser_navigate", {"url": target_url})
                    attack_instance = attack_cls()
                    result = await attack_instance.execute(server, target_url)
                    report.attack_results.append(result)
                    logger.info(
                        "Attack completed",
                        attack_type=attack_type,
                        success=result.success,
                        evidence_count=len(result.evidence),
                    )
                except Exception as e:
                    logger.error("Attack execution failed", attack_type=attack_type, error=str(e))
                    report.attack_results.append(
                        AttackResult(
                            attack_type=attack_type,
                            success=False,
                            severity=ThreatLevel.LOW,
                            error=str(e),
                        )
                    )

            # --- Scoring & Summary ------------------------------------------
            report.calculate_score()
            report.finished_at = datetime.utcnow().isoformat()
            report.summary = self._build_summary(report)

        finally:
            await server.stop()

        logger.info(
            "Orchestrator: dynamic attack complete",
            report_id=report.report_id,
            score=report.overall_score,
        )
        return report

    async def run_full_red_team(
        self,
        target_url: str,
        github_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Combined static + dynamic flow.

        Args:
            target_url: localhost URL of the running app (for dynamic attacks)
            github_url: Optional GitHub repo URL (for static scan)
        """
        combined: Dict[str, Any] = {
            "red_team_id": str(uuid.uuid4()),
            "started_at": datetime.utcnow().isoformat(),
            "static": None,
            "dynamic": None,
        }

        # Static phase (parallel-safe, but we await sequentially for simplicity)
        if github_url:
            try:
                combined["static"] = await self.run_static_scan(github_url)
            except Exception as e:
                logger.error("Static scan failed", error=str(e))
                combined["static"] = {"error": str(e)}

        # Dynamic phase
        try:
            report = await self.run_dynamic_attack(target_url)
            combined["dynamic"] = report.to_dict()
        except Exception as e:
            logger.error("Dynamic attack failed", error=str(e))
            combined["dynamic"] = {"error": str(e)}

        combined["finished_at"] = datetime.utcnow().isoformat()
        return combined

    # --- Internal helpers ---------------------------------------------------

    async def _generate_attack_plan(
        self, target_url: str, page_html: str, page_text: str
    ) -> AttackPlan:
        """Use Gemini to decide which attacks to run and in what order."""
        available_attacks = list(ATTACK_REGISTRY.keys())

        prompt = (
            f"あなたはAegisFlowのRedTeam攻撃プランナーです。\n"
            f"以下の対象アプリの情報から、最も効果的な攻撃の組み合わせと優先順位を決定してください。\n\n"
            f"対象URL: {target_url}\n"
            f"ページテキスト(冒頭500文字): {page_text[:500]}\n"
            f"ページHTML(冒頭2000文字): {page_html[:2000]}\n\n"
            f"利用可能な攻撃タイプ: {available_attacks}\n\n"
            f"以下のJSON形式で回答してください(他のテキストは不要):\n"
            f'{{\n'
            f'  "reasoning": "なぜこれらの攻撃を選んだか",\n'
            f'  "selected_attacks": ["attack_type1", ...],\n'
            f'  "priority_order": ["最優先", "2番目", ...]\n'
            f'}}\n'
        )

        # TODO: 実際のVertex AI SDKを使用
        # Gemini Flash で高速プランニング
        result = await self.gemini_client.analyze_with_flash(
            [{"type": "text", "text": prompt}]
        )

        # Parse Gemini response — fallback to all attacks if parse fails
        try:
            # GeminiClient returns ThreatAnalysisResult-like dict; extract reasoning
            reasoning = result.get("reasoning", "")
            # Try to extract JSON from reasoning if it's embedded
            import re

            json_match = re.search(r"\{.*\}", reasoning, re.DOTALL)
            if json_match:
                plan_data = json.loads(json_match.group())
            else:
                plan_data = {
                    "reasoning": reasoning or "Gemini plan (default)",
                    "selected_attacks": available_attacks,
                    "priority_order": available_attacks,
                }
        except Exception:
            plan_data = {
                "reasoning": "Default plan: run all available attack types",
                "selected_attacks": available_attacks,
                "priority_order": available_attacks,
            }

        return AttackPlan(
            plan_id=str(uuid.uuid4()),
            target_url=target_url,
            reasoning=plan_data.get("reasoning", ""),
            selected_attacks=plan_data.get("selected_attacks", available_attacks),
            priority_order=plan_data.get("priority_order", available_attacks),
        )

    @staticmethod
    def _build_summary(report: RedTeamReport) -> str:
        """Generate a human-readable summary string."""
        total = len(report.attack_results)
        confirmed = sum(1 for r in report.attack_results if r.success)
        critical = sum(
            1 for r in report.attack_results if r.success and r.severity == ThreatLevel.CRITICAL
        )
        high = sum(1 for r in report.attack_results if r.success and r.severity == ThreatLevel.HIGH)

        lines = [
            f"Red Team Report — {report.report_id}",
            f"Target: {report.target_url}",
            f"Overall Security Score: {report.overall_score}/100",
            f"Attacks Executed: {total} | Vulnerabilities Confirmed: {confirmed}",
            f"  Critical: {critical} | High: {high}",
        ]

        for r in report.attack_results:
            status = "VULNERABLE" if r.success else "SECURE"
            lines.append(f"  [{status}] {r.attack_type} ({r.severity.value}) — {len(r.evidence)} findings")

        return "\n".join(lines)
