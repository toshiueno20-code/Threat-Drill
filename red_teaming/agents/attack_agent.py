"""Autonomous Red Team Agent — Gemini 3 + Playwright MCP + Skill Registry.

The agent is the public-facing façade that the router talks to.  Internally it
delegates everything to the ``SkillRegistry`` (for individual skills) and
``AttackOrchestrator`` (for the full planned pipeline).

Key methods
-----------
execute_full_attack()   — orchestrator-driven: recon → plan → all skills → report
execute_skill(name)     — single skill in an isolated browser session
run_all_skills()        — concurrent execution of every registered skill
generate_novel_skills() — Gemini generates new attack ideas from CVE data
"""

import asyncio
import uuid
from datetime import datetime
from typing import Any

from shared.schemas import ThreatLevel
from shared.constants import RED_TEAM_MAX_CONCURRENT_ATTACKS
from shared.utils import get_logger
from intelligence_center.models import GeminiClient
from red_teaming.mcp_server.playwright_mcp import PlaywrightMCPServer
from red_teaming.skills import get_registry, SkillResult
from red_teaming.orchestrator.attack_orchestrator import AttackOrchestrator

logger = get_logger(__name__)


class RedTeamAgent:
    """High-level red-team agent backed by the Skill registry + orchestrator.

    Target URLs are verified via sandbox handshake at navigation time.
    """

    def __init__(self, gemini_client: GeminiClient, target_endpoint: str):
        # URL verification happens in PlaywrightMCPServer during navigation
        self.gemini_client = gemini_client
        self.target_endpoint = target_endpoint
        self.orchestrator = AttackOrchestrator(gemini_client)
        self.registry = get_registry()
        logger.info("RedTeamAgent ready", target=target_endpoint, skills=self.registry.names())

    # --- Skill listing (router-facing) --------------------------------------

    def get_attack_scenarios(self) -> list[dict[str, str]]:
        """Return all registered skills as scenario-info dicts."""
        return [
            {
                "scenario_id": s.skill_name,
                "name": s.skill_name,
                "description": s.skill_description,
                "attack_type": s.skill_name,
                "severity": s.default_severity.value,
            }
            for s in self.registry.list_all()
        ]

    # --- Single-skill execution --------------------------------------------

    async def execute_skill(self, skill_name: str) -> SkillResult:
        """Run one skill in an isolated Playwright session."""
        skill_instance = self.registry.get(skill_name)
        if skill_instance is None:
            return SkillResult(
                skill_name=skill_name,
                success=False,
                severity=ThreatLevel.LOW,
                error=f"Unknown skill: {skill_name}. Available: {self.registry.names()}",
            )

        server = PlaywrightMCPServer(headless=True)
        await server.start()
        try:
            await server.call_tool("browser_navigate", {"url": self.target_endpoint})
            return await skill_instance.execute(server, self.target_endpoint)
        except Exception as e:
            logger.error("Skill error", skill=skill_name, error=str(e))
            return SkillResult(
                skill_name=skill_name,
                success=False,
                severity=ThreatLevel.LOW,
                error=str(e),
            )
        finally:
            await server.stop()

    # --- Full orchestrated attack ------------------------------------------

    async def execute_full_attack(self) -> dict[str, Any]:
        """Orchestrator-driven: recon → Gemini plan → skills → report."""
        report = await self.orchestrator.run_dynamic_attack(self.target_endpoint)
        return report.model_dump()

    # --- Batch execution (concurrent) --------------------------------------

    async def run_all_skills(self) -> dict[str, Any]:
        """Run every registered skill concurrently with a semaphore cap."""
        skill_names = self.registry.names()
        semaphore = asyncio.Semaphore(RED_TEAM_MAX_CONCURRENT_ATTACKS)

        async def _run(name: str) -> dict[str, Any]:
            async with semaphore:
                result = await self.execute_skill(name)
                return {
                    "scenario_id": name,
                    "attack_result": result.model_dump(),
                    "vulnerability_confirmed": result.success,
                    "timestamp": datetime.utcnow().isoformat(),
                }

        results = await asyncio.gather(*[_run(n) for n in skill_names])
        confirmed = sum(1 for r in results if r.get("vulnerability_confirmed"))

        return {
            "run_id": str(uuid.uuid4()),
            "target": self.target_endpoint,
            "total_scenarios": len(results),
            "vulnerabilities_confirmed": confirmed,
            "results": list(results),
            "timestamp": datetime.utcnow().isoformat(),
        }

    # --- Continuous testing loop --------------------------------------------

    async def run_continuous_testing(self, interval_hours: int = 24) -> None:
        """Run all skills repeatedly at the given interval."""
        logger.info("Continuous testing started", interval_hours=interval_hours)
        while True:
            try:
                summary = await self.run_all_skills()
                logger.info(
                    "Round complete",
                    vulnerabilities=summary["vulnerabilities_confirmed"],
                    total=summary["total_scenarios"],
                )
                # TODO: パブリッシュ結果を Pub/Sub に送信
                await asyncio.sleep(interval_hours * 3600)
            except Exception as e:
                logger.error("Continuous testing error", error=str(e))
                await asyncio.sleep(3600)

    # --- AI-driven novel-skill generation ----------------------------------

    async def generate_novel_skills(
        self,
        recent_vulnerabilities: list[str],
    ) -> list[str]:
        """Use Gemini to propose new attack skill names from CVE data.

        Returns a list of *existing* registry skill names that should be
        prioritised, plus any novel labels the model suggests (for future
        implementation).
        """
        import json as _json
        import re as _re

        available = self.registry.names()
        prompt = (
            f"あなたはThreat DrillのRedTeam攻撃シナリオジェネレータです。\n"
            f"以下の最近の脆弱性情報から、対象アプリに適用できる攻撃スキルの組み合わせを提案してください。\n\n"
            f"既知の脆弱性: {recent_vulnerabilities}\n"
            f"既存スキル: {available}\n\n"
            f"既存スキルの優先順位リスト + 新規提案スキル名を以下JSON形式で回答:\n"
            f'["既存スキル名", ..., "新規提案スキル名"]\n'
        )

        result = await self.gemini_client.analyze_with_flash(
            [{"type": "text", "text": prompt}]
        )

        # Parse
        reasoning = result.get("reasoning", "")
        try:
            m = _re.search(r"\[.*\]", reasoning, _re.DOTALL)
            names: list[str] = _json.loads(m.group()) if m else []
        except Exception:
            names = []

        if not names:
            names = available  # fallback: run everything

        logger.info("Novel skill proposal", suggested=names)
        return names
