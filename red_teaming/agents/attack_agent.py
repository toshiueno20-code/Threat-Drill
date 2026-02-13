"""Red Team Agent wrapper with strict human-approval controls.

The legacy class name is preserved for compatibility. Policy behavior:
- AI can plan vulnerability checks.
- Any skill execution requires explicit user approval per request.
- Autonomous attack execution loops are disabled.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from shared.schemas import ThreatLevel
from shared.constants import RED_TEAM_MAX_CONCURRENT_ATTACKS
from shared.utils import get_logger
from intelligence_center.models import GeminiClient
from red_teaming.mcp_server.playwright_mcp import PlaywrightMCPServer
from red_teaming.skills import SkillResult, get_registry
from red_teaming.orchestrator.attack_orchestrator import AttackOrchestrator

logger = get_logger(__name__)


@dataclass
class ExecutionApproval:
    """Per-request user approval metadata for skill execution."""

    approved: bool
    approved_by: str
    approval_note: str = ""


class RedTeamAgent:
    """High-level red-team agent backed by the skill registry and orchestrator."""

    def __init__(self, gemini_client: GeminiClient, target_endpoint: str):
        self.gemini_client = gemini_client
        self.target_endpoint = target_endpoint
        self.orchestrator = AttackOrchestrator(gemini_client)
        self.registry = get_registry()
        logger.info("RedTeamAgent initialized", target=target_endpoint, skills=self.registry.names())

    def get_attack_scenarios(self) -> list[dict[str, str]]:
        """Return registered read-only check skills in scenario format."""
        return [
            {
                "scenario_id": skill.skill_name,
                "name": skill.skill_name,
                "description": skill.skill_description,
                "attack_type": "read_only_check",
                "severity": skill.default_severity.value,
            }
            for skill in self.registry.list_all()
        ]

    async def execute_skill(self, skill_name: str, approval: ExecutionApproval) -> SkillResult:
        """Run one check skill in an isolated browser session with user approval."""
        self._ensure_approved(approval)

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
        except Exception as exc:
            logger.error("Skill execution failed", skill=skill_name, error=str(exc))
            return SkillResult(
                skill_name=skill_name,
                success=False,
                severity=ThreatLevel.LOW,
                error=str(exc),
            )
        finally:
            await server.stop()

    async def execute_full_attack(self) -> dict[str, Any]:
        """Backward-compatible method; now returns assessment plan only."""
        report = await self.orchestrator.run_dynamic_assessment(self.target_endpoint)
        return report.model_dump()

    async def run_all_skills(
        self,
        approval: ExecutionApproval,
        selected_skills: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run approved check skills with bounded concurrency."""
        self._ensure_approved(approval)

        skill_names = selected_skills or self.registry.names()
        semaphore = asyncio.Semaphore(RED_TEAM_MAX_CONCURRENT_ATTACKS)

        async def _run(name: str) -> dict[str, Any]:
            async with semaphore:
                result = await self.execute_skill(name, approval)
                return {
                    "scenario_id": name,
                    "check_result": result.model_dump(),
                    "finding_confirmed": result.success,
                    "timestamp": datetime.utcnow().isoformat(),
                }

        results = await asyncio.gather(*[_run(name) for name in skill_names])
        confirmed = sum(1 for item in results if item.get("finding_confirmed"))

        return {
            "run_id": str(uuid.uuid4()),
            "target": self.target_endpoint,
            "total_scenarios": len(results),
            "findings_confirmed": confirmed,
            "results": list(results),
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def run_continuous_testing(self, interval_hours: int = 24) -> None:
        """Disabled by policy to prevent autonomous offensive behavior."""
        raise RuntimeError(
            "Continuous autonomous security skill execution is disabled. "
            "Use per-request execution with explicit user approval."
        )

    async def generate_novel_skills(self, recent_vulnerabilities: list[str]) -> list[str]:
        """Suggest prioritization among existing read-only checks."""
        import json as _json
        import re as _re

        available = self.registry.names()
        prompt = (
            "You are a security QA planner.\n"
            "Prioritize only the existing read-only vulnerability checks.\n"
            "Do not propose exploit instructions, payloads, or offensive actions.\n"
            f"Recent vulnerability types: {recent_vulnerabilities}\n"
            f"Available checks: {available}\n\n"
            "Return JSON array only. Example: [\"check_a\", \"check_b\"]"
        )

        result = await self.gemini_client.analyze_with_flash([{"type": "text", "text": prompt}])

        reasoning = str(result.get("reasoning", ""))
        try:
            match = _re.search(r"\[.*\]", reasoning, _re.DOTALL)
            names: list[str] = _json.loads(match.group()) if match else []
        except Exception:
            names = []

        filtered = [name for name in names if name in available]
        if not filtered:
            filtered = available

        logger.info("Check prioritization generated", suggested=filtered)
        return filtered

    @staticmethod
    def _ensure_approved(approval: ExecutionApproval) -> None:
        """Require explicit approval metadata before any skill execution."""
        if not approval.approved:
            raise PermissionError("Skill execution requires explicit user approval.")
        if not approval.approved_by.strip():
            raise PermissionError("Skill execution requires approved_by metadata.")
