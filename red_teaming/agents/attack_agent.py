"""Autonomous Red Team Agent powered by Gemini 3 + Playwright MCP.

Replaces the previous mock-only implementation with real browser-driven
attack execution via PlaywrightMCPServer and the attack-tool registry.
"""

import asyncio
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

from shared.schemas import ThreatLevel
from shared.constants import RED_TEAM_MAX_CONCURRENT_ATTACKS
from shared.utils import get_logger
from intelligence_center.models import GeminiClient
from red_teaming.mcp_server.playwright_mcp import PlaywrightMCPServer, validate_localhost_url
from red_teaming.mcp_server.attack_tools import ATTACK_REGISTRY, AttackResult
from red_teaming.orchestrator.attack_orchestrator import AttackOrchestrator

logger = get_logger(__name__)


class AttackScenario:
    """攻撃シナリオ定義."""

    def __init__(
        self,
        scenario_id: str,
        name: str,
        description: str,
        attack_type: str,
        severity: ThreatLevel,
        test_cases: List[Dict[str, Any]],
    ):
        self.scenario_id = scenario_id
        self.name = name
        self.description = description
        self.attack_type = attack_type
        self.severity = severity
        self.test_cases = test_cases


class RedTeamAgent:
    """Gemini 3 + Playwright MCP による自律型レッドチームエージェント.

    Usage:
        agent = RedTeamAgent(gemini_client, target_endpoint="http://localhost:8000")
        report = await agent.execute_full_attack()
    """

    def __init__(
        self,
        gemini_client: GeminiClient,
        target_endpoint: str,
    ):
        # localhost-only guard at construction time
        validate_localhost_url(target_endpoint)
        self.gemini_client = gemini_client
        self.target_endpoint = target_endpoint
        self.orchestrator = AttackOrchestrator(gemini_client)

        logger.info("RedTeamAgent initialized", target_endpoint=target_endpoint)

    # --- Scenario registry --------------------------------------------------

    def get_attack_scenarios(self) -> List[AttackScenario]:
        """Return one AttackScenario per registered attack type."""
        _map = {
            "xss": ("XSS Attack", "Cross-Site Scripting via form injection & URL fragments", ThreatLevel.HIGH),
            "sql_injection": ("SQL Injection", "Error-based and boolean-based SQLi via inputs", ThreatLevel.CRITICAL),
            "csrf": ("CSRF Attack", "CSRF token absence & SameSite cookie audit", ThreatLevel.HIGH),
            "prompt_injection": ("Prompt Injection via UI", "AI-input field prompt manipulation", ThreatLevel.CRITICAL),
            "auth_bypass": ("Auth Bypass / Session Hijack", "Default creds, token leaks, insecure cookies", ThreatLevel.CRITICAL),
            "path_traversal": ("Path Traversal", "Directory traversal & sensitive endpoint exposure", ThreatLevel.HIGH),
            "privilege_escalation": ("Privilege Escalation", "Multi-step role manipulation attack", ThreatLevel.HIGH),
        }
        scenarios = []
        for atype, (name, desc, sev) in _map.items():
            scenarios.append(
                AttackScenario(
                    scenario_id=f"{atype}-001",
                    name=name,
                    description=desc,
                    attack_type=atype,
                    severity=sev,
                    test_cases=[{"attack_type": atype, "target": self.target_endpoint}],
                )
            )
        return scenarios

    # --- Core execution (Playwright-driven) ----------------------------------

    async def execute_full_attack(self) -> Dict[str, Any]:
        """Run the complete dynamic red-team flow (Gemini plan → Playwright attacks).

        Returns the RedTeamReport as a dict.
        """
        report = await self.orchestrator.run_dynamic_attack(self.target_endpoint)
        return report.to_dict()

    async def execute_scenario(self, scenario: AttackScenario) -> Dict[str, Any]:
        """Execute a single named attack scenario via Playwright.

        Args:
            scenario: AttackScenario with attack_type matching ATTACK_REGISTRY

        Returns:
            Result dict with scenario_id, attack result, and detection metadata.
        """
        attack_cls = ATTACK_REGISTRY.get(scenario.attack_type)
        if attack_cls is None:
            return {
                "scenario_id": scenario.scenario_id,
                "error": f"Unknown attack_type: {scenario.attack_type}",
                "timestamp": datetime.utcnow().isoformat(),
            }

        server = PlaywrightMCPServer(headless=True)
        await server.start()
        try:
            await server.call_tool("browser_navigate", {"url": self.target_endpoint})
            attack = attack_cls()
            result: AttackResult = await attack.execute(server, self.target_endpoint)
        except Exception as e:
            logger.error("Scenario execution error", scenario_id=scenario.scenario_id, error=str(e))
            result = AttackResult(
                attack_type=scenario.attack_type,
                success=False,
                severity=scenario.severity,
                error=str(e),
            )
        finally:
            await server.stop()

        return {
            "scenario_id": scenario.scenario_id,
            "scenario_name": scenario.name,
            "attack_result": result.to_dict(),
            # Detection = we confirmed the vuln exists (red-team success)
            "vulnerability_confirmed": result.success,
            "timestamp": datetime.utcnow().isoformat(),
        }

    # --- Batch / continuous --------------------------------------------------

    async def run_all_scenarios(self) -> Dict[str, Any]:
        """Run every registered scenario with concurrency control.

        Returns aggregated results across all scenarios.
        """
        scenarios = self.get_attack_scenarios()
        semaphore = asyncio.Semaphore(RED_TEAM_MAX_CONCURRENT_ATTACKS)

        async def _run(s: AttackScenario) -> Dict[str, Any]:
            async with semaphore:
                return await self.execute_scenario(s)

        results = await asyncio.gather(*[_run(s) for s in scenarios])

        confirmed = sum(1 for r in results if r.get("vulnerability_confirmed"))
        return {
            "run_id": str(uuid.uuid4()),
            "target": self.target_endpoint,
            "total_scenarios": len(results),
            "vulnerabilities_confirmed": confirmed,
            "results": results,
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def run_continuous_testing(self, interval_hours: int = 24) -> None:
        """Continuously run all scenarios at the given interval."""
        logger.info("Starting continuous red team testing", interval_hours=interval_hours)

        while True:
            try:
                summary = await self.run_all_scenarios()
                logger.info(
                    "Continuous testing round completed",
                    vulnerabilities=summary["vulnerabilities_confirmed"],
                    total=summary["total_scenarios"],
                )
                # TODO: パブリッシュ結果を Pub/Sub に送信
                await asyncio.sleep(interval_hours * 3600)
            except Exception as e:
                logger.error("Continuous testing error", error=str(e))
                await asyncio.sleep(3600)

    # --- AI-driven scenario generation --------------------------------------

    async def generate_new_attack_scenarios(
        self,
        recent_vulnerabilities: List[str],
    ) -> List[AttackScenario]:
        """Use Gemini 3 to generate novel attack scenarios from recent vuln data.

        Args:
            recent_vulnerabilities: List of CVE IDs or vulnerability descriptions

        Returns:
            New AttackScenario instances (attack_type mapped to closest registry entry)
        """
        prompt = (
            f"あなたはAegisFlowのRedTeam攻撃シナリオジェネレータです。\n"
            f"以下の最近の脆弱性情報から、対象アプリに適用できる新しい攻撃シナリオを生成してください。\n\n"
            f"既知の脆弱性: {recent_vulnerabilities}\n"
            f"利用可能な攻撃タイプ: {list(ATTACK_REGISTRY.keys())}\n\n"
            f"以下のJSON形式で3つのシナリオを生成してください:\n"
            f'[\n  {{"name": "...", "description": "...", "attack_type": "<registry_keyの一つ>", "severity": "<critical|high|medium|low>"}}\n]\n'
        )

        result = await self.gemini_client.analyze_with_flash(
            [{"type": "text", "text": prompt}]
        )

        # Parse — fallback to one generic scenario
        import json
        import re

        try:
            reasoning = result.get("reasoning", "")
            json_match = re.search(r"\[.*\]", reasoning, re.DOTALL)
            scenarios_data = json.loads(json_match.group()) if json_match else []
        except Exception:
            scenarios_data = []

        if not scenarios_data:
            scenarios_data = [
                {
                    "name": "AI-Generated Novel Attack",
                    "description": "Gemini 3が生成した新しい攻撃パターン",
                    "attack_type": "xss",
                    "severity": "medium",
                }
            ]

        _sev_map = {"critical": ThreatLevel.CRITICAL, "high": ThreatLevel.HIGH, "medium": ThreatLevel.MEDIUM, "low": ThreatLevel.LOW}

        new_scenarios = []
        for item in scenarios_data[:5]:
            atype = item.get("attack_type", "xss")
            if atype not in ATTACK_REGISTRY:
                atype = "xss"  # fallback
            new_scenarios.append(
                AttackScenario(
                    scenario_id=f"ai-gen-{uuid.uuid4().hex[:8]}",
                    name=item.get("name", "Generated Scenario"),
                    description=item.get("description", ""),
                    attack_type=atype,
                    severity=_sev_map.get(item.get("severity", "medium"), ThreatLevel.MEDIUM),
                    test_cases=[{"attack_type": atype, "target": self.target_endpoint}],
                )
            )

        logger.info("Generated new attack scenarios", count=len(new_scenarios))
        return new_scenarios
