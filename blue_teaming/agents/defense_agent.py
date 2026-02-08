"""Blue Team Defense Agent — real-time threat detection and response.

The defense agent is the public-facing facade for Blue Team operations.
It coordinates detection, response, forensics, and hardening skills
and integrates with the Red Team for Purple Team exercises.

Key methods
-----------
run_detection_scan()   — run all detection skills against a payload
respond_to_incident()  — automated incident response workflow
run_forensic_analysis() — deep forensic investigation
run_all_defenses()     — concurrent execution of all defense skills
"""

import asyncio
import uuid
from datetime import datetime
from typing import Any

from shared.schemas import ThreatLevel
from shared.utils import get_logger
from blue_teaming.skills.base import (
    DefenseResult,
    IncidentContext,
    AlertLevel,
    get_defense_registry,
)

logger = get_logger(__name__)


class BlueTeamAgent:
    """High-level Blue Team agent backed by the DefenseRegistry.

    Provides coordinated defense capabilities including detection,
    response, forensics, and hardening.
    """

    def __init__(self) -> None:
        self.registry = get_defense_registry()
        logger.info("BlueTeamAgent ready", skills=self.registry.names())

    # --- Skill listing (router-facing) ----------------------------------------

    @staticmethod
    def _display_name(skill_name: str) -> str:
        """Convert snake_case skill name to human-readable Title Case."""
        return skill_name.replace("_", " ").title()

    def get_defense_scenarios(self) -> list[dict[str, str]]:
        """Return all registered defense skills as scenario-info dicts."""
        return [
            {
                "scenario_id": s.skill_name,
                "name": s.skill_name,
                "display_name": self._display_name(s.skill_name),
                "description": s.skill_description,
                "category": s.category,
                "alert_level": s.default_alert_level.value,
            }
            for s in self.registry.list_all()
        ]

    # --- Single skill execution ------------------------------------------------

    async def execute_skill(
        self,
        skill_name: str,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        """Run one defense skill."""
        skill_instance = self.registry.get(skill_name)
        if skill_instance is None:
            return DefenseResult(
                skill_name=skill_name,
                threat_detected=False,
                alert_level=AlertLevel.INFO,
                error=f"Unknown skill: {skill_name}. Available: {self.registry.names()}",
            )

        try:
            return await skill_instance.execute(context=context, **kwargs)
        except Exception as e:
            logger.error("Defense skill error", skill=skill_name, error=str(e))
            return DefenseResult(
                skill_name=skill_name,
                threat_detected=False,
                alert_level=AlertLevel.INFO,
                error=str(e),
            )

    # --- Detection scan -------------------------------------------------------

    async def run_detection_scan(self, payload: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run all detection skills against a payload."""
        context = IncidentContext(
            incident_id=str(uuid.uuid4()),
            raw_payload=payload,
            metadata=metadata or {},
        )

        detection_skills = [
            s for s in self.registry.list_all()
            if s.category == "detection"
        ]

        results: list[dict[str, Any]] = []
        threats_found = 0

        for skill in detection_skills:
            try:
                result = await skill.execute(context=context)
                results.append(result.model_dump())
                if result.threat_detected:
                    threats_found += 1
            except Exception as e:
                logger.error("Detection error", skill=skill.skill_name, error=str(e))

        overall_threat = threats_found > 0

        return {
            "scan_id": context.incident_id,
            "timestamp": datetime.utcnow().isoformat(),
            "payload_length": len(payload),
            "skills_executed": len(results),
            "threats_detected": threats_found,
            "overall_threat": overall_threat,
            "results": results,
        }

    # --- Incident response ----------------------------------------------------

    async def respond_to_incident(
        self,
        incident_context: IncidentContext,
    ) -> dict[str, Any]:
        """Full incident response: detection → response → forensics."""
        response_skills = [
            s for s in self.registry.list_all()
            if s.category == "response"
        ]

        results: list[dict[str, Any]] = []
        for skill in response_skills:
            try:
                result = await skill.execute(context=incident_context)
                results.append(result.model_dump())
            except Exception as e:
                logger.error("Response error", skill=skill.skill_name, error=str(e))

        return {
            "incident_id": incident_context.incident_id,
            "timestamp": datetime.utcnow().isoformat(),
            "attack_type": incident_context.attack_type,
            "skills_executed": len(results),
            "results": results,
        }

    # --- Forensic analysis ----------------------------------------------------

    async def run_forensic_analysis(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Run all forensic analysis skills."""
        forensic_skills = [
            s for s in self.registry.list_all()
            if s.category == "forensics"
        ]

        results: list[dict[str, Any]] = []
        for skill in forensic_skills:
            try:
                result = await skill.execute(context=context, **kwargs)
                results.append(result.model_dump())
            except Exception as e:
                logger.error("Forensics error", skill=skill.skill_name, error=str(e))

        return {
            "analysis_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "skills_executed": len(results),
            "results": results,
        }

    # --- Run all defenses concurrently ----------------------------------------

    async def run_all_defenses(
        self,
        payload: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run every registered defense skill concurrently."""
        context = IncidentContext(
            incident_id=str(uuid.uuid4()),
            raw_payload=payload,
            metadata=metadata or {},
        )

        all_skills = self.registry.list_all()
        semaphore = asyncio.Semaphore(10)

        async def _run(skill: Any) -> dict[str, Any]:
            async with semaphore:
                try:
                    result = await skill.execute(context=context)
                    return {
                        "skill_name": skill.skill_name,
                        "category": skill.category,
                        "result": result.model_dump(),
                        "threat_detected": result.threat_detected,
                    }
                except Exception as e:
                    return {
                        "skill_name": skill.skill_name,
                        "category": skill.category,
                        "error": str(e),
                        "threat_detected": False,
                    }

        results = await asyncio.gather(*[_run(s) for s in all_skills])
        threats = sum(1 for r in results if r.get("threat_detected"))

        return {
            "run_id": context.incident_id,
            "timestamp": datetime.utcnow().isoformat(),
            "total_skills": len(results),
            "threats_detected": threats,
            "results": list(results),
        }

    # --- Process Red Team findings (Purple Team integration) ------------------

    async def process_red_team_findings(
        self,
        red_team_report: dict[str, Any],
    ) -> dict[str, Any]:
        """Process Red Team attack results and generate defensive recommendations.

        This is the key integration point for Purple Team exercises.
        Takes Red Team findings and runs appropriate defense skills to
        validate detection capabilities and generate remediation steps.
        """
        findings: list[dict[str, Any]] = []
        attack_results = red_team_report.get("attack_results", [])

        for attack in attack_results:
            if not attack.get("success"):
                continue

            # Build incident context from Red Team finding
            context = IncidentContext(
                incident_id=str(uuid.uuid4()),
                attack_type=attack.get("skill_name", "unknown"),
                threat_level=ThreatLevel(attack.get("severity", "medium")),
                raw_payload="\n".join(attack.get("evidence", [])),
                red_team_report_id=red_team_report.get("report_id", ""),
            )

            # Run detection scan to see if we catch it
            detection_result = await self.run_detection_scan(
                payload=context.raw_payload,
                metadata={"attack_type": context.attack_type},
            )

            findings.append({
                "attack_skill": attack.get("skill_name"),
                "attack_severity": attack.get("severity"),
                "blue_team_detected": detection_result.get("overall_threat", False),
                "detection_details": detection_result,
            })

        total_attacks = len([a for a in attack_results if a.get("success")])
        detected = sum(1 for f in findings if f.get("blue_team_detected"))

        return {
            "purple_team_id": str(uuid.uuid4()),
            "red_team_report_id": red_team_report.get("report_id", ""),
            "timestamp": datetime.utcnow().isoformat(),
            "total_successful_attacks": total_attacks,
            "blue_team_detections": detected,
            "detection_rate": detected / total_attacks if total_attacks > 0 else 1.0,
            "coverage_gap": total_attacks - detected,
            "findings": findings,
        }
