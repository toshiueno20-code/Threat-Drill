"""Defense Orchestrator — coordinated Blue Team defense pipeline.

Architecture
------------
1. [Monitor]  Continuous monitoring and real-time threat detection.
2. [Detect]   Run detection skills against incoming data.
3. [Respond]  Automated incident response when threats are found.
4. [Analyze]  Forensic analysis and attack chain reconstruction.
5. [Harden]   Apply security hardening and policy updates.
6. [Report]   Generate defense posture report.
"""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from shared.schemas import ThreatLevel
from shared.utils import get_logger
from blue_teaming.skills.base import (
    AlertLevel,
    DefenseResult,
    IncidentContext,
    get_defense_registry,
)

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Report models
# ---------------------------------------------------------------------------


class DefensePosture(BaseModel):
    """Overall defense posture assessment."""

    posture_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    total_skills: int = 0
    skills_by_category: dict[str, int] = Field(default_factory=dict)
    active_threats: int = 0
    threats_blocked: int = 0
    threats_mitigated: int = 0
    defense_score: float = 100.0
    recommendations: list[str] = Field(default_factory=list)


class BlueTeamReport(BaseModel):
    """Full Blue Team defense report."""

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    finished_at: str | None = None
    posture: DefensePosture = Field(default_factory=DefensePosture)
    detection_results: list[DefenseResult] = Field(default_factory=list)
    response_results: list[DefenseResult] = Field(default_factory=list)
    forensic_results: list[DefenseResult] = Field(default_factory=list)
    hardening_results: list[DefenseResult] = Field(default_factory=list)
    summary: str = ""

    def calculate_score(self) -> float:
        """Calculate defense score from 0-100 based on skill effectiveness."""
        all_results = (
            self.detection_results
            + self.response_results
            + self.forensic_results
            + self.hardening_results
        )
        if not all_results:
            self.posture.defense_score = 100.0
            return 100.0

        threats = sum(1 for r in all_results if r.threat_detected)
        blocked = sum(1 for r in all_results if r.blocked)
        mitigated = sum(1 for r in all_results if r.mitigated)

        self.posture.active_threats = threats
        self.posture.threats_blocked = blocked
        self.posture.threats_mitigated = mitigated

        if threats == 0:
            score = 100.0
        else:
            handled = blocked + mitigated
            score = min(100.0, (handled / threats) * 100) if threats > 0 else 100.0

        self.posture.defense_score = round(score, 1)
        return self.posture.defense_score


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class DefenseOrchestrator:
    """Orchestrates the full Blue Team defense pipeline."""

    def __init__(self) -> None:
        self.registry = get_defense_registry()

    async def run_full_defense(
        self,
        payload: str = "",
        metadata: dict[str, Any] | None = None,
        incident_context: IncidentContext | None = None,
    ) -> BlueTeamReport:
        """Full defense pipeline: detect → respond → analyze → harden → report."""
        report = BlueTeamReport()

        if incident_context is None:
            incident_context = IncidentContext(
                incident_id=str(uuid.uuid4()),
                raw_payload=payload,
                metadata=metadata or {},
            )

        all_skills = self.registry.list_all()

        # Categorize skills
        categories: dict[str, list] = {
            "detection": [],
            "response": [],
            "forensics": [],
            "hardening": [],
        }
        for s in all_skills:
            cat = getattr(s, "category", "general")
            if cat in categories:
                categories[cat].append(s)

        report.posture.total_skills = len(all_skills)
        report.posture.skills_by_category = {k: len(v) for k, v in categories.items()}

        # Phase 1: Detection
        logger.info("Defense phase: Detection", skills=len(categories["detection"]))
        for skill in categories["detection"]:
            try:
                result = await skill.execute(context=incident_context)
                report.detection_results.append(result)
            except Exception as e:
                logger.error("Detection skill error", skill=skill.skill_name, error=str(e))

        # Phase 2: Response (if threats detected)
        threats_detected = any(r.threat_detected for r in report.detection_results)
        if threats_detected:
            logger.info("Defense phase: Response", skills=len(categories["response"]))
            for skill in categories["response"]:
                try:
                    result = await skill.execute(context=incident_context)
                    report.response_results.append(result)
                except Exception as e:
                    logger.error("Response skill error", skill=skill.skill_name, error=str(e))

        # Phase 3: Forensics
        logger.info("Defense phase: Forensics", skills=len(categories["forensics"]))
        for skill in categories["forensics"]:
            try:
                result = await skill.execute(context=incident_context)
                report.forensic_results.append(result)
            except Exception as e:
                logger.error("Forensics skill error", skill=skill.skill_name, error=str(e))

        # Phase 4: Hardening
        logger.info("Defense phase: Hardening", skills=len(categories["hardening"]))
        for skill in categories["hardening"]:
            try:
                result = await skill.execute(context=incident_context)
                report.hardening_results.append(result)
            except Exception as e:
                logger.error("Hardening skill error", skill=skill.skill_name, error=str(e))

        # Calculate score and summary
        report.calculate_score()
        report.finished_at = datetime.utcnow().isoformat()
        report.summary = _build_defense_summary(report)

        logger.info(
            "Defense pipeline complete",
            report_id=report.report_id,
            score=report.posture.defense_score,
        )
        return report

    async def get_defense_posture(self) -> DefensePosture:
        """Quick posture assessment without running full pipeline."""
        all_skills = self.registry.list_all()
        categories: dict[str, int] = {}
        for s in all_skills:
            cat = getattr(s, "category", "general")
            categories[cat] = categories.get(cat, 0) + 1

        return DefensePosture(
            total_skills=len(all_skills),
            skills_by_category=categories,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_defense_summary(report: BlueTeamReport) -> str:
    total = (
        len(report.detection_results)
        + len(report.response_results)
        + len(report.forensic_results)
        + len(report.hardening_results)
    )
    all_results = (
        report.detection_results
        + report.response_results
        + report.forensic_results
        + report.hardening_results
    )
    threats = sum(1 for r in all_results if r.threat_detected)
    blocked = sum(1 for r in all_results if r.blocked)

    lines = [
        f"Blue Team Report — {report.report_id}",
        f"Defense Score: {report.posture.defense_score}/100",
        f"Skills Executed: {total}  |  Threats: {threats}  |  Blocked: {blocked}",
        "",
        f"  Detection:  {len(report.detection_results)} skills",
        f"  Response:   {len(report.response_results)} skills",
        f"  Forensics:  {len(report.forensic_results)} skills",
        f"  Hardening:  {len(report.hardening_results)} skills",
        "",
    ]
    for r in all_results:
        tag = "THREAT" if r.threat_detected else "CLEAR "
        lines.append(f"  [{tag}] {r.skill_name:<30} {r.alert_level.value:<10} {len(r.findings)} findings")

    return "\n".join(lines)
