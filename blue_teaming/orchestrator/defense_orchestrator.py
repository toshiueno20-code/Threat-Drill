"""Defense Orchestrator — NIST-aligned Blue Team pipeline with weighted scoring.

Architecture (NIST SP 800-61 lifecycle)
---------------------------------------
1. [Preparation]     Hardening skills validate configuration.
2. [Detection]       Detection skills scan for active threats.
3. [Containment]     Response skills contain identified threats.
4. [Eradication]     Threat artifacts removed.
5. [Recovery]        Normal operations restored.
6. [Post-Incident]   Forensic analysis and lessons learned.

Enhanced with:
- Weighted defense score (detection 35%, response 25%, forensics 15%, hardening 25%)
- CVSS-aggregated severity assessment
- Cross-skill finding correlation
- MITRE ATT&CK coverage summary
"""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from shared.utils import get_logger
from blue_teaming.skills.base import (
    AlertLevel,
    DefenseResult,
    IncidentContext,
    NISTIRPhase,
    MITRETechnique,
    get_defense_registry,
)

logger = get_logger(__name__)

# Category weights for defense score calculation
CATEGORY_WEIGHTS = {
    "detection": 0.35,
    "response": 0.25,
    "forensics": 0.15,
    "hardening": 0.25,
}


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
    max_cvss_score: float = 0.0
    max_cvss_severity: str = "None"
    mitre_techniques_detected: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class BlueTeamReport(BaseModel):
    """Full Blue Team defense report with NIST alignment."""

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    finished_at: str | None = None
    posture: DefensePosture = Field(default_factory=DefensePosture)
    detection_results: list[DefenseResult] = Field(default_factory=list)
    response_results: list[DefenseResult] = Field(default_factory=list)
    forensic_results: list[DefenseResult] = Field(default_factory=list)
    hardening_results: list[DefenseResult] = Field(default_factory=list)
    correlated_findings: list[str] = Field(default_factory=list)
    summary: str = ""

    def calculate_score(self) -> float:
        """Weighted defense score with CVSS aggregation and MITRE tracking."""
        category_results = {
            "detection": self.detection_results,
            "response": self.response_results,
            "forensics": self.forensic_results,
            "hardening": self.hardening_results,
        }

        all_results = sum(category_results.values(), [])
        if not all_results:
            self.posture.defense_score = 100.0
            return 100.0

        threats = sum(1 for r in all_results if r.threat_detected)
        blocked = sum(1 for r in all_results if r.blocked)
        mitigated = sum(1 for r in all_results if r.mitigated)

        self.posture.active_threats = threats
        self.posture.threats_blocked = blocked
        self.posture.threats_mitigated = mitigated

        # Weighted score per category
        weighted_score = 0.0
        for cat, results in category_results.items():
            weight = CATEGORY_WEIGHTS.get(cat, 0.25)
            if not results:
                weighted_score += weight * 100.0
                continue
            cat_threats = sum(1 for r in results if r.threat_detected)
            cat_handled = sum(1 for r in results if r.blocked or r.mitigated)
            cat_score = (cat_handled / cat_threats * 100) if cat_threats > 0 else 100.0
            weighted_score += weight * min(cat_score, 100.0)

        # CVSS aggregation — track highest severity
        max_cvss = 0.0
        all_mitre: set[str] = set()
        for r in all_results:
            if r.cvss_score > max_cvss:
                max_cvss = r.cvss_score
            for tech in r.mitre_techniques:
                all_mitre.add(tech.technique_id)

        self.posture.max_cvss_score = max_cvss
        if max_cvss >= 9.0:
            self.posture.max_cvss_severity = "Critical"
        elif max_cvss >= 7.0:
            self.posture.max_cvss_severity = "High"
        elif max_cvss >= 4.0:
            self.posture.max_cvss_severity = "Medium"
        elif max_cvss > 0:
            self.posture.max_cvss_severity = "Low"
        else:
            self.posture.max_cvss_severity = "None"

        self.posture.mitre_techniques_detected = sorted(all_mitre)

        # Cross-skill correlation
        self.correlated_findings = _correlate_findings(all_results)

        self.posture.defense_score = round(weighted_score, 1)
        return self.posture.defense_score


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
        """NIST-aligned defense: detect -> respond -> analyze -> harden -> report."""
        report = BlueTeamReport()

        if incident_context is None:
            incident_context = IncidentContext(
                incident_id=str(uuid.uuid4()),
                raw_payload=payload,
                metadata=metadata or {},
            )

        all_skills = self.registry.list_all()

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

        # Phase 1: Detection (NIST: Detection & Analysis)
        logger.info("Defense phase: Detection", skills=len(categories["detection"]))
        for skill in categories["detection"]:
            try:
                result = await skill.execute(context=incident_context)
                report.detection_results.append(result)
            except Exception as e:
                logger.error("Detection error", skill=skill.skill_name, error=str(e))

        # Phase 2: Response (NIST: Containment + Eradication)
        threats_detected = any(r.threat_detected for r in report.detection_results)
        if threats_detected:
            logger.info("Defense phase: Response", skills=len(categories["response"]))
            for skill in categories["response"]:
                try:
                    result = await skill.execute(context=incident_context)
                    report.response_results.append(result)
                except Exception as e:
                    logger.error("Response error", skill=skill.skill_name, error=str(e))

        # Phase 3: Forensics (NIST: Post-Incident Activity)
        logger.info("Defense phase: Forensics", skills=len(categories["forensics"]))
        for skill in categories["forensics"]:
            try:
                result = await skill.execute(context=incident_context)
                report.forensic_results.append(result)
            except Exception as e:
                logger.error("Forensics error", skill=skill.skill_name, error=str(e))

        # Phase 4: Hardening (NIST: Preparation)
        logger.info("Defense phase: Hardening", skills=len(categories["hardening"]))
        for skill in categories["hardening"]:
            try:
                result = await skill.execute(context=incident_context)
                report.hardening_results.append(result)
            except Exception as e:
                logger.error("Hardening error", skill=skill.skill_name, error=str(e))

        report.calculate_score()
        report.finished_at = datetime.utcnow().isoformat()
        report.summary = _build_defense_summary(report)

        logger.info(
            "Defense pipeline complete",
            report_id=report.report_id,
            score=report.posture.defense_score,
            max_cvss=report.posture.max_cvss_score,
            mitre_count=len(report.posture.mitre_techniques_detected),
        )
        return report

    async def get_defense_posture(self) -> DefensePosture:
        """Quick posture assessment without running full pipeline."""
        all_skills = self.registry.list_all()
        categories: dict[str, int] = {}
        mitre_coverage: set[str] = set()
        for s in all_skills:
            cat = getattr(s, "category", "general")
            categories[cat] = categories.get(cat, 0) + 1
            for tid in getattr(s, "mitre_techniques", []):
                mitre_coverage.add(tid)

        return DefensePosture(
            total_skills=len(all_skills),
            skills_by_category=categories,
            mitre_techniques_detected=sorted(mitre_coverage),
        )


def _correlate_findings(results: list[DefenseResult]) -> list[str]:
    """Cross-skill finding correlation — identify compound threats."""
    correlations: list[str] = []
    finding_types: set[str] = set()

    for r in results:
        if not r.threat_detected:
            continue
        for f in r.findings:
            fl = f.lower()
            if "injection" in fl:
                finding_types.add("injection")
            if "exfiltration" in fl or "credential" in fl or "key" in fl:
                finding_types.add("exfiltration")
            if "jailbreak" in fl or "dan" in fl:
                finding_types.add("jailbreak")
            if "rate" in fl or "dos" in fl:
                finding_types.add("dos")

    if "injection" in finding_types and "exfiltration" in finding_types:
        correlations.append(
            "[CORRELATED] Injection + Data Exfiltration detected — "
            "possible multi-stage attack: inject to extract sensitive data"
        )
    if "jailbreak" in finding_types and "injection" in finding_types:
        correlations.append(
            "[CORRELATED] Jailbreak + Injection detected — "
            "combined bypass attempt to override safety controls"
        )
    if "dos" in finding_types and "injection" in finding_types:
        correlations.append(
            "[CORRELATED] DoS + Injection detected — "
            "possible distraction attack (DoS as cover for injection)"
        )

    return correlations


def _build_defense_summary(report: BlueTeamReport) -> str:
    all_results = (
        report.detection_results
        + report.response_results
        + report.forensic_results
        + report.hardening_results
    )
    total = len(all_results)
    threats = sum(1 for r in all_results if r.threat_detected)
    blocked = sum(1 for r in all_results if r.blocked)

    lines = [
        f"Blue Team Report — {report.report_id}",
        f"Defense Score: {report.posture.defense_score}/100 "
        f"(weighted: detection 35%, response 25%, forensics 15%, hardening 25%)",
        f"Max CVSS: {report.posture.max_cvss_score} ({report.posture.max_cvss_severity})",
        f"Skills: {total}  |  Threats: {threats}  |  Blocked: {blocked}",
        f"MITRE Techniques: {', '.join(report.posture.mitre_techniques_detected) or 'None'}",
        "",
        f"  Detection:  {len(report.detection_results)} skills",
        f"  Response:   {len(report.response_results)} skills",
        f"  Forensics:  {len(report.forensic_results)} skills",
        f"  Hardening:  {len(report.hardening_results)} skills",
        "",
    ]

    for r in all_results:
        tag = "THREAT" if r.threat_detected else "CLEAR "
        mitre_ids = ", ".join(t.technique_id for t in r.mitre_techniques) if r.mitre_techniques else "—"
        lines.append(
            f"  [{tag}] {r.skill_name:<30} {r.alert_level.value:<10} "
            f"CVSS:{r.cvss_score:<5} MITRE:{mitre_ids}"
        )

    if report.correlated_findings:
        lines.append("")
        lines.append("Correlated Findings:")
        for cf in report.correlated_findings:
            lines.append(f"  {cf}")

    return "\n".join(lines)
