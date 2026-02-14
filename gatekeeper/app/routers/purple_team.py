"""Purple Team API router for Red + Blue coordination."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from blue_teaming.agents.defense_agent import BlueTeamAgent
from blue_teaming.orchestrator.defense_orchestrator import DefenseOrchestrator
from blue_teaming.skills.base import MITRE_TECHNIQUE_DB, get_defense_registry
from gatekeeper.config import settings
from intelligence_center.models import GeminiClient
from red_teaming.orchestrator.attack_orchestrator import AttackOrchestrator
from red_teaming.skills import get_registry as get_attack_registry
from shared.utils import get_logger
from shared.utils.target_allowlist import TargetNotAllowedError, validate_target_url

logger = get_logger(__name__)
router = APIRouter()

# Hackathon demo: show all skills, but only plan for a curated set (same as Red Team demo mode).
_HACKATHON_EXECUTABLE_SKILLS_ORDERED = [
    "owasp_llm01_prompt_injection",
    "owasp_llm02_sensitive_disclosure",
    "owasp_llm05_improper_output",
    "owasp_llm06_excessive_agency",
    "owasp_llm07_system_prompt_leakage",
]


class PurpleTeamExerciseRequest(BaseModel):
    target_url: str = Field(default="http://localhost:8080", description="Red Team target URL")
    test_payload: str = Field(default="", description="Blue Team test payload")
    run_red_team: bool = Field(default=False, description="Include Red Team planning phase")
    # Optional: if provided and approved, execute read-only dynamic checks after planning.
    execution_approval: dict | None = Field(
        default=None,
        description="Optional approval payload to execute read-only Red Team checks during the exercise.",
    )
    browser_automation_approval: dict | None = Field(
        default=None,
        description="Optional approval payload to allow Playwright browser automation for executing Red Team checks.",
    )


class ValidationRequest(BaseModel):
    red_team_report: dict = Field(..., description="Red Team report to validate")


def _build_gemini_client() -> GeminiClient:
    return GeminiClient(
        api_key=settings.api_key,
        base_url=settings.gemini_api_base_url,
        flash_model=settings.gemini_flash_model,
        deep_model=settings.gemini_deep_model,
        embedding_model=settings.gemini_embed_model,
        project_id=settings.gcp_project_id,
        location=settings.gcp_location,
    )


@router.post("/exercise")
async def run_exercise(request: PurpleTeamExerciseRequest) -> dict:
    """Run a Purple Team exercise with optional Red Team planning and Blue Team defense."""
    if request.run_red_team:
        try:
            validate_target_url(request.target_url)
        except TargetNotAllowedError as exc:
            raise HTTPException(status_code=403, detail=str(exc))

    logger.info("Purple Team exercise started", target=request.target_url)

    exercise_id = str(uuid.uuid4())
    results: dict = {
        "exercise_id": exercise_id,
        "started_at": datetime.utcnow().isoformat(),
        "target_url": request.target_url,
        "red_team": None,
        "blue_team": None,
        "integration": None,
    }

    red_team_report = None
    if request.run_red_team:
        try:
            orchestrator = AttackOrchestrator(_build_gemini_client())
            plan_report = await orchestrator.run_dynamic_assessment(
                request.target_url,
                allowed_checks=_HACKATHON_EXECUTABLE_SKILLS_ORDERED if settings.hackathon_demo_mode else None,
            )

            # If explicit approvals are present, execute the planned checks (read-only) in the same exercise.
            approved = False
            approved_by = ""
            try:
                ap = request.execution_approval or {}
                approved = bool(ap.get("approved"))
                approved_by = str(ap.get("approved_by") or "").strip()
            except Exception:
                approved = False
                approved_by = ""

            browser_ok = False
            try:
                bp = request.browser_automation_approval or {}
                browser_ok = bool(bp.get("approved")) and str(bp.get("approved_by") or "").strip()
            except Exception:
                browser_ok = False

            if approved and approved_by and browser_ok:
                plan = plan_report.vulnerability_check_plan or plan_report.attack_plan
                planned_order = list(getattr(plan, "priority_order", []) or [])
                # Safety: if plan is missing, fall back to curated demo list when in hackathon mode.
                if not planned_order and settings.hackathon_demo_mode:
                    planned_order = list(_HACKATHON_EXECUTABLE_SKILLS_ORDERED)

                exec_report = await orchestrator.run_dynamic_checks(
                    request.target_url,
                    selected_checks=planned_order or None,
                    allow_browser_automation=True,
                    approved_by=approved_by,
                )
                # Attach the plan to the execution report so UI can show planned vs executed.
                exec_report.vulnerability_check_plan = plan
                exec_report.sync_legacy_fields()
                red_team_report = exec_report.model_dump()
            else:
                red_team_report = plan_report.model_dump()

            results["red_team"] = red_team_report
        except Exception as exc:
            logger.error("Red Team phase failed", error=str(exc))
            results["red_team"] = {"error": str(exc)}

    try:
        defense_orchestrator = DefenseOrchestrator()
        defense_report = await defense_orchestrator.run_full_defense(payload=request.test_payload)
        results["blue_team"] = defense_report.model_dump()
    except Exception as exc:
        logger.error("Blue Team phase failed", error=str(exc))
        results["blue_team"] = {"error": str(exc)}

    if red_team_report:
        try:
            agent = BlueTeamAgent()
            integration = await agent.process_red_team_findings(red_team_report)
            results["integration"] = integration
        except Exception as exc:
            logger.error("Integration phase failed", error=str(exc))
            results["integration"] = {"error": str(exc)}

    results["finished_at"] = datetime.utcnow().isoformat()

    # Red Team dynamic phase is plan-only by policy; score may be null unless checks were executed.
    red_score = red_team_report.get("overall_score") if red_team_report else None
    blue_score = (
        results["blue_team"].get("posture", {}).get("defense_score", 100)
        if isinstance(results["blue_team"], dict)
        else None
    )
    detection_rate = results.get("integration", {}).get("detection_rate") if results.get("integration") else None

    results["summary"] = {
        "red_team_score": red_score,
        "blue_team_score": blue_score,
        "detection_rate": detection_rate,
        "exercise_status": "completed",
    }

    logger.info("Purple Team exercise completed", exercise_id=exercise_id)
    return {"status": "completed", "result": results}


@router.post("/validate")
async def validate_detection(request: ValidationRequest) -> dict:
    """Validate Blue Team detections against a Red Team report."""
    logger.info("Purple Team validation requested")
    try:
        agent = BlueTeamAgent()
        result = await agent.process_red_team_findings(request.red_team_report)
        return {"status": "completed", "result": result}
    except Exception as exc:
        logger.error("Validation error", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/status")
async def get_combined_status() -> dict:
    """Get current Red/Blue operational status and skill coverage."""
    try:
        attack_registry = get_attack_registry()
        defense_registry = get_defense_registry()

        attack_skills = attack_registry.list_all()
        defense_skills = defense_registry.list_all()

        defense_categories: dict[str, int] = {}
        defense_mitre: set[str] = set()
        for skill in defense_skills:
            category = getattr(skill, "category", "general")
            defense_categories[category] = defense_categories.get(category, 0) + 1
            for technique_id in getattr(skill, "mitre_techniques", []):
                defense_mitre.add(technique_id)

        attack_severities: dict[str, int] = {}
        for skill in attack_skills:
            severity = skill.default_severity.value
            attack_severities[severity] = attack_severities.get(severity, 0) + 1

        return {
            "status": "operational",
            "red_team": {
                "total_skills": len(attack_skills),
                "skills_by_severity": attack_severities,
                "skills": [skill.skill_name for skill in attack_skills],
            },
            "blue_team": {
                "total_skills": len(defense_skills),
                "skills_by_category": defense_categories,
                "skills": [skill.skill_name for skill in defense_skills],
                "mitre_coverage": sorted(defense_mitre),
            },
            "coverage": {
                "attack_vectors": len(attack_skills),
                "defense_capabilities": len(defense_skills),
                "ratio": round(len(defense_skills) / max(len(attack_skills), 1), 2),
                "mitre_techniques_covered": len(defense_mitre),
            },
        }
    except Exception as exc:
        logger.error("Status check error", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/mitre-coverage")
async def get_mitre_coverage() -> dict:
    """Return MITRE ATT&CK technique coverage by defense skills."""
    try:
        defense_registry = get_defense_registry()
        defense_skills = defense_registry.list_all()

        coverage: dict[str, dict] = {}
        for skill in defense_skills:
            for technique_id in getattr(skill, "mitre_techniques", []):
                if technique_id not in coverage:
                    technique_info = MITRE_TECHNIQUE_DB.get(technique_id, {})
                    coverage[technique_id] = {
                        "technique_id": technique_id,
                        "technique_name": technique_info.get("technique_name", "Unknown"),
                        "tactic": technique_info.get("tactic", "unknown"),
                        "url": technique_info.get("url", ""),
                        "covered_by": [],
                    }

                coverage[technique_id]["covered_by"].append(
                    {
                        "skill_name": skill.skill_name,
                        "category": skill.category,
                    }
                )

        all_known = set(MITRE_TECHNIQUE_DB.keys())
        covered = set(coverage.keys())
        gaps = all_known - covered

        gap_details = []
        for technique_id in sorted(gaps):
            technique_info = MITRE_TECHNIQUE_DB[technique_id]
            gap_details.append(
                {
                    "technique_id": technique_id,
                    "technique_name": technique_info.get("technique_name", "Unknown"),
                    "tactic": technique_info.get("tactic", "unknown"),
                    "recommendation": f"Add defense skill for {technique_info.get('technique_name', technique_id)}",
                }
            )

        return {
            "status": "ok",
            "total_techniques_known": len(all_known),
            "total_techniques_covered": len(covered),
            "coverage_percentage": round(len(covered) / max(len(all_known), 1) * 100, 1),
            "covered_techniques": list(coverage.values()),
            "coverage_gaps": gap_details,
        }
    except Exception as exc:
        logger.error("MITRE coverage error", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))
