"""Purple Team API router — Red + Blue Team coordination.

The Purple Team router provides integrated exercises that coordinate
Red Team attacks with Blue Team defenses, measuring detection coverage,
response effectiveness, and identifying security gaps.

Endpoints:
    POST /exercise          — Run a full Purple Team exercise
    POST /validate          — Validate Blue Team detection against Red Team findings
    GET  /status            — Get combined Red/Blue team status
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from shared.utils import get_logger
from blue_teaming.agents.defense_agent import BlueTeamAgent
from blue_teaming.orchestrator.defense_orchestrator import DefenseOrchestrator
from blue_teaming.skills.base import IncidentContext, get_defense_registry
from red_teaming.skills import get_registry as get_attack_registry

logger = get_logger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class PurpleTeamExerciseRequest(BaseModel):
    target_url: str = Field(default="http://localhost:8080", description="Red Team攻撃対象URL")
    test_payload: str = Field(default="", description="Blue Teamテスト用ペイロード")
    run_red_team: bool = Field(default=False, description="Red Team攻撃を実行するか")


class ValidationRequest(BaseModel):
    red_team_report: dict = Field(..., description="Red Teamレポート")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/exercise")
async def run_exercise(request: PurpleTeamExerciseRequest) -> dict:
    """Purple Team演習の実行 — Red+Blue協調テスト."""
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

    # Phase 1: Run Red Team attack (if requested and target is available)
    red_team_report = None
    if request.run_red_team:
        try:
            from intelligence_center.models import GeminiClient
            from red_teaming.orchestrator.attack_orchestrator import AttackOrchestrator

            orchestrator = AttackOrchestrator(GeminiClient())
            report = await orchestrator.run_dynamic_attack(request.target_url)
            red_team_report = report.model_dump()
            results["red_team"] = red_team_report
        except Exception as e:
            logger.error("Red Team phase failed", error=str(e))
            results["red_team"] = {"error": str(e)}

    # Phase 2: Run Blue Team defense
    try:
        defense_orchestrator = DefenseOrchestrator()
        defense_report = await defense_orchestrator.run_full_defense(
            payload=request.test_payload,
        )
        results["blue_team"] = defense_report.model_dump()
    except Exception as e:
        logger.error("Blue Team phase failed", error=str(e))
        results["blue_team"] = {"error": str(e)}

    # Phase 3: Cross-validate (if Red Team ran)
    if red_team_report:
        try:
            agent = BlueTeamAgent()
            integration = await agent.process_red_team_findings(red_team_report)
            results["integration"] = integration
        except Exception as e:
            logger.error("Integration phase failed", error=str(e))
            results["integration"] = {"error": str(e)}

    results["finished_at"] = datetime.utcnow().isoformat()

    # Calculate overall score
    red_score = red_team_report.get("overall_score", 100) if red_team_report else None
    blue_score = results["blue_team"].get("posture", {}).get("defense_score", 100) if isinstance(results["blue_team"], dict) else None
    detection_rate = results.get("integration", {}).get("detection_rate") if results.get("integration") else None

    results["summary"] = {
        "red_team_score": red_score,
        "blue_team_score": blue_score,
        "detection_rate": detection_rate,
        "exercise_status": "completed",
    }

    logger.info("Purple Team exercise complete", exercise_id=exercise_id)
    return {"status": "completed", "result": results}


@router.post("/validate")
async def validate_detection(request: ValidationRequest) -> dict:
    """Blue Teamの検出能力をRed Team結果で検証."""
    logger.info("Purple Team validation requested")
    try:
        agent = BlueTeamAgent()
        result = await agent.process_red_team_findings(request.red_team_report)
        return {"status": "completed", "result": result}
    except Exception as e:
        logger.error("Validation error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_combined_status() -> dict:
    """Red Team + Blue Teamの統合ステータス."""
    try:
        attack_registry = get_attack_registry()
        defense_registry = get_defense_registry()

        attack_skills = attack_registry.list_all()
        defense_skills = defense_registry.list_all()

        # Categorize defense skills
        defense_categories: dict[str, int] = {}
        for s in defense_skills:
            cat = getattr(s, "category", "general")
            defense_categories[cat] = defense_categories.get(cat, 0) + 1

        # Categorize attack skills by severity
        attack_severities: dict[str, int] = {}
        for s in attack_skills:
            sev = s.default_severity.value
            attack_severities[sev] = attack_severities.get(sev, 0) + 1

        return {
            "status": "operational",
            "red_team": {
                "total_skills": len(attack_skills),
                "skills_by_severity": attack_severities,
                "skills": [s.skill_name for s in attack_skills],
            },
            "blue_team": {
                "total_skills": len(defense_skills),
                "skills_by_category": defense_categories,
                "skills": [s.skill_name for s in defense_skills],
            },
            "coverage": {
                "attack_vectors": len(attack_skills),
                "defense_capabilities": len(defense_skills),
                "ratio": round(len(defense_skills) / max(len(attack_skills), 1), 2),
            },
        }
    except Exception as e:
        logger.error("Status check error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
