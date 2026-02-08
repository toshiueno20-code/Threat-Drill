"""Blue Team API router — detection, response, forensics, hardening.

Endpoints:
    GET  /scenarios          — List all registered defense skills
    POST /scan/detect        — Run detection scan against payload
    POST /respond/incident   — Automated incident response
    POST /analyze/forensics  — Forensic analysis
    POST /defense/full       — Full defense pipeline
    POST /defense/skill      — Run a single defense skill
    GET  /posture            — Get current defense posture
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from shared.utils import get_logger
from blue_teaming.agents.defense_agent import BlueTeamAgent
from blue_teaming.orchestrator.defense_orchestrator import DefenseOrchestrator
from blue_teaming.skills.base import IncidentContext, get_defense_registry

logger = get_logger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class DetectionScanRequest(BaseModel):
    payload: str = Field(..., description="検査対象のペイロード")
    metadata: dict | None = Field(None, description="追加メタデータ")


class IncidentResponseRequest(BaseModel):
    incident_id: str = Field(default="", description="インシデントID")
    attack_type: str = Field(default="unknown", description="攻撃タイプ")
    threat_level: str = Field(default="medium", description="脅威レベル")
    source_ip: str = Field(default="", description="攻撃元IP")
    raw_payload: str = Field(default="", description="攻撃ペイロード")


class ForensicAnalysisRequest(BaseModel):
    log_data: str = Field(default="", description="分析対象のログデータ")
    incident_id: str = Field(default="", description="関連インシデントID")


class FullDefenseRequest(BaseModel):
    payload: str = Field(default="", description="検査対象のペイロード")
    metadata: dict | None = Field(None, description="追加メタデータ")


class SingleSkillRequest(BaseModel):
    skill_name: str = Field(..., description="実行する防御スキル名")
    payload: str = Field(default="", description="検査対象のペイロード")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/scenarios")
async def list_defense_scenarios() -> dict:
    """登録されている全防御スキルの一覧を返す."""
    try:
        agent = BlueTeamAgent()
        scenarios = agent.get_defense_scenarios()
        return {"scenarios": scenarios}
    except Exception as e:
        logger.error("Failed to list defense scenarios", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/detect")
async def detection_scan(request: DetectionScanRequest) -> dict:
    """検出スキャンの実行 — ペイロードに対する全検出スキルの実行."""
    logger.info("Detection scan requested", payload_length=len(request.payload))
    try:
        agent = BlueTeamAgent()
        result = await agent.run_detection_scan(
            payload=request.payload,
            metadata=request.metadata,
        )
        return {"status": "completed", "result": result}
    except Exception as e:
        logger.error("Detection scan error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/respond/incident")
async def incident_response(request: IncidentResponseRequest) -> dict:
    """インシデントレスポンスの自動実行."""
    logger.info("Incident response requested", attack_type=request.attack_type)
    try:
        context = IncidentContext(
            incident_id=request.incident_id,
            attack_type=request.attack_type,
            threat_level=request.threat_level,
            source_ip=request.source_ip,
            raw_payload=request.raw_payload,
        )
        agent = BlueTeamAgent()
        result = await agent.respond_to_incident(context)
        return {"status": "completed", "result": result}
    except Exception as e:
        logger.error("Incident response error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/forensics")
async def forensic_analysis(request: ForensicAnalysisRequest) -> dict:
    """フォレンジック分析の実行."""
    logger.info("Forensic analysis requested")
    try:
        context = IncidentContext(
            incident_id=request.incident_id,
            raw_payload=request.log_data,
        )
        agent = BlueTeamAgent()
        result = await agent.run_forensic_analysis(
            context=context,
            log_data=request.log_data,
        )
        return {"status": "completed", "result": result}
    except Exception as e:
        logger.error("Forensic analysis error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/defense/full")
async def full_defense(request: FullDefenseRequest) -> dict:
    """全防御パイプラインの実行 (検出→対応→分析→強化→レポート)."""
    logger.info("Full defense pipeline requested")
    try:
        orchestrator = DefenseOrchestrator()
        report = await orchestrator.run_full_defense(
            payload=request.payload,
            metadata=request.metadata,
        )
        return {"status": "completed", "report": report.model_dump()}
    except Exception as e:
        logger.error("Full defense error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/defense/skill")
async def run_single_skill(request: SingleSkillRequest) -> dict:
    """単一防御スキルの実行."""
    logger.info("Single defense skill requested", skill=request.skill_name)

    registry = get_defense_registry()
    if request.skill_name not in registry:
        raise HTTPException(
            status_code=404,
            detail=f"Skill '{request.skill_name}' not found. Available: {registry.names()}",
        )

    try:
        agent = BlueTeamAgent()
        context = IncidentContext(raw_payload=request.payload)
        result = await agent.execute_skill(
            skill_name=request.skill_name,
            context=context,
        )
        return {"status": "completed", "result": result.model_dump()}
    except Exception as e:
        logger.error("Defense skill error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/posture")
async def get_posture() -> dict:
    """現在の防御ポスチャー (体制) の取得."""
    try:
        orchestrator = DefenseOrchestrator()
        posture = await orchestrator.get_defense_posture()
        return {"status": "ok", "posture": posture.model_dump()}
    except Exception as e:
        logger.error("Posture check error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
