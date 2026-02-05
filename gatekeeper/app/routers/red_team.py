"""Red Team API router — static scan, dynamic attack, full pipeline.

Endpoints:
    POST /scan/static        — GitHub repo static security scan
    POST /attack/dynamic     — Playwright-driven live attack against localhost app
    POST /attack/full        — Combined static + dynamic red-team pipeline
    GET  /scenarios          — List all registered attack scenarios
    POST /attack/scenario    — Run a single named scenario
"""

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from shared.utils import get_logger
from intelligence_center.models import GeminiClient
from red_teaming.mcp_server.playwright_mcp import LocalhostGuardError
from red_teaming.agents.attack_agent import RedTeamAgent
from red_teaming.orchestrator.attack_orchestrator import AttackOrchestrator

logger = get_logger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class StaticScanRequest(BaseModel):
    github_url: str = Field(..., description="GitHub repositoryのURL")


class DynamicAttackRequest(BaseModel):
    target_url: str = Field(..., description="攻撃対象のURL (localhost のみ)")


class FullRedTeamRequest(BaseModel):
    target_url: str = Field(..., description="攻撃対象のURL (localhost のみ)")
    github_url: Optional[str] = Field(None, description="静的スキャン用 GitHub URL (省略時はスキップ)")


class SingleScenarioRequest(BaseModel):
    target_url: str = Field(..., description="攻撃対象のURL (localhost のみ)")
    scenario_id: str = Field(..., description="実行するシナリオID (例: xss-001)")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/scan/static")
async def static_scan(request: StaticScanRequest) -> dict:
    """GitHub repositoryの静的セキュリティスキャン.

    既存の static_analyzer パイプラインを Red Team オーケストレータ経由で実行する.
    """
    logger.info("Red Team static scan requested", github_url=request.github_url)

    gemini_client = GeminiClient()
    orchestrator = AttackOrchestrator(gemini_client)

    try:
        result = await orchestrator.run_static_scan(request.github_url)
        return {"status": "completed", "result": result}
    except Exception as e:
        logger.error("Static scan error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attack/dynamic")
async def dynamic_attack(request: DynamicAttackRequest) -> dict:
    """Playwright MCP経由の動的攻撃実行.

    - localhost-only ガード
    - Gemini による攻撃プラン生成
    - 全攻撃タイプの実行
    - 統合レポート返却
    """
    logger.info("Red Team dynamic attack requested", target_url=request.target_url)

    gemini_client = GeminiClient()
    orchestrator = AttackOrchestrator(gemini_client)

    try:
        report = await orchestrator.run_dynamic_attack(request.target_url)
        return {"status": "completed", "report": report.to_dict()}
    except LocalhostGuardError as e:
        logger.warning("Localhost guard blocked attack", reason=str(e))
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error("Dynamic attack error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attack/full")
async def full_red_team(request: FullRedTeamRequest) -> dict:
    """静的スキャン + 動的攻撃の一貫パイプライン.

    github_url が指定されている場合は静的スキャンも実行する.
    """
    logger.info(
        "Full red team pipeline requested",
        target_url=request.target_url,
        github_url=request.github_url,
    )

    gemini_client = GeminiClient()
    orchestrator = AttackOrchestrator(gemini_client)

    try:
        result = await orchestrator.run_full_red_team(
            target_url=request.target_url,
            github_url=request.github_url,
        )
        return {"status": "completed", "result": result}
    except LocalhostGuardError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error("Full red team error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scenarios")
async def list_scenarios(target_url: str = "http://localhost:8000") -> dict:
    """登録されている攻撃シナリオの一覧を返す.

    Query param: target_url (デフォルト: http://localhost:8000)
    """
    try:
        gemini_client = GeminiClient()
        agent = RedTeamAgent(gemini_client, target_endpoint=target_url)
        scenarios = agent.get_attack_scenarios()
        return {
            "scenarios": [
                {
                    "scenario_id": s.scenario_id,
                    "name": s.name,
                    "description": s.description,
                    "attack_type": s.attack_type,
                    "severity": s.severity.value,
                }
                for s in scenarios
            ]
        }
    except LocalhostGuardError as e:
        raise HTTPException(status_code=403, detail=str(e))


@router.post("/attack/scenario")
async def run_single_scenario(request: SingleScenarioRequest) -> dict:
    """単一シナリオの実行.

    scenario_id で指定したシナリオだけを実行して結果を返す.
    """
    logger.info(
        "Single scenario attack requested",
        target_url=request.target_url,
        scenario_id=request.scenario_id,
    )

    gemini_client = GeminiClient()

    try:
        agent = RedTeamAgent(gemini_client, target_endpoint=request.target_url)
    except LocalhostGuardError as e:
        raise HTTPException(status_code=403, detail=str(e))

    # Find the matching scenario
    scenarios = agent.get_attack_scenarios()
    scenario = next((s for s in scenarios if s.scenario_id == request.scenario_id), None)

    if scenario is None:
        raise HTTPException(
            status_code=404,
            detail=f"Scenario '{request.scenario_id}' not found. "
                   f"Available: {[s.scenario_id for s in scenarios]}",
        )

    try:
        result = await agent.execute_scenario(scenario)
        return {"status": "completed", "result": result}
    except Exception as e:
        logger.error("Scenario execution error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
