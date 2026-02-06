"""Red Team API router — static scan, dynamic attack, full pipeline.

Endpoints:
    POST /scan/static        — GitHub repo static security scan
    POST /attack/dynamic     — Playwright-driven live attack against localhost app
    POST /attack/full        — Combined static + dynamic red-team pipeline
    GET  /scenarios          — List all registered attack skills
    POST /attack/scenario    — Run a single skill by name
"""

import re

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from shared.utils import get_logger
from intelligence_center.models import GeminiClient
from red_teaming.mcp_server.sandbox_verifier import SandboxVerificationError
from red_teaming.skills import get_registry
from red_teaming.agents.attack_agent import RedTeamAgent
from red_teaming.orchestrator.attack_orchestrator import AttackOrchestrator

logger = get_logger(__name__)

router = APIRouter()


_OWASP_WEB_RE = re.compile(r"^owasp_a(\d{2})_(.+)$")
_OWASP_LLM_RE = re.compile(r"^owasp_llm(\d{2})_(.+)$")


def _pretty_name(raw: str) -> str:
    return raw.replace("_", " ").strip().title()


def _derive_skill_meta(skill_name: str, description: str) -> dict[str, str | int]:
    web = _OWASP_WEB_RE.match(skill_name)
    if web:
        idx = int(web.group(1))
        title = description.split(" - ", 1)[-1].strip() if " - " in description else _pretty_name(web.group(2))
        return {"display_name": f"OWASP Web A{idx:02d}: {title}", "category": "owasp_web", "order": idx}

    llm = _OWASP_LLM_RE.match(skill_name)
    if llm:
        idx = int(llm.group(1))
        title = description.split(" - ", 1)[-1].strip() if " - " in description else _pretty_name(llm.group(2))
        return {"display_name": f"OWASP LLM{idx:02d}: {title}", "category": "owasp_llm", "order": idx}

    return {"display_name": _pretty_name(skill_name), "category": "core", "order": 999}


def _skill_sort_key(item: dict) -> tuple[int, int, str]:
    rank = {"owasp_web": 0, "owasp_llm": 1, "core": 2}.get(item.get("category", "core"), 3)
    return (rank, int(item.get("order", 999)), str(item.get("skill_name", "")))


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class StaticScanRequest(BaseModel):
    github_url: str = Field(..., description="GitHub repositoryのURL")


class DynamicAttackRequest(BaseModel):
    target_url: str = Field(..., description="攻撃対象のURL (localhost または検証済みサンドボックス)")


class FullRedTeamRequest(BaseModel):
    target_url: str = Field(..., description="攻撃対象のURL (localhost または検証済みサンドボックス)")
    github_url: str | None = Field(None, description="静的スキャン用 GitHub URL (省略時はスキップ)")


class SingleSkillRequest(BaseModel):
    target_url: str = Field(..., description="攻撃対象のURL (localhost または検証済みサンドボックス)")
    skill_name: str = Field(..., description="実行するスキル名 (例: xss, sql_injection)")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/scan/static")
async def static_scan(request: StaticScanRequest) -> dict:
    """GitHub repositoryの静的セキュリティスキャン."""
    logger.info("Static scan requested", github_url=request.github_url)
    orchestrator = AttackOrchestrator(GeminiClient())
    try:
        result = await orchestrator.run_static_scan(request.github_url)
        return {"status": "completed", "result": result}
    except Exception as e:
        logger.error("Static scan error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attack/dynamic")
async def dynamic_attack(request: DynamicAttackRequest) -> dict:
    """Playwright MCP経由の動的攻撃実行 (recon → Gemini plan → 全スキル → レポート)."""
    logger.info("Dynamic attack requested", target_url=request.target_url)
    orchestrator = AttackOrchestrator(GeminiClient())
    try:
        report = await orchestrator.run_dynamic_attack(request.target_url)
        return {"status": "completed", "report": report.model_dump()}
    except SandboxVerificationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error("Dynamic attack error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attack/full")
async def full_red_team(request: FullRedTeamRequest) -> dict:
    """静的スキャン + 動的攻撃の一貫パイプライン."""
    logger.info("Full pipeline requested", target=request.target_url, github=request.github_url)
    orchestrator = AttackOrchestrator(GeminiClient())
    try:
        result = await orchestrator.run_full_red_team(
            target_url=request.target_url,
            github_url=request.github_url,
        )
        return {"status": "completed", "result": result}
    except SandboxVerificationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error("Full red team error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scenarios")
async def list_scenarios() -> dict:
    """登録されている全攻撃スキルの一覧を返す."""
    try:
        registry = get_registry()
        skills_list = registry.list_all()
        logger.info(f"Found {len(skills_list)} skills in registry")
        scenarios = []
        for s in skills_list:
            meta = _derive_skill_meta(s.skill_name, s.skill_description)
            scenarios.append(
                {
                    "skill_name": s.skill_name,
                    "display_name": meta["display_name"],
                    "description": s.skill_description,
                    "severity": s.default_severity.value,
                    "category": meta["category"],
                    "order": meta["order"],
                }
            )
        scenarios.sort(key=_skill_sort_key)
        return {
            "scenarios": scenarios
        }
    except Exception as e:
        logger.error("Failed to list scenarios", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to load skills: {str(e)}")


@router.post("/attack/scenario")
async def run_single_skill(request: SingleSkillRequest) -> dict:
    """単一スキルの実行.

    skill_name で指定したスキルだけを実行して結果を返す.
    """
    logger.info("Single skill requested", skill=request.skill_name, target=request.target_url)

    registry = get_registry()
    if request.skill_name not in registry:
        raise HTTPException(
            status_code=404,
            detail=f"Skill '{request.skill_name}' not found. Available: {registry.names()}",
        )

    try:
        agent = RedTeamAgent(GeminiClient(), target_endpoint=request.target_url)
    except SandboxVerificationError as e:
        raise HTTPException(status_code=403, detail=str(e))

    try:
        result = await agent.execute_skill(request.skill_name)
        return {"status": "completed", "result": result.model_dump()}
    except Exception as e:
        logger.error("Skill execution error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
