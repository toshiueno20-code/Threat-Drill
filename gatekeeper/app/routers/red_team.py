"""Red Team API router.

Policy updates:
- Dynamic/full endpoints generate vulnerability check plans only.
- Skill execution is allowed only through explicit per-request user approval.
"""

from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from gatekeeper.config import settings
from intelligence_center.models import GeminiClient
from red_teaming.agents.attack_agent import ExecutionApproval, RedTeamAgent
from red_teaming.mcp_server.sandbox_verifier import SandboxVerificationError
from red_teaming.orchestrator.attack_orchestrator import AttackOrchestrator
from red_teaming.skills import get_registry
from shared.utils import get_logger
from shared.utils.target_allowlist import TargetNotAllowedError, validate_target_url

logger = get_logger(__name__)
router = APIRouter()

_OWASP_WEB_RE = re.compile(r"^owasp_a(\d{2})_(.+)$")
_OWASP_LLM_RE = re.compile(r"^owasp_llm(\d{2})_(.+)$")

# Hackathon demo: show all skills, but only a curated set is executable/planned.
_HACKATHON_EXECUTABLE_SKILLS_ORDERED = [
    "owasp_llm01_prompt_injection",
    "owasp_llm02_sensitive_disclosure",
    "owasp_llm05_improper_output",
    "owasp_llm06_excessive_agency",
    "owasp_llm07_system_prompt_leakage",
]
_HACKATHON_EXECUTABLE_SKILLS = set(_HACKATHON_EXECUTABLE_SKILLS_ORDERED)


def _build_gemini_client() -> GeminiClient:
    """Build Gemini client with API-key-first configuration."""
    return GeminiClient(
        api_key=settings.api_key,
        base_url=settings.gemini_api_base_url,
        flash_model=settings.gemini_flash_model,
        deep_model=settings.gemini_deep_model,
        embedding_model=settings.gemini_embed_model,
        project_id=settings.gcp_project_id,
        location=settings.gcp_location,
    )


def _pretty_name(raw: str) -> str:
    return raw.replace("_", " ").strip().title()


def _derive_skill_meta(skill_name: str, description: str) -> dict[str, str | int]:
    web = _OWASP_WEB_RE.match(skill_name)
    if web:
        idx = int(web.group(1))
        title = description.split(" - ", 1)[-1].strip() if " - " in description else _pretty_name(web.group(2))
        return {
            "display_name": f"OWASP Web A{idx:02d}: {title}",
            "category": "owasp_web",
            "order": idx,
        }

    llm = _OWASP_LLM_RE.match(skill_name)
    if llm:
        idx = int(llm.group(1))
        title = description.split(" - ", 1)[-1].strip() if " - " in description else _pretty_name(llm.group(2))
        return {
            "display_name": f"OWASP LLM{idx:02d}: {title}",
            "category": "owasp_llm",
            "order": idx,
        }

    return {"display_name": _pretty_name(skill_name), "category": "core", "order": 999}


def _skill_sort_key(item: dict) -> tuple[int, int, str]:
    rank = {"owasp_web": 0, "owasp_llm": 1, "core": 2}.get(item.get("category", "core"), 3)
    return (rank, int(item.get("order", 999)), str(item.get("skill_name", "")))


def _require_execution_approval(approval: "ExecutionApprovalRequest") -> ExecutionApproval:
    """Validate approval payload for every execution request."""
    if not approval.approved:
        raise HTTPException(
            status_code=403,
            detail="Skill execution is blocked: explicit user approval is required for each request.",
        )
    if not approval.approved_by.strip():
        raise HTTPException(status_code=400, detail="approved_by is required when approved=true.")

    return ExecutionApproval(
        approved=True,
        approved_by=approval.approved_by.strip(),
        approval_note=approval.approval_note.strip() if approval.approval_note else "",
    )


def _require_browser_automation_approval(
    approval: "ExecutionApprovalRequest",
    *,
    purpose: str,
) -> ExecutionApproval:
    """Validate approval payload for browser automation (Playwright/MCP) per request."""
    if not approval.approved:
        raise HTTPException(
            status_code=403,
            detail=(
                "Browser automation is blocked: explicit user approval is required for each request "
                f"(purpose={purpose})."
            ),
        )
    if not approval.approved_by.strip():
        raise HTTPException(status_code=400, detail="approved_by is required when approved=true.")

    return ExecutionApproval(
        approved=True,
        approved_by=approval.approved_by.strip(),
        approval_note=approval.approval_note.strip() if approval.approval_note else "",
    )


class ExecutionApprovalRequest(BaseModel):
    approved: bool = Field(
        default=False,
        description="Must be true for each skill execution request.",
    )
    approved_by: str = Field(
        default="",
        description="Human approver identity (for audit trace).",
    )
    approval_note: str | None = Field(
        default=None,
        description="Optional human note explaining why execution is permitted.",
    )


class StaticScanRequest(BaseModel):
    github_url: str = Field(..., description="GitHub repository URL")


class DynamicAttackRequest(BaseModel):
    target_url: str = Field(..., description="Target URL (allowlist validated)")
    # Browser automation is optional and requires explicit per-request human approval.
    browser_automation_approval: ExecutionApprovalRequest | None = Field(
        default=None,
        description="Approval payload required to enable Playwright-based browser reconnaissance.",
    )
    mcp_tools_approval: ExecutionApprovalRequest | None = Field(
        default=None,
        description="Approval payload required to allow Gemini to use MCP tools (Playwright MCP).",
    )


class FullRedTeamRequest(BaseModel):
    target_url: str = Field(..., description="Target URL (allowlist validated)")
    github_url: str | None = Field(None, description="Optional GitHub URL for static scan")
    browser_automation_approval: ExecutionApprovalRequest | None = Field(
        default=None,
        description="Approval payload required to enable Playwright-based browser reconnaissance.",
    )
    mcp_tools_approval: ExecutionApprovalRequest | None = Field(
        default=None,
        description="Approval payload required to allow Gemini to use MCP tools (Playwright MCP).",
    )


class SingleSkillRequest(BaseModel):
    target_url: str = Field(..., description="Target URL (allowlist validated)")
    skill_name: str = Field(..., description="Skill name to execute")
    execution_approval: ExecutionApprovalRequest = Field(
        ...,
        description="Explicit per-request human approval payload",
    )


class DynamicChecksExecutionRequest(BaseModel):
    target_url: str = Field(..., description="Target URL (allowlist validated)")
    selected_checks: list[str] | None = Field(
        default=None,
        description="Optional list of read-only checks to execute. Defaults to all registered checks.",
    )
    # Skill execution and browser automation both require explicit per-request approval.
    execution_approval: ExecutionApprovalRequest = Field(
        ...,
        description="Explicit per-request human approval payload for executing checks.",
    )
    browser_automation_approval: ExecutionApprovalRequest = Field(
        ...,
        description="Approval payload required to enable Playwright browser automation for executing checks.",
    )


@router.post("/scan/static")
async def static_scan(request: StaticScanRequest) -> dict:
    """Run static repository security scan."""
    logger.info("Static scan requested", github_url=request.github_url)
    orchestrator = AttackOrchestrator(_build_gemini_client())
    try:
        result = await orchestrator.run_static_scan(request.github_url)
        return {"status": "completed", "result": result}
    except Exception as exc:
        logger.error("Static scan error", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/attack/dynamic")
async def dynamic_attack(request: DynamicAttackRequest) -> dict:
    """Run dynamic recon + vulnerability check planning (no autonomous execution)."""
    try:
        validate_target_url(request.target_url)
    except TargetNotAllowedError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    logger.info("Dynamic assessment requested", target_url=request.target_url)
    orchestrator = AttackOrchestrator(_build_gemini_client())
    try:
        allow_browser_automation = False
        allow_mcp_tools = False
        approved_by: str | None = None

        if request.browser_automation_approval is not None:
            approval = _require_browser_automation_approval(
                request.browser_automation_approval,
                purpose="playwright_recon",
            )
            allow_browser_automation = True
            approved_by = approval.approved_by

        if request.mcp_tools_approval is not None:
            approval = _require_browser_automation_approval(
                request.mcp_tools_approval,
                purpose="mcp_tool_use",
            )
            allow_mcp_tools = True
            approved_by = approved_by or approval.approved_by

        report = await orchestrator.run_dynamic_assessment(
            request.target_url,
            allow_browser_automation=allow_browser_automation,
            allow_mcp_tools=allow_mcp_tools,
            approved_by=approved_by or "",
            allowed_checks=_HACKATHON_EXECUTABLE_SKILLS_ORDERED if settings.hackathon_demo_mode else None,
        )
        return {"status": "completed", "report": report.model_dump()}
    except SandboxVerificationError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        logger.error("Dynamic assessment error", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/attack/full")
async def full_red_team(request: FullRedTeamRequest) -> dict:
    """Run static scan + dynamic vulnerability check planning."""
    try:
        validate_target_url(request.target_url)
    except TargetNotAllowedError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    logger.info("Full assessment requested", target=request.target_url, github=request.github_url)
    orchestrator = AttackOrchestrator(_build_gemini_client())
    try:
        allow_browser_automation = False
        allow_mcp_tools = False
        approved_by: str | None = None

        if request.browser_automation_approval is not None:
            approval = _require_browser_automation_approval(
                request.browser_automation_approval,
                purpose="playwright_recon",
            )
            allow_browser_automation = True
            approved_by = approval.approved_by

        if request.mcp_tools_approval is not None:
            approval = _require_browser_automation_approval(
                request.mcp_tools_approval,
                purpose="mcp_tool_use",
            )
            allow_mcp_tools = True
            approved_by = approved_by or approval.approved_by

        result = await orchestrator.run_full_red_team(
            target_url=request.target_url,
            github_url=request.github_url,
            allow_browser_automation=allow_browser_automation,
            allow_mcp_tools=allow_mcp_tools,
            approved_by=approved_by or "",
            allowed_checks=_HACKATHON_EXECUTABLE_SKILLS_ORDERED if settings.hackathon_demo_mode else None,
        )
        return {"status": "completed", "result": result}
    except SandboxVerificationError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        logger.error("Full assessment error", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/scenarios")
async def list_scenarios() -> dict:
    """List registered read-only security check skills."""
    try:
        registry = get_registry()
        skills_list = registry.list_all()
        scenarios = []

        for skill in skills_list:
            meta = _derive_skill_meta(skill.skill_name, skill.skill_description)
            scenarios.append(
                {
                    "skill_name": skill.skill_name,
                    "display_name": meta["display_name"],
                    "description": skill.skill_description,
                    "severity": skill.default_severity.value,
                    "category": meta["category"],
                    "order": meta["order"],
                }
            )

        scenarios.sort(key=_skill_sort_key)
        return {"scenarios": scenarios}
    except Exception as exc:
        logger.error("Failed to list scenarios", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Failed to load skills: {str(exc)}")


@router.post("/attack/scenario")
async def run_single_skill(request: SingleSkillRequest) -> dict:
    """Execute one approved read-only security check skill."""
    try:
        validate_target_url(request.target_url)
    except TargetNotAllowedError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    approval = _require_execution_approval(request.execution_approval)

    registry = get_registry()
    if request.skill_name not in registry:
        raise HTTPException(
            status_code=404,
            detail=f"Skill '{request.skill_name}' not found. Available: {registry.names()}",
        )

    if settings.hackathon_demo_mode and request.skill_name not in _HACKATHON_EXECUTABLE_SKILLS:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Skill '{request.skill_name}' is marked To be continued for the hackathon demo. "
                "Only the curated GenAI app inspection skills are executable in demo mode."
            ),
        )

    logger.info(
        "Single skill execution approved",
        skill=request.skill_name,
        target=request.target_url,
        approved_by=approval.approved_by,
    )

    try:
        agent = RedTeamAgent(_build_gemini_client(), target_endpoint=request.target_url)
    except SandboxVerificationError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    try:
        result = await agent.execute_skill(request.skill_name, approval=approval)
        return {"status": "completed", "result": result.model_dump()}
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        logger.error("Skill execution error", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/attack/dynamic/checks")
async def execute_dynamic_checks(request: DynamicChecksExecutionRequest) -> dict:
    """Execute approved read-only dynamic checks in a browser session."""
    try:
        validate_target_url(request.target_url)
    except TargetNotAllowedError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    approval = _require_execution_approval(request.execution_approval)
    _require_browser_automation_approval(request.browser_automation_approval, purpose="playwright_dynamic_checks")

    selected_checks = request.selected_checks
    if settings.hackathon_demo_mode:
        # Demo policy: allow executing dynamic checks, but only for curated GenAI app checks.
        if selected_checks:
            filtered = [name for name in selected_checks if name in _HACKATHON_EXECUTABLE_SKILLS]
            selected_checks = filtered or list(_HACKATHON_EXECUTABLE_SKILLS_ORDERED)
        else:
            selected_checks = list(_HACKATHON_EXECUTABLE_SKILLS_ORDERED)

    logger.info(
        "Dynamic checks execution approved",
        target=request.target_url,
        approved_by=approval.approved_by,
        selected_checks=len(selected_checks or []),
    )

    orchestrator = AttackOrchestrator(_build_gemini_client())
    try:
        report = await orchestrator.run_dynamic_checks(
            request.target_url,
            selected_checks=selected_checks,
            allow_browser_automation=True,
            approved_by=approval.approved_by,
        )
        return {"status": "completed", "report": report.model_dump()}
    except SandboxVerificationError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        logger.error("Dynamic checks execution error", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))
