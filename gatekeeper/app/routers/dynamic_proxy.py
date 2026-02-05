"""Dynamic Proxy endpoints for real-time AI monitoring."""

from typing import List, Dict, Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from dynamic_proxy.interceptor.realtime_proxy import (
    RealtimeAIProxy,
    UserContext,
    AgentAction,
    ProxyAction,
)
from shared.schemas import MultimodalInput
from intelligence_center.models import GeminiClient
from gatekeeper.config import settings
from shared.utils import get_logger

logger = get_logger(__name__)
router = APIRouter()


class InterceptInputRequest(BaseModel):
    """ユーザー入力インターセプトリクエスト."""

    inputs: List[MultimodalInput]
    user_id: str
    session_id: str
    permission_level: str = "user"
    conversation_history: List[Dict[str, Any]] = []
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


class InterceptActionRequest(BaseModel):
    """アクションインターセプトリクエスト."""

    action_id: str
    action_type: str
    tool_name: str
    arguments: Dict[str, Any]
    target_resource: str
    requires_permission: str
    user_id: str
    session_id: str
    permission_level: str = "user"
    conversation_history: List[Dict[str, Any]] = []


class InterceptOutputRequest(BaseModel):
    """出力インターセプトリクエスト."""

    output_text: str
    user_id: str
    session_id: str
    permission_level: str = "user"


class InterceptResponse(BaseModel):
    """インターセプトレスポンス."""

    decision: ProxyAction
    threat_level: str
    reasoning: str
    confidence: float
    redacted_content: Optional[str] = None
    alert_sent: bool
    processing_time_ms: float


# プロキシインスタンスの初期化（グローバル）
_proxy_instance: Optional[RealtimeAIProxy] = None


def get_proxy_instance() -> RealtimeAIProxy:
    """プロキシインスタンスの取得（シングルトン）."""
    global _proxy_instance

    if _proxy_instance is None:
        gemini_client = GeminiClient(
            project_id=settings.gcp_project_id,
            location=settings.gcp_location,
        )
        _proxy_instance = RealtimeAIProxy(
            gemini_client=gemini_client,
            enable_deep_think=settings.enable_deep_think,
        )

    return _proxy_instance


@router.post("/intercept/input", response_model=InterceptResponse)
async def intercept_user_input(request: InterceptInputRequest) -> InterceptResponse:
    """
    ユーザー入力をインターセプト.

    リアルタイムでユーザーの入力（テキスト、画像、音声など）を分析し、
    脅威を検知します。Gemini 3 Flashで高速スキャンし、疑わしい場合は
    Deep Thinkモードで詳細分析を実施します。
    """
    logger.info(
        "User input interception requested",
        user_id=request.user_id,
        session_id=request.session_id,
        input_count=len(request.inputs),
    )

    try:
        proxy = get_proxy_instance()

        user_context = UserContext(
            user_id=request.user_id,
            session_id=request.session_id,
            permission_level=request.permission_level,
            conversation_history=request.conversation_history,
            ip_address=request.ip_address,
            user_agent=request.user_agent,
        )

        result = await proxy.intercept_user_input(
            inputs=request.inputs,
            user_context=user_context,
        )

        return InterceptResponse(
            decision=result.decision,
            threat_level=result.threat_level.value,
            reasoning=result.reasoning,
            confidence=result.confidence,
            redacted_content=result.redacted_content,
            alert_sent=result.alert_sent,
            processing_time_ms=result.processing_time_ms,
        )

    except Exception as e:
        logger.error(
            "User input interception failed",
            user_id=request.user_id,
            error=str(e),
        )
        raise HTTPException(status_code=500, detail=f"Interception failed: {str(e)}")


@router.post("/intercept/action", response_model=InterceptResponse)
async def intercept_agent_action(request: InterceptActionRequest) -> InterceptResponse:
    """
    AIエージェントのアクション実行前にインターセプト.

    AIが実行しようとしているアクション（SQL、API呼び出し、ファイル操作など）を
    検証し、権限チェックとセキュリティ検証を実施します。
    """
    logger.info(
        "Agent action interception requested",
        user_id=request.user_id,
        action_type=request.action_type,
        tool_name=request.tool_name,
    )

    try:
        proxy = get_proxy_instance()

        user_context = UserContext(
            user_id=request.user_id,
            session_id=request.session_id,
            permission_level=request.permission_level,
            conversation_history=request.conversation_history,
        )

        action = AgentAction(
            action_id=request.action_id,
            action_type=request.action_type,
            tool_name=request.tool_name,
            arguments=request.arguments,
            target_resource=request.target_resource,
            requires_permission=request.requires_permission,
        )

        result = await proxy.intercept_agent_action(
            action=action,
            user_context=user_context,
        )

        return InterceptResponse(
            decision=result.decision,
            threat_level=result.threat_level.value,
            reasoning=result.reasoning,
            confidence=result.confidence,
            redacted_content=result.redacted_content,
            alert_sent=result.alert_sent,
            processing_time_ms=result.processing_time_ms,
        )

    except Exception as e:
        logger.error(
            "Agent action interception failed",
            user_id=request.user_id,
            error=str(e),
        )
        raise HTTPException(status_code=500, detail=f"Interception failed: {str(e)}")


@router.post("/intercept/output", response_model=InterceptResponse)
async def intercept_agent_output(request: InterceptOutputRequest) -> InterceptResponse:
    """
    AIエージェントの出力をインターセプト（機密情報のREDACT）.

    AIが生成した出力に機密情報（メールアドレス、SSN、APIキーなど）が
    含まれていないかをチェックし、含まれている場合は伏せ字（REDACT）にします。
    """
    logger.info(
        "Agent output interception requested",
        user_id=request.user_id,
        output_length=len(request.output_text),
    )

    try:
        proxy = get_proxy_instance()

        user_context = UserContext(
            user_id=request.user_id,
            session_id=request.session_id,
            permission_level=request.permission_level,
            conversation_history=[],
        )

        result = await proxy.intercept_agent_output(
            output_text=request.output_text,
            user_context=user_context,
        )

        return InterceptResponse(
            decision=result.decision,
            threat_level=result.threat_level.value,
            reasoning=result.reasoning,
            confidence=result.confidence,
            redacted_content=result.redacted_content,
            alert_sent=result.alert_sent,
            processing_time_ms=result.processing_time_ms,
        )

    except Exception as e:
        logger.error(
            "Agent output interception failed",
            user_id=request.user_id,
            error=str(e),
        )
        raise HTTPException(status_code=500, detail=f"Interception failed: {str(e)}")


@router.get("/health")
async def dynamic_proxy_health() -> dict:
    """Dynamic Proxyモジュールのヘルスチェック."""
    return {"status": "healthy", "module": "dynamic_proxy"}
