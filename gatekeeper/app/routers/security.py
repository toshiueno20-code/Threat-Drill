"""Security analysis endpoints."""

import uuid
from datetime import datetime
from typing import List

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from shared.schemas import (
    MultimodalInput,
    ThreatAnalysisResult,
    SecurityEvent,
    ThreatLevel,
)
from shared.utils import get_logger

logger = get_logger(__name__)
router = APIRouter()


class SecurityAnalysisRequest(BaseModel):
    """セキュリティ分析リクエスト."""

    inputs: List[MultimodalInput]
    user_id: str | None = None
    session_id: str | None = None
    context_history: List[dict] = []
    source_ip: str | None = None
    user_agent: str | None = None


class SecurityAnalysisResponse(BaseModel):
    """セキュリティ分析レスポンス."""

    event_id: str
    threat_analysis: ThreatAnalysisResult
    blocked: bool
    timestamp: datetime
    message: str


@router.post("/analyze", response_model=SecurityAnalysisResponse)
async def analyze_security(
    request: SecurityAnalysisRequest,
    background_tasks: BackgroundTasks,
) -> SecurityAnalysisResponse:
    """
    マルチモーダル入力のセキュリティ分析.

    Gemini 3 Flashで高速スキャンし、疑わしい場合はDeep Thinkモードを起動。
    """
    event_id = str(uuid.uuid4())

    logger.info(
        "Security analysis started",
        event_id=event_id,
        user_id=request.user_id,
        input_count=len(request.inputs),
    )

    try:
        # TODO: 実際のGemini 3統合（次のステップで実装）
        # 現在はモックレスポンスを返す
        threat_analysis = ThreatAnalysisResult(
            threat_level=ThreatLevel.SAFE,
            confidence=0.95,
            reasoning="初期実装: 実際のGemini 3分析は次のステップで統合します",
            detected_patterns=[],
            recommended_actions=[],
            deep_think_used=False,
            analysis_duration_ms=50.0,
            model_version="gemini-3-flash-mock",
            context_window_tokens=1000,
        )

        blocked = threat_analysis.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]

        # セキュリティイベントの記録（バックグラウンド）
        background_tasks.add_task(
            _store_security_event,
            event_id,
            request,
            threat_analysis,
            blocked,
        )

        return SecurityAnalysisResponse(
            event_id=event_id,
            threat_analysis=threat_analysis,
            blocked=blocked,
            timestamp=datetime.utcnow(),
            message="Analysis completed successfully" if not blocked else "Threat detected and blocked",
        )

    except Exception as e:
        logger.error(
            "Security analysis failed",
            event_id=event_id,
            error=str(e),
        )
        raise HTTPException(status_code=500, detail="Security analysis failed")


async def _store_security_event(
    event_id: str,
    request: SecurityAnalysisRequest,
    threat_analysis: ThreatAnalysisResult,
    blocked: bool,
) -> None:
    """セキュリティイベントの保存（非同期）."""
    try:
        security_event = SecurityEvent(
            event_id=event_id,
            timestamp=datetime.utcnow(),
            user_id=request.user_id,
            session_id=request.session_id,
            inputs=request.inputs,
            threat_analysis=threat_analysis,
            blocked=blocked,
            source_ip=request.source_ip,
            user_agent=request.user_agent,
            context_history=request.context_history,
        )

        # TODO: Firestoreへの保存とPub/Subへのパブリッシュ
        logger.info(
            "Security event stored",
            event_id=event_id,
            threat_level=threat_analysis.threat_level,
        )

    except Exception as e:
        logger.error(
            "Failed to store security event",
            event_id=event_id,
            error=str(e),
        )


@router.get("/events/{event_id}", response_model=SecurityEvent)
async def get_security_event(event_id: str) -> SecurityEvent:
    """セキュリティイベントの取得."""
    # TODO: Firestoreから取得
    raise HTTPException(status_code=404, detail="Event not found")


@router.get("/health")
async def security_health() -> dict[str, str]:
    """セキュリティモジュールのヘルスチェック."""
    return {"status": "healthy", "module": "security"}
