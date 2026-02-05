"""Analysis and monitoring endpoints."""

from typing import Dict, Any, List

from fastapi import APIRouter
from pydantic import BaseModel

from shared.utils import get_logger

logger = get_logger(__name__)
router = APIRouter()


class ThreatStatistics(BaseModel):
    """脅威統計."""

    total_requests: int
    threats_detected: int
    threats_blocked: int
    false_positives: int
    deep_think_activations: int
    average_analysis_time_ms: float


class SystemStatus(BaseModel):
    """システムステータス."""

    status: str
    components: Dict[str, str]
    metrics: ThreatStatistics


@router.get("/statistics", response_model=ThreatStatistics)
async def get_threat_statistics() -> ThreatStatistics:
    """脅威統計の取得."""
    # TODO: 実際のメトリクスをPrometheusまたはFirestoreから取得
    return ThreatStatistics(
        total_requests=0,
        threats_detected=0,
        threats_blocked=0,
        false_positives=0,
        deep_think_activations=0,
        average_analysis_time_ms=0.0,
    )


@router.get("/status", response_model=SystemStatus)
async def get_system_status() -> SystemStatus:
    """システム全体のステータス取得."""
    # TODO: 各コンポーネントのヘルスチェック
    return SystemStatus(
        status="operational",
        components={
            "gatekeeper": "healthy",
            "vertex_ai": "unknown",
            "firestore": "unknown",
            "pubsub": "unknown",
        },
        metrics=ThreatStatistics(
            total_requests=0,
            threats_detected=0,
            threats_blocked=0,
            false_positives=0,
            deep_think_activations=0,
            average_analysis_time_ms=0.0,
        ),
    )


@router.get("/patterns", response_model=List[Dict[str, Any]])
async def get_attack_patterns() -> List[Dict[str, Any]]:
    """検知された攻撃パターンの一覧取得."""
    # TODO: Firestoreから攻撃パターンを取得
    return []


@router.get("/insights", response_model=List[Dict[str, Any]])
async def get_system_insights() -> List[Dict[str, Any]]:
    """Gemini 3が生成したシステムインサイトの取得."""
    # TODO: Firestoreからインサイトを取得
    return []
