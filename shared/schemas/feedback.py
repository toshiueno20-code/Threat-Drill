"""Feedback loop schemas for self-correction."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .security import PolicyRule, ThreatLevel


class AttackPattern(BaseModel):
    """検知された攻撃パターン."""

    pattern_id: str
    name: str
    description: str
    attack_vector: str
    detection_count: int = Field(default=1)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    severity: ThreatLevel
    mitigation_strategy: str
    vector_embedding: List[float] = Field(description="パターンのベクトル表現")
    related_cve: List[str] = Field(default_factory=list)
    successful_blocks: int = Field(default=0)
    false_positives: int = Field(default=0)


class FeedbackEvent(BaseModel):
    """フィードバックイベント."""

    event_id: str
    original_security_event_id: str
    feedback_type: str = Field(description="false_positive, true_positive, missed_threat など")
    analyst_notes: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PolicyUpdate(BaseModel):
    """ポリシー更新イベント."""

    update_id: str
    update_type: str = Field(description="create, modify, delete, auto_tune")
    affected_rules: List[str] = Field(description="影響を受けるルールID")
    new_rules: List[PolicyRule] = Field(default_factory=list)
    modified_rules: List[PolicyRule] = Field(default_factory=list)
    deleted_rule_ids: List[str] = Field(default_factory=list)
    reason: str = Field(description="更新理由（Gemini 3の分析結果）")
    auto_approved: bool = Field(default=False)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    rollback_available: bool = Field(default=True)
    performance_impact: Optional[Dict[str, float]] = None


class SystemInsightUpdate(BaseModel):
    """システムインサイト更新（Gemini 3の学習結果）."""

    insight_id: str
    category: str = Field(description="attack_trend, vulnerability, performance_optimization など")
    summary: str
    detailed_analysis: str = Field(description="Gemini 3の詳細分析")
    recommended_actions: List[str]
    confidence: float = Field(ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    data_sources: List[str] = Field(description="分析に使用したデータソース")
