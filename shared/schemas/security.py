"""Security-related schemas for threat detection and analysis."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class ThreatLevel(str, Enum):
    """脅威レベルの定義."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ModalityType(str, Enum):
    """マルチモーダル入力のタイプ."""

    TEXT = "text"
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    CODE = "code"
    TOOL_EXECUTION = "tool_execution"


class MultimodalInput(BaseModel):
    """マルチモーダル入力データ."""

    modality: ModalityType
    content: str | bytes = Field(description="コンテンツ（テキストまたはバイナリ）")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    @field_validator("content", mode="before")
    @classmethod
    def validate_content(cls, v: Any) -> str | bytes:
        """コンテンツのバリデーション."""
        if isinstance(v, (str, bytes)):
            return v
        raise ValueError("Content must be string or bytes")


class ThreatAnalysisResult(BaseModel):
    """脅威分析結果."""

    threat_level: ThreatLevel
    confidence: float = Field(ge=0.0, le=1.0, description="信頼度スコア")
    reasoning: str = Field(description="判定理由（Gemini 3の思考プロセス）")
    detected_patterns: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    deep_think_used: bool = Field(default=False, description="Deep Thinkモードを使用したか")
    analysis_duration_ms: float = Field(description="分析にかかった時間（ミリ秒）")
    model_version: str = Field(description="使用したGeminiモデルバージョン")
    context_window_tokens: int = Field(default=0, description="分析に使用したコンテキストトークン数")


class SecurityEvent(BaseModel):
    """セキュリティイベント."""

    event_id: str = Field(description="イベント一意識別子")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    inputs: List[MultimodalInput]
    threat_analysis: ThreatAnalysisResult
    blocked: bool = Field(default=False, description="リクエストがブロックされたか")
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    context_history: List[Dict[str, Any]] = Field(
        default_factory=list, description="過去のコンテキスト履歴"
    )


class RBACPermission(BaseModel):
    """ロールベースアクセス制御の権限."""

    resource: str = Field(description="リソース名")
    actions: List[str] = Field(description="許可されたアクション")
    conditions: Dict[str, Any] = Field(default_factory=dict, description="条件式")


class PolicyRule(BaseModel):
    """セキュリティポリシールール."""

    rule_id: str
    name: str
    description: str
    pattern: str = Field(description="検知パターン（正規表現またはベクトル類似度閾値）")
    threat_level: ThreatLevel
    action: str = Field(description="block, warn, log など")
    enabled: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    auto_generated: bool = Field(default=False, description="自動生成されたルールか")
    confidence_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    vector_embedding: Optional[List[float]] = None
