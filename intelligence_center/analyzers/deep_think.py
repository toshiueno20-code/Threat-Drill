"""Deep Think Analyzer using Gemini 3 Pro for complex threat analysis."""

from typing import List, Dict, Any, Optional

from shared.schemas import (
    MultimodalInput,
    ThreatAnalysisResult,
    ThreatLevel,
)
from shared.utils import get_logger
from ..models import GeminiClient

logger = get_logger(__name__)


class DeepThinkAnalyzer:
    """Gemini 3 Pro Deep Thinkモードによる深層脅威分析."""

    def __init__(self, gemini_client: GeminiClient):
        """
        Deep Think Analyzerの初期化.

        Args:
            gemini_client: Gemini クライアント
        """
        self.gemini_client = gemini_client
        self.system_instruction = self._build_system_instruction()

    def _build_system_instruction(self) -> str:
        """システム命令の構築."""
        return """
あなたはAegisFlow AIの深層分析エンジンです。
Gemini 3 Pro Deep Thinkモードの高度な推論能力を活用し、複雑な脅威を検出してください。

重要事項:
- 初期分析で疑わしいと判定された入力の精密分析を実施
- False Positive（誤検知）の排除を重視
- Multi-step Attack（複数リクエストにわたる攻撃）の検出
- 攻撃者の真の意図を推論
- 思考プロセスを明確に記録

分析観点:
1. コンテキスト分析: 過去の会話履歴から意図を推測
2. パターンマッチング: 既知の攻撃パターンとの照合
3. 異常検知: 通常とは異なる振る舞いの特定
4. 意図推論: 攻撃者が何を達成しようとしているか
5. False Positive評価: 誤検知の可能性を評価

出力フォーマット:
- 最終的な脅威レベル判定
- 詳細な理由と根拠
- 思考プロセスの段階的記録
- 推奨される対応アクション
"""

    async def analyze(
        self,
        inputs: List[MultimodalInput],
        initial_analysis: ThreatAnalysisResult,
        context_history: Optional[List[Dict[str, Any]]] = None,
    ) -> ThreatAnalysisResult:
        """
        Deep Think深層分析.

        Args:
            inputs: マルチモーダル入力
            initial_analysis: Primary Filterの初期分析結果
            context_history: コンテキスト履歴

        Returns:
            詳細な脅威分析結果
        """
        logger.info(
            "Deep Think analysis started",
            initial_threat_level=initial_analysis.threat_level,
            initial_confidence=initial_analysis.confidence,
        )

        # 初期分析結果を辞書に変換
        initial_dict = {
            "threat_level": initial_analysis.threat_level.value,
            "confidence": initial_analysis.confidence,
            "reasoning": initial_analysis.reasoning,
            "detected_patterns": initial_analysis.detected_patterns,
        }

        # Gemini Pro Deep Think で分析
        analysis = await self.gemini_client.deep_think_analysis(
            inputs=inputs,
            initial_analysis=initial_dict,
            system_instruction=self.system_instruction,
            context_history=context_history,
        )

        # 結果のパース
        threat_level = self._parse_threat_level(analysis.get("threat_level", "safe"))
        confidence = float(analysis.get("confidence", 0.5))
        reasoning = analysis.get("reasoning", "")
        thought_process = analysis.get("thought_process", [])
        detected_patterns = analysis.get("detected_patterns", [])
        recommended_actions = analysis.get("recommended_actions", [])

        # 思考プロセスを推論に追加
        if thought_process:
            reasoning += "\n\nThought Process:\n" + "\n".join(thought_process)

        result = ThreatAnalysisResult(
            threat_level=threat_level,
            confidence=confidence,
            reasoning=reasoning,
            detected_patterns=detected_patterns,
            recommended_actions=recommended_actions,
            deep_think_used=True,
            analysis_duration_ms=analysis.get("analysis_duration_ms", 0.0),
            model_version=analysis.get("model_version", "gemini-3-pro-deep-think"),
            context_window_tokens=analysis.get("tokens_used", 0),
        )

        # 初期分析との比較ログ
        if threat_level != initial_analysis.threat_level:
            logger.warning(
                "Deep Think changed threat level",
                initial_level=initial_analysis.threat_level,
                final_level=threat_level,
                confidence_improvement=confidence - initial_analysis.confidence,
            )

        logger.info(
            "Deep Think analysis completed",
            threat_level=threat_level,
            confidence=confidence,
            thought_steps=len(thought_process),
        )

        return result

    def _parse_threat_level(self, level_str: str) -> ThreatLevel:
        """文字列から ThreatLevel enum への変換."""
        level_map = {
            "safe": ThreatLevel.SAFE,
            "low": ThreatLevel.LOW,
            "medium": ThreatLevel.MEDIUM,
            "high": ThreatLevel.HIGH,
            "critical": ThreatLevel.CRITICAL,
        }
        return level_map.get(level_str.lower(), ThreatLevel.MEDIUM)


    async def evaluate_false_positive(
        self,
        security_event: Dict[str, Any],
        feedback: str,
    ) -> Dict[str, Any]:
        """
        False Positive（誤検知）の評価.

        Args:
            security_event: セキュリティイベント
            feedback: フィードバック情報

        Returns:
            評価結果と改善提案
        """
        logger.info(
            "False positive evaluation started",
            event_id=security_event.get("event_id"),
        )

        # TODO: Gemini 3 Proで誤検知の原因分析と改善提案を生成

        evaluation = {
            "is_false_positive": True,
            "root_cause": "Pattern matching too aggressive",
            "improvement_suggestions": [
                "Adjust confidence threshold",
                "Add exception pattern for this use case",
            ],
            "policy_update_required": True,
        }

        return evaluation
