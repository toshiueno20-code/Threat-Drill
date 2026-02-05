"""Self-Correction Policy Engine powered by Gemini 3."""

import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

from shared.schemas import (
    PolicyRule,
    SecurityEvent,
    PolicyUpdate,
    ThreatLevel,
    AttackPattern,
)
from shared.utils import get_logger
from intelligence_center.models import GeminiClient

logger = get_logger(__name__)


class SelfCorrectionEngine:
    """Gemini 3を活用した自己修正ポリシーエンジン."""

    def __init__(self, gemini_client: GeminiClient):
        """
        SelfCorrectionEngineの初期化.

        Args:
            gemini_client: Gemini クライアント
        """
        self.gemini_client = gemini_client
        self.system_instruction = self._build_system_instruction()

    def _build_system_instruction(self) -> str:
        """システム命令の構築."""
        return """
あなたはAegisFlow AIの自己修正エンジンです。
セキュリティイベントとフィードバックを分析し、防御ポリシーを自動的に改善してください。

重要事項:
- False Positive（誤検知）を減らす
- False Negative（見逃し）を防ぐ
- 新しい攻撃パターンに対応する
- 既存のポリシーとの整合性を保つ
- セキュリティと利便性のバランスを取る

分析観点:
1. なぜこの攻撃が検知できたか/できなかったか
2. 既存のポリシーに何が不足しているか
3. どのようなルールを追加/修正すべきか
4. False Positiveを引き起こしている過剰なルールはないか
5. 新しいルールのリスクと効果

出力:
- 推奨されるポリシー変更
- 変更の理由と根拠
- 期待される効果
- 潜在的なリスク
"""

    async def analyze_security_event(
        self,
        event: SecurityEvent,
        existing_policies: List[PolicyRule],
    ) -> Dict[str, Any]:
        """
        セキュリティイベントを分析し、ポリシー改善案を生成.

        Args:
            event: セキュリティイベント
            existing_policies: 既存のポリシールール

        Returns:
            分析結果とポリシー改善案
        """
        logger.info(
            "Analyzing security event for policy improvement",
            event_id=event.event_id,
            threat_level=event.threat_analysis.threat_level,
        )

        # TODO: Gemini 3 Proで分析
        # 現在はモック実装
        analysis = {
            "root_cause": "Attack pattern not covered by existing policies",
            "recommended_changes": [
                {
                    "action": "create",
                    "rule": {
                        "rule_id": str(uuid.uuid4()),
                        "name": f"Auto-generated rule for {event.event_id}",
                        "description": "Automatically generated based on detected threat",
                        "pattern": "example_pattern",
                        "threat_level": event.threat_analysis.threat_level.value,
                        "action": "block",
                        "auto_generated": True,
                        "confidence_threshold": 0.8,
                    },
                }
            ],
            "expected_impact": {
                "false_positive_risk": 0.1,
                "coverage_improvement": 0.3,
            },
        }

        return analysis

    async def handle_false_positive(
        self,
        event: SecurityEvent,
        existing_policies: List[PolicyRule],
        feedback_notes: Optional[str] = None,
    ) -> PolicyUpdate:
        """
        False Positive（誤検知）の処理とポリシー調整.

        Args:
            event: セキュリティイベント
            existing_policies: 既存のポリシールール
            feedback_notes: フィードバックメモ

        Returns:
            ポリシー更新情報
        """
        logger.info(
            "Handling false positive",
            event_id=event.event_id,
        )

        # TODO: Gemini 3で誤検知の原因を分析
        # 1. どのポリシーがトリガーされたか
        # 2. なぜ誤検知したか
        # 3. ポリシーをどう調整すべきか

        # モック実装: 信頼度閾値を上げる
        modified_rules: List[PolicyRule] = []
        for policy in existing_policies:
            if policy.threat_level == event.threat_analysis.threat_level:
                # 信頼度閾値を上げる
                policy.confidence_threshold = min(0.95, policy.confidence_threshold + 0.05)
                modified_rules.append(policy)

        update = PolicyUpdate(
            update_id=str(uuid.uuid4()),
            update_type="auto_tune",
            affected_rules=[p.rule_id for p in modified_rules],
            new_rules=[],
            modified_rules=modified_rules,
            deleted_rule_ids=[],
            reason=f"Adjusting policy due to false positive in event {event.event_id}. {feedback_notes or ''}",
            auto_approved=False,  # 誤検知対応は慎重に
            timestamp=datetime.utcnow(),
        )

        logger.info(
            "False positive handling completed",
            update_id=update.update_id,
            modified_rules_count=len(modified_rules),
        )

        return update

    async def handle_missed_threat(
        self,
        threat_description: str,
        attack_vector: str,
        existing_policies: List[PolicyRule],
    ) -> PolicyUpdate:
        """
        Missed Threat（見逃した脅威）の処理と新規ポリシー生成.

        Args:
            threat_description: 脅威の説明
            attack_vector: 攻撃ベクトル
            existing_policies: 既存のポリシールール

        Returns:
            ポリシー更新情報
        """
        logger.info(
            "Handling missed threat",
            threat_description=threat_description,
        )

        # TODO: Gemini 3で新しい検知パターンを生成
        # 1. 見逃された脅威のパターンを分析
        # 2. 既存のポリシーに不足している部分を特定
        # 3. 新しいポリシールールを生成
        # 4. ベクトル埋め込みを生成

        # モック実装: 新規ポリシー作成
        new_rule = PolicyRule(
            rule_id=str(uuid.uuid4()),
            name=f"Auto-generated: {threat_description[:50]}",
            description=f"Generated to detect missed threat: {threat_description}",
            pattern=attack_vector,
            threat_level=ThreatLevel.HIGH,
            action="block",
            enabled=True,
            auto_generated=True,
            confidence_threshold=0.75,
        )

        update = PolicyUpdate(
            update_id=str(uuid.uuid4()),
            update_type="create",
            affected_rules=[new_rule.rule_id],
            new_rules=[new_rule],
            modified_rules=[],
            deleted_rule_ids=[],
            reason=f"New policy created for missed threat: {threat_description}",
            auto_approved=False,  # 新規ポリシーは人間の承認が必要
            timestamp=datetime.utcnow(),
        )

        logger.info(
            "Missed threat handling completed",
            update_id=update.update_id,
            new_rule_id=new_rule.rule_id,
        )

        return update

    async def optimize_policies(
        self,
        policies: List[PolicyRule],
        performance_metrics: Dict[str, Any],
    ) -> PolicyUpdate:
        """
        既存ポリシーの最適化.

        Args:
            policies: 既存のポリシールール
            performance_metrics: パフォーマンスメトリクス

        Returns:
            ポリシー更新情報
        """
        logger.info(
            "Optimizing policies",
            total_policies=len(policies),
        )

        # TODO: Gemini 3でポリシーを最適化
        # 1. 使用されていないポリシーを特定
        # 2. 重複するポリシーを統合
        # 3. パフォーマンスへの影響を分析
        # 4. 最適化案を生成

        # モック実装: 無効なポリシーの削除
        deleted_ids = [
            p.rule_id
            for p in policies
            if not p.enabled or p.confidence_threshold > 0.99
        ]

        update = PolicyUpdate(
            update_id=str(uuid.uuid4()),
            update_type="auto_tune",
            affected_rules=deleted_ids,
            new_rules=[],
            modified_rules=[],
            deleted_rule_ids=deleted_ids,
            reason="Optimizing policies: removing unused or overly restrictive rules",
            auto_approved=True,  # 最適化は自動承認
            timestamp=datetime.utcnow(),
            performance_impact=performance_metrics,
        )

        logger.info(
            "Policy optimization completed",
            update_id=update.update_id,
            deleted_count=len(deleted_ids),
        )

        return update

    async def learn_from_attack_patterns(
        self,
        patterns: List[AttackPattern],
        existing_policies: List[PolicyRule],
    ) -> PolicyUpdate:
        """
        攻撃パターンから学習し、ポリシーを更新.

        Args:
            patterns: 検知された攻撃パターン
            existing_policies: 既存のポリシールール

        Returns:
            ポリシー更新情報
        """
        logger.info(
            "Learning from attack patterns",
            pattern_count=len(patterns),
        )

        # TODO: Gemini 3で攻撃パターンを分析
        # 1. パターン間の共通点を見つける
        # 2. トレンドを分析
        # 3. 予防的なポリシーを生成

        new_rules: List[PolicyRule] = []

        # 頻繁に検知されるパターンに対してポリシーを生成
        for pattern in patterns:
            if pattern.detection_count > 10 and pattern.false_positives < 2:
                new_rule = PolicyRule(
                    rule_id=str(uuid.uuid4()),
                    name=f"Pattern-based: {pattern.name}",
                    description=pattern.description,
                    pattern=pattern.attack_vector,
                    threat_level=pattern.severity,
                    action="block",
                    enabled=True,
                    auto_generated=True,
                    confidence_threshold=0.8,
                    vector_embedding=pattern.vector_embedding,
                )
                new_rules.append(new_rule)

        update = PolicyUpdate(
            update_id=str(uuid.uuid4()),
            update_type="create",
            affected_rules=[r.rule_id for r in new_rules],
            new_rules=new_rules,
            modified_rules=[],
            deleted_rule_ids=[],
            reason=f"Learned from {len(patterns)} attack patterns",
            auto_approved=False,
            timestamp=datetime.utcnow(),
        )

        logger.info(
            "Pattern learning completed",
            update_id=update.update_id,
            new_rules_count=len(new_rules),
        )

        return update
