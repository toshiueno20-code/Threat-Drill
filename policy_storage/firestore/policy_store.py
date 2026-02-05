"""Policy storage using Firestore."""

from datetime import datetime
from typing import List, Optional, Dict, Any

from google.cloud import firestore
from google.oauth2 import service_account

from shared.schemas import PolicyRule, SecurityEvent, AttackPattern
from shared.constants import (
    COLLECTION_POLICIES,
    COLLECTION_SECURITY_EVENTS,
    COLLECTION_ATTACK_PATTERNS,
    COLLECTION_SYSTEM_INSIGHTS,
)
from shared.utils import get_logger

logger = get_logger(__name__)


class PolicyStore:
    """Firestoreを使用したポリシー管理."""

    def __init__(
        self,
        project_id: str,
        database: str = "(default)",
        credentials: Optional[service_account.Credentials] = None,
    ):
        """
        PolicyStoreの初期化.

        Args:
            project_id: Google Cloud Project ID
            database: Firestore データベース名
            credentials: サービスアカウント認証情報
        """
        self.project_id = project_id
        self.db = firestore.Client(
            project=project_id,
            database=database,
            credentials=credentials,
        )

        logger.info(
            "PolicyStore initialized",
            project_id=project_id,
            database=database,
        )

    async def get_policy(self, rule_id: str) -> Optional[PolicyRule]:
        """
        ポリシールールの取得.

        Args:
            rule_id: ルールID

        Returns:
            ポリシールール、見つからない場合はNone
        """
        try:
            doc_ref = self.db.collection(COLLECTION_POLICIES).document(rule_id)
            doc = doc_ref.get()

            if doc.exists:
                data = doc.to_dict()
                return PolicyRule(**data)

            return None

        except Exception as e:
            logger.error(
                "Failed to get policy",
                rule_id=rule_id,
                error=str(e),
            )
            raise

    async def get_all_policies(self, enabled_only: bool = True) -> List[PolicyRule]:
        """
        全ポリシールールの取得.

        Args:
            enabled_only: 有効なルールのみを取得

        Returns:
            ポリシールールのリスト
        """
        try:
            query = self.db.collection(COLLECTION_POLICIES)

            if enabled_only:
                query = query.where("enabled", "==", True)

            docs = query.stream()
            policies = [PolicyRule(**doc.to_dict()) for doc in docs]

            logger.info(
                "Retrieved policies",
                count=len(policies),
                enabled_only=enabled_only,
            )

            return policies

        except Exception as e:
            logger.error("Failed to get policies", error=str(e))
            raise

    async def create_policy(self, policy: PolicyRule) -> str:
        """
        ポリシールールの作成.

        Args:
            policy: 作成するポリシールール

        Returns:
            作成されたルールID
        """
        try:
            policy.created_at = datetime.utcnow()
            policy.updated_at = datetime.utcnow()

            doc_ref = self.db.collection(COLLECTION_POLICIES).document(policy.rule_id)
            doc_ref.set(policy.model_dump())

            logger.info(
                "Policy created",
                rule_id=policy.rule_id,
                threat_level=policy.threat_level,
            )

            return policy.rule_id

        except Exception as e:
            logger.error(
                "Failed to create policy",
                rule_id=policy.rule_id,
                error=str(e),
            )
            raise

    async def update_policy(self, policy: PolicyRule) -> None:
        """
        ポリシールールの更新.

        Args:
            policy: 更新するポリシールール
        """
        try:
            policy.updated_at = datetime.utcnow()

            doc_ref = self.db.collection(COLLECTION_POLICIES).document(policy.rule_id)
            doc_ref.update(policy.model_dump())

            logger.info(
                "Policy updated",
                rule_id=policy.rule_id,
            )

        except Exception as e:
            logger.error(
                "Failed to update policy",
                rule_id=policy.rule_id,
                error=str(e),
            )
            raise

    async def delete_policy(self, rule_id: str) -> None:
        """
        ポリシールールの削除.

        Args:
            rule_id: ルールID
        """
        try:
            doc_ref = self.db.collection(COLLECTION_POLICIES).document(rule_id)
            doc_ref.delete()

            logger.info("Policy deleted", rule_id=rule_id)

        except Exception as e:
            logger.error(
                "Failed to delete policy",
                rule_id=rule_id,
                error=str(e),
            )
            raise

    async def store_security_event(self, event: SecurityEvent) -> None:
        """
        セキュリティイベントの保存.

        Args:
            event: セキュリティイベント
        """
        try:
            doc_ref = self.db.collection(COLLECTION_SECURITY_EVENTS).document(event.event_id)
            doc_ref.set(event.model_dump(mode="json"))

            logger.info(
                "Security event stored",
                event_id=event.event_id,
                threat_level=event.threat_analysis.threat_level,
            )

        except Exception as e:
            logger.error(
                "Failed to store security event",
                event_id=event.event_id,
                error=str(e),
            )
            raise

    async def get_security_event(self, event_id: str) -> Optional[SecurityEvent]:
        """
        セキュリティイベントの取得.

        Args:
            event_id: イベントID

        Returns:
            セキュリティイベント、見つからない場合はNone
        """
        try:
            doc_ref = self.db.collection(COLLECTION_SECURITY_EVENTS).document(event_id)
            doc = doc_ref.get()

            if doc.exists:
                data = doc.to_dict()
                return SecurityEvent(**data)

            return None

        except Exception as e:
            logger.error(
                "Failed to get security event",
                event_id=event_id,
                error=str(e),
            )
            raise

    async def store_attack_pattern(self, pattern: AttackPattern) -> None:
        """
        攻撃パターンの保存.

        Args:
            pattern: 攻撃パターン
        """
        try:
            doc_ref = self.db.collection(COLLECTION_ATTACK_PATTERNS).document(pattern.pattern_id)

            # 既存パターンが存在する場合は更新
            existing = doc_ref.get()
            if existing.exists:
                # 検出回数の更新
                doc_ref.update({
                    "detection_count": firestore.Increment(1),
                    "last_seen": datetime.utcnow(),
                })
            else:
                doc_ref.set(pattern.model_dump(mode="json"))

            logger.info(
                "Attack pattern stored",
                pattern_id=pattern.pattern_id,
                severity=pattern.severity,
            )

        except Exception as e:
            logger.error(
                "Failed to store attack pattern",
                pattern_id=pattern.pattern_id,
                error=str(e),
            )
            raise

    async def get_attack_patterns(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
    ) -> List[AttackPattern]:
        """
        攻撃パターンの取得.

        Args:
            limit: 取得数上限
            severity: 脅威レベルフィルタ

        Returns:
            攻撃パターンのリスト
        """
        try:
            query = self.db.collection(COLLECTION_ATTACK_PATTERNS)

            if severity:
                query = query.where("severity", "==", severity)

            query = query.order_by("detection_count", direction=firestore.Query.DESCENDING)
            query = query.limit(limit)

            docs = query.stream()
            patterns = [AttackPattern(**doc.to_dict()) for doc in docs]

            logger.info(
                "Retrieved attack patterns",
                count=len(patterns),
                severity=severity,
            )

            return patterns

        except Exception as e:
            logger.error("Failed to get attack patterns", error=str(e))
            raise

    async def query_events(
        self,
        start_time: datetime,
        end_time: datetime,
        threat_level: Optional[str] = None,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        """
        期間内のセキュリティイベントをクエリ.

        Args:
            start_time: 開始時刻
            end_time: 終了時刻
            threat_level: 脅威レベルフィルタ
            limit: 取得数上限

        Returns:
            セキュリティイベントのリスト
        """
        try:
            query = self.db.collection(COLLECTION_SECURITY_EVENTS)
            query = query.where("timestamp", ">=", start_time)
            query = query.where("timestamp", "<=", end_time)

            if threat_level:
                query = query.where("threat_analysis.threat_level", "==", threat_level)

            query = query.order_by("timestamp", direction=firestore.Query.DESCENDING)
            query = query.limit(limit)

            docs = query.stream()
            events = [SecurityEvent(**doc.to_dict()) for doc in docs]

            logger.info(
                "Queried security events",
                count=len(events),
                start_time=start_time,
                end_time=end_time,
            )

            return events

        except Exception as e:
            logger.error("Failed to query events", error=str(e))
            raise
