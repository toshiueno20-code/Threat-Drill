"""Pub/Sub event publisher for feedback loop."""

import json
from typing import Any, Dict, Optional

from google.cloud import pubsub_v1
from google.oauth2 import service_account

from shared.constants import (
    TOPIC_SECURITY_EVENTS,
    TOPIC_FEEDBACK_LOOP,
    TOPIC_POLICY_UPDATES,
    TOPIC_RED_TEAM_FINDINGS,
)
from shared.utils import get_logger

logger = get_logger(__name__)


class EventPublisher:
    """Pub/Subイベントパブリッシャー."""

    def __init__(
        self,
        project_id: str,
        credentials: Optional[service_account.Credentials] = None,
    ):
        """
        EventPublisherの初期化.

        Args:
            project_id: Google Cloud Project ID
            credentials: サービスアカウント認証情報
        """
        self.project_id = project_id
        self.publisher = pubsub_v1.PublisherClient(credentials=credentials)

        # トピックパスの構築
        self.topics = {
            "security_events": self.publisher.topic_path(project_id, TOPIC_SECURITY_EVENTS),
            "feedback_loop": self.publisher.topic_path(project_id, TOPIC_FEEDBACK_LOOP),
            "policy_updates": self.publisher.topic_path(project_id, TOPIC_POLICY_UPDATES),
            "red_team_findings": self.publisher.topic_path(project_id, TOPIC_RED_TEAM_FINDINGS),
        }

        logger.info(
            "EventPublisher initialized",
            project_id=project_id,
            topics=list(self.topics.keys()),
        )

    async def publish_security_event(
        self,
        event_data: Dict[str, Any],
        attributes: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        セキュリティイベントのパブリッシュ.

        Args:
            event_data: イベントデータ
            attributes: メッセージ属性

        Returns:
            メッセージID
        """
        return await self._publish(
            topic_name="security_events",
            data=event_data,
            attributes=attributes,
        )

    async def publish_feedback_event(
        self,
        feedback_data: Dict[str, Any],
        attributes: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        フィードバックイベントのパブリッシュ.

        Args:
            feedback_data: フィードバックデータ
            attributes: メッセージ属性

        Returns:
            メッセージID
        """
        return await self._publish(
            topic_name="feedback_loop",
            data=feedback_data,
            attributes=attributes,
        )

    async def publish_policy_update(
        self,
        update_data: Dict[str, Any],
        attributes: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        ポリシー更新イベントのパブリッシュ.

        Args:
            update_data: 更新データ
            attributes: メッセージ属性

        Returns:
            メッセージID
        """
        return await self._publish(
            topic_name="policy_updates",
            data=update_data,
            attributes=attributes,
        )

    async def publish_red_team_finding(
        self,
        finding_data: Dict[str, Any],
        attributes: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Red Team発見事項のパブリッシュ.

        Args:
            finding_data: 発見事項データ
            attributes: メッセージ属性

        Returns:
            メッセージID
        """
        return await self._publish(
            topic_name="red_team_findings",
            data=finding_data,
            attributes=attributes,
        )

    async def _publish(
        self,
        topic_name: str,
        data: Dict[str, Any],
        attributes: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        メッセージのパブリッシュ（内部メソッド）.

        Args:
            topic_name: トピック名
            data: メッセージデータ
            attributes: メッセージ属性

        Returns:
            メッセージID
        """
        try:
            topic_path = self.topics[topic_name]

            # JSONシリアライズ
            message_json = json.dumps(data, default=str)
            message_bytes = message_json.encode("utf-8")

            # 属性の設定
            if attributes is None:
                attributes = {}

            # パブリッシュ
            future = self.publisher.publish(
                topic_path,
                data=message_bytes,
                **attributes,
            )

            message_id = future.result()

            logger.info(
                "Message published",
                topic=topic_name,
                message_id=message_id,
                data_size=len(message_bytes),
            )

            return message_id

        except Exception as e:
            logger.error(
                "Failed to publish message",
                topic=topic_name,
                error=str(e),
            )
            raise

    def create_topics_if_not_exists(self) -> None:
        """トピックが存在しない場合は作成."""
        for topic_name, topic_path in self.topics.items():
            try:
                self.publisher.get_topic(request={"topic": topic_path})
                logger.info("Topic exists", topic=topic_name)
            except Exception:
                # トピックが存在しない場合は作成
                try:
                    self.publisher.create_topic(request={"name": topic_path})
                    logger.info("Topic created", topic=topic_name)
                except Exception as e:
                    logger.error(
                        "Failed to create topic",
                        topic=topic_name,
                        error=str(e),
                    )
