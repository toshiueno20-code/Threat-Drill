"""Cloud Functions for feedback loop processing."""

import base64
import json
import os
from typing import Any, Dict

import functions_framework
from google.cloud import firestore

# 環境変数から設定を取得
PROJECT_ID = os.environ.get("GCP_PROJECT_ID")
FIRESTORE_DATABASE = os.environ.get("FIRESTORE_DATABASE", "(default)")


@functions_framework.cloud_event
def process_security_event(cloud_event: Any) -> None:
    """
    セキュリティイベント処理のCloud Function.

    Args:
        cloud_event: Pub/Subからのクラウドイベント
    """
    try:
        # Pub/Subメッセージのデコード
        message_data = base64.b64decode(cloud_event.data["message"]["data"])
        event_data = json.loads(message_data)

        event_id = event_data.get("event_id")
        threat_level = event_data.get("threat_analysis", {}).get("threat_level")

        print(f"Processing security event: {event_id}, threat_level: {threat_level}")

        # 高脅威レベルの場合、追加処理を実施
        if threat_level in ["high", "critical"]:
            _trigger_deep_analysis(event_data)

        # イベントをFirestoreに保存（既に保存されている可能性があるが冪等性を確保）
        db = firestore.Client(project=PROJECT_ID, database=FIRESTORE_DATABASE)
        db.collection("security_events").document(event_id).set(
            event_data,
            merge=True,
        )

        print(f"Security event processed successfully: {event_id}")

    except Exception as e:
        print(f"Error processing security event: {str(e)}")
        raise


@functions_framework.cloud_event
def process_feedback_loop(cloud_event: Any) -> None:
    """
    フィードバックループ処理のCloud Function.

    Args:
        cloud_event: Pub/Subからのクラウドイベント
    """
    try:
        # Pub/Subメッセージのデコード
        message_data = base64.b64decode(cloud_event.data["message"]["data"])
        feedback_data = json.loads(message_data)

        feedback_type = feedback_data.get("feedback_type")
        event_id = feedback_data.get("original_security_event_id")

        print(f"Processing feedback: type={feedback_type}, event_id={event_id}")

        # フィードバックタイプに応じた処理
        if feedback_type == "false_positive":
            _handle_false_positive(feedback_data)
        elif feedback_type == "missed_threat":
            _handle_missed_threat(feedback_data)

        print(f"Feedback processed successfully: {event_id}")

    except Exception as e:
        print(f"Error processing feedback: {str(e)}")
        raise


@functions_framework.cloud_event
def process_policy_update(cloud_event: Any) -> None:
    """
    ポリシー更新処理のCloud Function.

    Args:
        cloud_event: Pub/Subからのクラウドイベント
    """
    try:
        # Pub/Subメッセージのデコード
        message_data = base64.b64decode(cloud_event.data["message"]["data"])
        update_data = json.loads(message_data)

        update_id = update_data.get("update_id")
        update_type = update_data.get("update_type")

        print(f"Processing policy update: {update_id}, type: {update_type}")

        db = firestore.Client(project=PROJECT_ID, database=FIRESTORE_DATABASE)

        # 新規ルールの追加
        for rule in update_data.get("new_rules", []):
            db.collection("policies").document(rule["rule_id"]).set(rule)

        # ルールの更新
        for rule in update_data.get("modified_rules", []):
            db.collection("policies").document(rule["rule_id"]).set(
                rule,
                merge=True,
            )

        # ルールの削除
        for rule_id in update_data.get("deleted_rule_ids", []):
            db.collection("policies").document(rule_id).delete()

        # 更新履歴を保存
        db.collection("policy_update_history").document(update_id).set(update_data)

        print(f"Policy update processed successfully: {update_id}")

    except Exception as e:
        print(f"Error processing policy update: {str(e)}")
        raise


def _trigger_deep_analysis(event_data: Dict[str, Any]) -> None:
    """
    Deep Think分析のトリガー.

    Args:
        event_data: イベントデータ
    """
    # TODO: Gemini 3 Pro Deep Thinkを起動
    print(f"Triggering deep analysis for event: {event_data.get('event_id')}")


def _handle_false_positive(feedback_data: Dict[str, Any]) -> None:
    """
    False Positive（誤検知）の処理.

    Args:
        feedback_data: フィードバックデータ
    """
    print(f"Handling false positive: {feedback_data.get('event_id')}")

    # TODO: Gemini 3で原因分析し、ポリシーを自動調整
    # 1. 誤検知の原因パターンを抽出
    # 2. ポリシールールの信頼度閾値を調整
    # 3. 除外パターンを追加


def _handle_missed_threat(feedback_data: Dict[str, Any]) -> None:
    """
    Missed Threat（見逃した脅威）の処理.

    Args:
        feedback_data: フィードバックデータ
    """
    print(f"Handling missed threat: {feedback_data.get('event_id')}")

    # TODO: Gemini 3で新しい検知パターンを生成
    # 1. 見逃された脅威のパターンを分析
    # 2. 新しいポリシールールを自動生成
    # 3. ベクトル埋め込みを作成してインデックスに追加
