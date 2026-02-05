"""Real-time Proxy Interceptor for AI Applications."""

import time
import uuid
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

from shared.schemas import MultimodalInput, ThreatLevel
from shared.utils import get_logger
from intelligence_center.models import GeminiClient
from intelligence_center.analyzers import PrimaryFilterAnalyzer, DeepThinkAnalyzer

logger = get_logger(__name__)


class ProxyAction(str, Enum):
    """プロキシアクション."""

    PASS = "pass"  # そのまま実行
    BLOCK = "block"  # 拒否
    REDACT = "redact"  # 機密情報を伏せ字


@dataclass
class UserContext:
    """ユーザーコンテキスト."""

    user_id: str
    session_id: str
    permission_level: str  # "admin", "user", "guest"
    conversation_history: List[Dict[str, Any]]
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


@dataclass
class AgentAction:
    """AIエージェントが実行しようとしているアクション."""

    action_id: str
    action_type: str  # "sql_query", "api_call", "file_write", etc.
    tool_name: str
    arguments: Dict[str, Any]
    target_resource: str
    requires_permission: str  # Required permission level


@dataclass
class InterceptResult:
    """インターセプト結果."""

    decision: ProxyAction
    threat_level: ThreatLevel
    reasoning: str
    confidence: float
    redacted_content: Optional[str] = None
    alert_sent: bool = False
    processing_time_ms: float = 0.0


class RealtimeAIProxy:
    """リアルタイムAIプロキシ."""

    def __init__(
        self,
        gemini_client: GeminiClient,
        enable_deep_think: bool = True,
    ):
        """
        プロキシの初期化.

        Args:
            gemini_client: Geminiクライアント
            enable_deep_think: Deep Thinkモードを有効化
        """
        self.gemini_client = gemini_client
        self.enable_deep_think = enable_deep_think
        self.primary_filter = PrimaryFilterAnalyzer(gemini_client)
        self.deep_think = DeepThinkAnalyzer(gemini_client)

        logger.info("RealtimeAIProxy initialized", deep_think_enabled=enable_deep_think)

    async def intercept_user_input(
        self,
        inputs: List[MultimodalInput],
        user_context: UserContext,
    ) -> InterceptResult:
        """
        ユーザー入力をインターセプト.

        Args:
            inputs: ユーザー入力
            user_context: ユーザーコンテキスト

        Returns:
            インターセプト結果
        """
        start_time = time.time()

        logger.info(
            "Intercepting user input",
            user_id=user_context.user_id,
            session_id=user_context.session_id,
            input_count=len(inputs),
        )

        # Primary Filter（Gemini Flash）で高速スキャン
        primary_result = await self.primary_filter.analyze(
            inputs=inputs,
            context_history=user_context.conversation_history,
        )

        # 脅威レベルに応じて判断
        if primary_result.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            decision = ProxyAction.BLOCK
            reasoning = f"High threat detected: {primary_result.reasoning}"

        elif primary_result.threat_level == ThreatLevel.MEDIUM:
            # Deep Thinkで詳細分析
            if self.enable_deep_think and "TRIGGER_DEEP_THINK" in primary_result.recommended_actions:
                logger.info("Triggering Deep Think analysis")

                deep_result = await self.deep_think.analyze(
                    inputs=inputs,
                    initial_analysis=primary_result,
                    context_history=user_context.conversation_history,
                )

                # Deep Thinkの結果で再判定
                if deep_result.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
                    decision = ProxyAction.BLOCK
                    reasoning = f"Deep Think confirmed threat: {deep_result.reasoning}"
                else:
                    decision = ProxyAction.PASS
                    reasoning = f"Deep Think cleared: {deep_result.reasoning}"

                primary_result = deep_result
            else:
                decision = ProxyAction.PASS
                reasoning = "Medium threat, but allowing with monitoring"

        else:
            decision = ProxyAction.PASS
            reasoning = "No significant threat detected"

        processing_time = (time.time() - start_time) * 1000

        result = InterceptResult(
            decision=decision,
            threat_level=primary_result.threat_level,
            reasoning=reasoning,
            confidence=primary_result.confidence,
            processing_time_ms=processing_time,
        )

        logger.info(
            "User input interception completed",
            decision=decision.value,
            threat_level=primary_result.threat_level.value,
            processing_time_ms=processing_time,
        )

        return result

    async def intercept_agent_action(
        self,
        action: AgentAction,
        user_context: UserContext,
    ) -> InterceptResult:
        """
        AIエージェントのアクション実行前にインターセプト.

        Args:
            action: エージェントアクション
            user_context: ユーザーコンテキスト

        Returns:
            インターセプト結果
        """
        start_time = time.time()

        logger.info(
            "Intercepting agent action",
            action_type=action.action_type,
            tool_name=action.tool_name,
            user_id=user_context.user_id,
        )

        # 権限チェック
        if not self._check_permission(user_context.permission_level, action.requires_permission):
            processing_time = (time.time() - start_time) * 1000

            return InterceptResult(
                decision=ProxyAction.BLOCK,
                threat_level=ThreatLevel.HIGH,
                reasoning=(
                    f"Permission denied: User has '{user_context.permission_level}' permission, "
                    f"but action requires '{action.requires_permission}'"
                ),
                confidence=1.0,
                processing_time_ms=processing_time,
                alert_sent=True,
            )

        # アクションタイプ別の検証
        if action.action_type == "sql_query":
            return await self._validate_sql_query(action, user_context, start_time)

        elif action.action_type == "api_call":
            return await self._validate_api_call(action, user_context, start_time)

        elif action.action_type == "file_operation":
            return await self._validate_file_operation(action, user_context, start_time)

        else:
            # デフォルトは許可
            processing_time = (time.time() - start_time) * 1000
            return InterceptResult(
                decision=ProxyAction.PASS,
                threat_level=ThreatLevel.LOW,
                reasoning=f"Action type '{action.action_type}' is allowed",
                confidence=0.8,
                processing_time_ms=processing_time,
            )

    async def _validate_sql_query(
        self,
        action: AgentAction,
        user_context: UserContext,
        start_time: float,
    ) -> InterceptResult:
        """SQL クエリの検証."""
        sql_query = action.arguments.get("query", "")

        logger.info("Validating SQL query", user_id=user_context.user_id)

        # 危険なSQLパターンをチェック
        dangerous_patterns = [
            "DROP TABLE",
            "DELETE FROM",
            "TRUNCATE",
            "ALTER TABLE",
            "DROP DATABASE",
        ]

        for pattern in dangerous_patterns:
            if pattern.lower() in sql_query.lower():
                processing_time = (time.time() - start_time) * 1000

                return InterceptResult(
                    decision=ProxyAction.BLOCK,
                    threat_level=ThreatLevel.CRITICAL,
                    reasoning=f"Dangerous SQL operation detected: {pattern}",
                    confidence=0.95,
                    processing_time_ms=processing_time,
                    alert_sent=True,
                )

        # TODO: Gemini 3でSQLクエリを分析
        # - アクセス権限外のテーブルを参照していないか
        # - SQLインジェクションの可能性がないか

        processing_time = (time.time() - start_time) * 1000

        return InterceptResult(
            decision=ProxyAction.PASS,
            threat_level=ThreatLevel.LOW,
            reasoning="SQL query validated successfully",
            confidence=0.85,
            processing_time_ms=processing_time,
        )

    async def _validate_api_call(
        self,
        action: AgentAction,
        user_context: UserContext,
        start_time: float,
    ) -> InterceptResult:
        """API呼び出しの検証."""
        api_endpoint = action.arguments.get("endpoint", "")
        method = action.arguments.get("method", "GET")

        logger.info(
            "Validating API call",
            endpoint=api_endpoint,
            method=method,
            user_id=user_context.user_id,
        )

        # 管理者APIへのアクセスチェック
        if "/admin/" in api_endpoint and user_context.permission_level != "admin":
            processing_time = (time.time() - start_time) * 1000

            return InterceptResult(
                decision=ProxyAction.BLOCK,
                threat_level=ThreatLevel.HIGH,
                reasoning="Unauthorized access to admin API",
                confidence=1.0,
                processing_time_ms=processing_time,
                alert_sent=True,
            )

        processing_time = (time.time() - start_time) * 1000

        return InterceptResult(
            decision=ProxyAction.PASS,
            threat_level=ThreatLevel.LOW,
            reasoning="API call validated",
            confidence=0.9,
            processing_time_ms=processing_time,
        )

    async def _validate_file_operation(
        self,
        action: AgentAction,
        user_context: UserContext,
        start_time: float,
    ) -> InterceptResult:
        """ファイル操作の検証."""
        operation = action.arguments.get("operation", "")
        file_path = action.arguments.get("path", "")

        logger.info(
            "Validating file operation",
            operation=operation,
            path=file_path,
            user_id=user_context.user_id,
        )

        # 危険な操作
        if operation in ["delete", "write"] and (
            "/etc/" in file_path or "/sys/" in file_path or "/root/" in file_path
        ):
            processing_time = (time.time() - start_time) * 1000

            return InterceptResult(
                decision=ProxyAction.BLOCK,
                threat_level=ThreatLevel.CRITICAL,
                reasoning=f"Dangerous file operation on system path: {file_path}",
                confidence=1.0,
                processing_time_ms=processing_time,
                alert_sent=True,
            )

        processing_time = (time.time() - start_time) * 1000

        return InterceptResult(
            decision=ProxyAction.PASS,
            threat_level=ThreatLevel.LOW,
            reasoning="File operation validated",
            confidence=0.85,
            processing_time_ms=processing_time,
        )

    def _check_permission(self, user_level: str, required_level: str) -> bool:
        """権限チェック."""
        permission_hierarchy = {
            "admin": 3,
            "user": 2,
            "guest": 1,
        }

        user_perm = permission_hierarchy.get(user_level, 0)
        required_perm = permission_hierarchy.get(required_level, 0)

        return user_perm >= required_perm

    async def intercept_agent_output(
        self,
        output_text: str,
        user_context: UserContext,
    ) -> InterceptResult:
        """
        AIエージェントの出力をインターセプト（機密情報のREDACT）.

        Args:
            output_text: エージェントの出力テキスト
            user_context: ユーザーコンテキスト

        Returns:
            インターセプト結果（必要に応じてREDACT）
        """
        start_time = time.time()

        logger.info(
            "Intercepting agent output",
            output_length=len(output_text),
            user_id=user_context.user_id,
        )

        # 機密情報パターンのチェック
        sensitive_patterns = [
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "EMAIL", "[EMAIL_REDACTED]"),
            (r"\b\d{3}-\d{2}-\d{4}\b", "SSN", "[SSN_REDACTED]"),
            (r"\b\d{16}\b", "CREDIT_CARD", "[CC_REDACTED]"),
            (r"sk-[a-zA-Z0-9]{48}", "API_KEY", "[API_KEY_REDACTED]"),
        ]

        redacted_output = output_text
        has_sensitive_data = False

        import re

        for pattern, data_type, replacement in sensitive_patterns:
            matches = re.findall(pattern, redacted_output)
            if matches:
                has_sensitive_data = True
                redacted_output = re.sub(pattern, replacement, redacted_output)
                logger.warning(
                    "Sensitive data detected in output",
                    data_type=data_type,
                    matches_count=len(matches),
                )

        processing_time = (time.time() - start_time) * 1000

        if has_sensitive_data:
            return InterceptResult(
                decision=ProxyAction.REDACT,
                threat_level=ThreatLevel.MEDIUM,
                reasoning="Sensitive data detected and redacted from output",
                confidence=0.9,
                redacted_content=redacted_output,
                processing_time_ms=processing_time,
                alert_sent=True,
            )

        return InterceptResult(
            decision=ProxyAction.PASS,
            threat_level=ThreatLevel.SAFE,
            reasoning="No sensitive data detected in output",
            confidence=0.95,
            processing_time_ms=processing_time,
        )
