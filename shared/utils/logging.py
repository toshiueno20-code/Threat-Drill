"""Structured logging utilities for Threat Drill."""

import logging
import sys
from typing import Any

import structlog
from structlog.types import EventDict, Processor


def add_security_context(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """セキュリティコンテキストを追加."""
    # セキュリティイベント用の追加フィールド
    if "threat_level" in event_dict:
        event_dict["security_event"] = True
    return event_dict


def setup_logger(log_level: str = "INFO", json_logs: bool = True) -> None:
    """構造化ロガーのセットアップ."""
    processors: list[Processor] = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        add_security_context,
    ]

    if json_logs:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # 標準ロギングの設定
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper()),
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """ロガーの取得."""
    return structlog.get_logger(name)
