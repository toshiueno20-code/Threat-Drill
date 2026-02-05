"""Input validation utilities."""

import re
from typing import Any

from ..schemas.security import MultimodalInput, ModalityType


class InputValidator:
    """入力データのバリデーター."""

    # 基本的なセキュリティチェック用パターン
    SUSPICIOUS_PATTERNS = [
        r"<script[^>]*>.*?</script>",  # XSS
        r"javascript:",  # JavaScript URL
        r"data:text/html",  # Data URI XSS
        r"(union|select|insert|update|delete|drop)\s+(from|into|table)",  # SQL Injection
        r"eval\s*\(",  # eval injection
        r"exec\s*\(",  # exec injection
        r"\.\./",  # Path traversal
        r"\.\.\%2[fF]",  # Encoded path traversal
        r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]",  # Control characters
    ]

    @classmethod
    def validate_input_safety(cls, input_data: MultimodalInput) -> tuple[bool, list[str]]:
        """
        入力データの基本的な安全性チェック.

        Returns:
            (is_safe, detected_issues) のタプル
        """
        detected_issues: list[str] = []

        if input_data.modality == ModalityType.TEXT:
            if isinstance(input_data.content, str):
                for pattern in cls.SUSPICIOUS_PATTERNS:
                    if re.search(pattern, input_data.content, re.IGNORECASE):
                        detected_issues.append(f"Suspicious pattern detected: {pattern}")

        # サイズチェック
        if isinstance(input_data.content, str):
            if len(input_data.content) > 1_000_000:  # 1MB
                detected_issues.append("Input size exceeds maximum allowed")
        elif isinstance(input_data.content, bytes):
            if len(input_data.content) > 10_000_000:  # 10MB
                detected_issues.append("Binary input size exceeds maximum allowed")

        return (len(detected_issues) == 0, detected_issues)

    @classmethod
    def sanitize_text(cls, text: str) -> str:
        """テキストのサニタイズ."""
        # HTMLエスケープ
        sanitized = text.replace("&", "&amp;")
        sanitized = sanitized.replace("<", "&lt;")
        sanitized = sanitized.replace(">", "&gt;")
        sanitized = sanitized.replace('"', "&quot;")
        sanitized = sanitized.replace("'", "&#x27;")
        return sanitized


def validate_input_safety(input_data: MultimodalInput) -> tuple[bool, list[str]]:
    """入力データの安全性チェック（モジュールレベル関数）."""
    return InputValidator.validate_input_safety(input_data)
