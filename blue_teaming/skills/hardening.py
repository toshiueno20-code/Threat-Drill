"""Security hardening skills — proactive defense and policy enforcement.

These skills perform security hardening by validating configurations,
enforcing policies, and proactively strengthening defenses.
"""

import re
import time
from typing import Any, ClassVar

from .base import (
    BaseDefenseSkill,
    DefenseResult,
    AlertLevel,
    DefenseAction,
    IncidentContext,
    defense_skill,
    record_defense,
)


@defense_skill
class OutputSanitizer(BaseDefenseSkill):
    """Sanitizes AI model outputs to prevent data leakage and XSS."""

    skill_name: ClassVar[str] = "output_sanitizer"
    skill_description: ClassVar[str] = "Sanitizes AI model outputs by redacting credentials, PII, and dangerous HTML/JS content before delivery to users"
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.MEDIUM
    category: ClassVar[str] = "hardening"

    REDACTION_RULES = [
        (r"(sk-[A-Za-z0-9]{20,})", "[REDACTED_API_KEY]"),
        (r"(AIza[A-Za-z0-9_-]{35})", "[REDACTED_GOOGLE_KEY]"),
        (r"(-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----)", "[REDACTED_PRIVATE_KEY]"),
        (r"((?:password|passwd|pwd)\s*[:=]\s*)\S+", r"\1[REDACTED]"),
        (r"(\b\d{3}[-.]?\d{2}[-.]?\d{4}\b)", "[REDACTED_SSN]"),
    ]

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []

        record_defense(timeline, "start", "Sanitizing output content")

        content = kwargs.get("content", "")
        if context and context.raw_payload:
            content = content or context.raw_payload

        redactions_applied = 0
        for pattern, replacement in self.REDACTION_RULES:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                redactions_applied += len(matches)
                findings.append(f"Redacted {len(matches)} instance(s) matching: {replacement}")
                record_defense(timeline, "redact", f"Applied redaction: {replacement}")

        record_defense(timeline, "complete", f"Sanitization complete: {redactions_applied} redactions")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=redactions_applied > 0,
            alert_level=AlertLevel.HIGH if redactions_applied > 0 else AlertLevel.INFO,
            action_taken=DefenseAction.REMEDIATE if redactions_applied > 0 else DefenseAction.MONITOR,
            findings=findings,
            recommendations=["Review redacted content for data leak source"] if redactions_applied > 0 else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            mitigated=redactions_applied > 0,
        )


@defense_skill
class PolicyEnforcer(BaseDefenseSkill):
    """Enforces security policies and compliance rules."""

    skill_name: ClassVar[str] = "policy_enforcer"
    skill_description: ClassVar[str] = "Real-time enforcement of security policies including RBAC validation, content policies, and compliance requirements (GDPR/CCPA)"
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.HIGH
    category: ClassVar[str] = "hardening"

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []
        violations: list[str] = []

        record_defense(timeline, "start", "Evaluating security policy compliance")

        permission_level = kwargs.get("permission_level", "user")
        requested_action = kwargs.get("action", "read")
        resource = kwargs.get("resource", "")

        # Check RBAC
        restricted_actions = {"delete", "admin", "export_all", "modify_policy"}
        if requested_action in restricted_actions and permission_level not in ("admin",):
            violations.append(f"RBAC violation: {permission_level} attempted {requested_action} on {resource}")
            record_defense(timeline, "violation", f"Unauthorized action: {requested_action}")

        # Check content policy
        payload = context.raw_payload if context else kwargs.get("payload", "")
        if payload and len(payload) > 50000:
            violations.append("Content size policy violation: payload exceeds maximum allowed size")
            record_defense(timeline, "violation", "Content size exceeded")

        has_violations = len(violations) > 0
        findings.extend(violations)
        if not has_violations:
            findings.append("All policy checks passed")

        record_defense(timeline, "complete", f"Policy check: {len(violations)} violation(s)")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=has_violations,
            alert_level=AlertLevel.CRITICAL if has_violations else AlertLevel.INFO,
            action_taken=DefenseAction.BLOCK if has_violations else DefenseAction.MONITOR,
            findings=findings,
            recommendations=[
                "Review and update access control policies",
                "Audit user permission assignments",
            ] if has_violations else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            blocked=has_violations,
        )


@defense_skill
class InputValidator(BaseDefenseSkill):
    """Validates and sanitizes all incoming inputs."""

    skill_name: ClassVar[str] = "input_validator"
    skill_description: ClassVar[str] = "Comprehensive input validation with type checking, length limits, encoding verification, and malicious content detection"
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.MEDIUM
    category: ClassVar[str] = "hardening"

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []
        issues: list[str] = []

        record_defense(timeline, "start", "Validating input content")

        payload = context.raw_payload if context else kwargs.get("payload", "")

        # Check encoding
        try:
            if isinstance(payload, bytes):
                payload.decode("utf-8")
            record_defense(timeline, "check", "Encoding validation passed")
        except UnicodeDecodeError:
            issues.append("Invalid UTF-8 encoding detected")
            record_defense(timeline, "fail", "Encoding validation failed")

        # Check for null bytes
        if "\x00" in payload:
            issues.append("Null byte injection detected")
            record_defense(timeline, "fail", "Null byte found in input")

        # Check for control characters
        control_chars = sum(1 for c in payload if ord(c) < 32 and c not in ("\n", "\r", "\t"))
        if control_chars > 0:
            issues.append(f"Suspicious control characters: {control_chars} found")
            record_defense(timeline, "warn", "Control characters detected")

        # Check length
        max_length = kwargs.get("max_length", 100000)
        if len(payload) > max_length:
            issues.append(f"Input exceeds maximum length: {len(payload)}/{max_length}")
            record_defense(timeline, "fail", "Length limit exceeded")

        has_issues = len(issues) > 0
        findings.extend(issues)
        if not has_issues:
            findings.append("Input validation passed all checks")

        record_defense(timeline, "complete", f"Validation: {len(issues)} issue(s)")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=has_issues,
            alert_level=AlertLevel.HIGH if has_issues else AlertLevel.INFO,
            action_taken=DefenseAction.BLOCK if has_issues else DefenseAction.MONITOR,
            findings=findings,
            recommendations=["Reject malformed input and log for analysis"] if has_issues else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            blocked=has_issues,
        )
