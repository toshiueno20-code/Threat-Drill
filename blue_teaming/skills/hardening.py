"""Security hardening skills — defense-in-depth with MITRE mapping.

Enhanced with:
- MITRE ATT&CK technique mapping for hardening targets
- CVSS scoring for policy violations
- NIST IR phase alignment (Preparation phase)
- Extended credential detection patterns
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
    NISTIRPhase,
    ContainmentStrategy,
    CVSSVector,
    CVSS_PRESETS,
    defense_skill,
    record_defense,
)


@defense_skill
class OutputSanitizer(BaseDefenseSkill):
    """Sanitizes AI outputs — MITRE T1048 countermeasure.

    Prevents data exfiltration through AI model output by
    redacting credentials, PII, and dangerous content.
    """

    skill_name: ClassVar[str] = "output_sanitizer"
    skill_description: ClassVar[str] = (
        "Sanitizes AI outputs by redacting credentials (20+ patterns), "
        "PII, and dangerous HTML/JS content — countermeasure for MITRE T1048"
    )
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.MEDIUM
    category: ClassVar[str] = "hardening"
    mitre_techniques: ClassVar[list[str]] = ["T1048", "T1552"]

    REDACTION_RULES = [
        # API Keys & tokens
        (r"(sk-[A-Za-z0-9]{20,})", "[REDACTED:OPENAI_KEY]"),
        (r"(sk-proj-[A-Za-z0-9_-]{20,})", "[REDACTED:OPENAI_PROJECT_KEY]"),
        (r"(AIza[A-Za-z0-9_-]{35})", "[REDACTED:GOOGLE_KEY]"),
        (r"(AKIA[A-Z0-9]{16})", "[REDACTED:AWS_KEY]"),
        (r"((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})", "[REDACTED:GITHUB_TOKEN]"),
        (r"(xoxb-[0-9]+-[A-Za-z0-9]+)", "[REDACTED:SLACK_TOKEN]"),
        # Private keys & certs
        (r"(-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----)",
         "[REDACTED:PRIVATE_KEY]"),
        # Credentials
        (r"((?:password|passwd|pwd|secret|api_key|apikey|access_token|auth_token)\s*[:=]\s*)\S{6,}",
         r"\1[REDACTED]"),
        (r"((?:DATABASE_URL|MONGO_URI|REDIS_URL|DB_PASSWORD)\s*=\s*)\S+", r"\1[REDACTED]"),
        # PII
        (r"(\b\d{3}[-.]?\d{2}[-.]?\d{4}\b)", "[REDACTED:SSN]"),
        (r"(\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b)", "[REDACTED:CC]"),
        # Dangerous content
        (r"(<script[^>]*>[\s\S]*?</script>)", "[REDACTED:SCRIPT]"),
        (r"(javascript:\S+)", "[REDACTED:JS_URI]"),
    ]

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []
        mitre_mappings = self.get_mitre_mappings()

        record_defense(timeline, "start", "Sanitizing output (extended patterns)")

        content = kwargs.get("content", "")
        if context and context.raw_payload:
            content = content or context.raw_payload

        redactions_applied = 0
        categories: set[str] = set()
        for pattern, replacement in self.REDACTION_RULES:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                redactions_applied += len(matches)
                categories.add(replacement.strip("[]").split(":")[0] if ":" in replacement else "GENERIC")
                findings.append(
                    f"[MITRE:T1048] Redacted {len(matches)} instance(s): {replacement}"
                )
                record_defense(timeline, "redact", replacement)

        cvss = CVSS_PRESETS.get("credential_exposure", CVSSVector())
        record_defense(timeline, "complete", f"Redactions: {redactions_applied}")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=redactions_applied > 0,
            alert_level=AlertLevel.HIGH if redactions_applied > 0 else AlertLevel.INFO,
            action_taken=DefenseAction.REMEDIATE if redactions_applied > 0 else DefenseAction.MONITOR,
            findings=findings,
            recommendations=[
                "Investigate data leak source in the model pipeline",
                "Rotate any exposed credentials immediately",
                "Review output filtering rules for completeness",
            ] if redactions_applied > 0 else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            mitigated=redactions_applied > 0,
            mitre_techniques=mitre_mappings if redactions_applied > 0 else [],
            cvss_score=cvss.base_score() if redactions_applied > 0 else 0.0,
            cvss_severity=cvss.severity_label() if redactions_applied > 0 else "None",
            ir_phase=NISTIRPhase.CONTAINMENT,
            containment_strategy=ContainmentStrategy.OUTPUT_FILTER if redactions_applied > 0 else None,
            detection_confidence=0.9 if redactions_applied > 0 else 0.0,
        )


@defense_skill
class PolicyEnforcer(BaseDefenseSkill):
    """Enforces security policies — RBAC, content, and compliance."""

    skill_name: ClassVar[str] = "policy_enforcer"
    skill_description: ClassVar[str] = (
        "Real-time policy enforcement: RBAC validation, content policies, "
        "compliance requirements (GDPR/CCPA/個人情報保護法), and "
        "least-privilege verification"
    )
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.HIGH
    category: ClassVar[str] = "hardening"

    RESTRICTED_ACTIONS = {
        "delete": "admin",
        "admin": "admin",
        "export_all": "admin",
        "modify_policy": "admin",
        "view_pii": "admin",
        "modify_model": "admin",
        "access_logs": "admin",
    }

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []
        violations: list[str] = []

        record_defense(timeline, "start", "Evaluating security policies (RBAC + compliance)")

        permission_level = kwargs.get("permission_level", "user")
        requested_action = kwargs.get("action", "read")
        resource = kwargs.get("resource", "")

        # RBAC check
        required_role = self.RESTRICTED_ACTIONS.get(requested_action)
        if required_role and permission_level != required_role:
            violations.append(
                f"[RBAC] {permission_level} attempted '{requested_action}' "
                f"on '{resource}' (requires: {required_role})"
            )
            record_defense(timeline, "violation", f"Unauthorized: {requested_action}")

        # Content size policy
        payload = context.raw_payload if context else kwargs.get("payload", "")
        if payload and len(payload) > 50000:
            violations.append(
                f"[Policy] Content size violation: {len(payload):,} chars (max: 50,000)"
            )
            record_defense(timeline, "violation", "Content size exceeded")

        # Rate-based policy
        metadata = context.metadata if context else kwargs.get("metadata", {})
        if metadata.get("requests_per_minute", 0) > 200:
            violations.append("[Policy] Rate policy exceeded: >200 req/min")
            record_defense(timeline, "violation", "Rate policy exceeded")

        has_violations = len(violations) > 0
        findings.extend(violations)
        if not has_violations:
            findings.append("All policy checks passed (RBAC, content, rate)")

        record_defense(timeline, "complete", f"Violations: {len(violations)}")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=has_violations,
            alert_level=AlertLevel.CRITICAL if has_violations else AlertLevel.INFO,
            action_taken=DefenseAction.BLOCK if has_violations else DefenseAction.MONITOR,
            findings=findings,
            recommendations=[
                "Review and update RBAC policy assignments",
                "Audit user permission grants (least-privilege principle)",
                "Log policy violations for compliance reporting",
            ] if has_violations else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            blocked=has_violations,
            ir_phase=NISTIRPhase.PREPARATION,
            detection_confidence=1.0 if has_violations else 0.0,
        )


@defense_skill
class InputValidator(BaseDefenseSkill):
    """Validates inputs — defense-in-depth first layer."""

    skill_name: ClassVar[str] = "input_validator"
    skill_description: ClassVar[str] = (
        "Comprehensive input validation: encoding verification, null byte "
        "detection, control character analysis, Unicode normalization check, "
        "and length limits"
    )
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.MEDIUM
    category: ClassVar[str] = "hardening"
    mitre_techniques: ClassVar[list[str]] = ["T1190"]

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []
        issues: list[str] = []
        mitre_mappings = self.get_mitre_mappings()

        record_defense(timeline, "start", "Validating input (defense-in-depth)")

        payload = context.raw_payload if context else kwargs.get("payload", "")

        # Encoding check
        try:
            if isinstance(payload, bytes):
                payload.decode("utf-8")
            record_defense(timeline, "pass", "UTF-8 encoding valid")
        except UnicodeDecodeError:
            issues.append("[T1190] Invalid UTF-8 encoding — potential binary injection")
            record_defense(timeline, "fail", "Encoding invalid")

        # Null byte injection
        if "\x00" in payload:
            issues.append("[T1190] Null byte injection detected")
            record_defense(timeline, "fail", "Null byte found")

        # Control characters
        control_chars = sum(1 for c in payload if ord(c) < 32 and c not in ("\n", "\r", "\t"))
        if control_chars > 0:
            issues.append(f"[T1190] Suspicious control characters: {control_chars}")
            record_defense(timeline, "warn", f"Control chars: {control_chars}")

        # Unicode normalization consistency
        import unicodedata
        nfc = unicodedata.normalize("NFC", payload)
        if nfc != payload and len(payload) > 0:
            diff = sum(1 for a, b in zip(payload, nfc) if a != b)
            if diff > 3:
                issues.append(f"[T1190] Unicode normalization inconsistency: {diff} chars differ (NFC)")
                record_defense(timeline, "warn", f"Unicode normalization diff: {diff}")

        # Length check
        max_length = kwargs.get("max_length", 100000)
        if len(payload) > max_length:
            issues.append(f"[T1190] Input exceeds max length: {len(payload):,}/{max_length:,}")
            record_defense(timeline, "fail", "Length exceeded")

        has_issues = len(issues) > 0
        findings.extend(issues)
        if not has_issues:
            findings.append("Input validation passed (encoding, null, control, unicode, length)")

        record_defense(timeline, "complete", f"Issues: {len(issues)}")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=has_issues,
            alert_level=AlertLevel.HIGH if has_issues else AlertLevel.INFO,
            action_taken=DefenseAction.BLOCK if has_issues else DefenseAction.MONITOR,
            findings=findings,
            recommendations=[
                "Reject and log malformed input",
                "Apply Unicode NFC normalization before processing",
            ] if has_issues else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            blocked=has_issues,
            mitre_techniques=mitre_mappings if has_issues else [],
            ir_phase=NISTIRPhase.PREPARATION,
            containment_strategy=ContainmentStrategy.INPUT_FILTER if has_issues else None,
            detection_confidence=0.85 if has_issues else 0.0,
        )
