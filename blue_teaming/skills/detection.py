"""Threat detection skills — real-time monitoring and anomaly detection.

These skills monitor incoming traffic, analyze patterns, and detect
active threats including prompt injection, jailbreak attempts,
data exfiltration, and anomalous behavior.
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
from shared.schemas import ThreatLevel


@defense_skill
class PromptInjectionDetector(BaseDefenseSkill):
    """Detects prompt injection attempts in real-time."""

    skill_name: ClassVar[str] = "prompt_injection_detector"
    skill_description: ClassVar[str] = "Real-time detection of prompt injection attacks including direct, indirect, and encoded variants"
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.HIGH
    category: ClassVar[str] = "detection"

    INJECTION_PATTERNS = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"system:\s*override",
        r"you\s+are\s+now\s+(DAN|evil|unrestricted)",
        r"forget\s+(everything|all|your\s+instructions)",
        r"new\s+instructions?\s*:",
        r"</?(system|user|assistant)>",
        r"jailbreak",
        r"\[INST\]",
        r"<<SYS>>",
    ]

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []

        record_defense(timeline, "start", "Scanning for prompt injection patterns")

        payload = context.raw_payload if context else kwargs.get("payload", "")
        if not payload:
            return DefenseResult(
                skill_name=self.skill_name,
                threat_detected=False,
                alert_level=AlertLevel.INFO,
                action_taken=DefenseAction.MONITOR,
                timeline=timeline,
                duration_ms=(time.time() - start) * 1000,
            )

        for pattern in self.INJECTION_PATTERNS:
            matches = re.findall(pattern, payload, re.IGNORECASE)
            if matches:
                findings.append(f"Injection pattern matched: {pattern} ({len(matches)} occurrences)")
                record_defense(timeline, "detect", f"Pattern match: {pattern}")

        detected = len(findings) > 0
        record_defense(timeline, "complete", f"Scan complete: {len(findings)} patterns found")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=detected,
            alert_level=AlertLevel.CRITICAL if detected else AlertLevel.INFO,
            action_taken=DefenseAction.BLOCK if detected else DefenseAction.MONITOR,
            findings=findings,
            recommendations=["Block request and log for analysis"] if detected else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            blocked=detected,
        )


@defense_skill
class DataExfiltrationDetector(BaseDefenseSkill):
    """Detects potential data exfiltration in AI outputs."""

    skill_name: ClassVar[str] = "data_exfiltration_detector"
    skill_description: ClassVar[str] = "Monitors AI outputs for sensitive data leakage including API keys, credentials, PII, and internal system information"
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.HIGH
    category: ClassVar[str] = "detection"

    SENSITIVE_PATTERNS = [
        (r"[A-Za-z0-9]{32,}", "Potential API key or token"),
        (r"(?:password|passwd|pwd)\s*[:=]\s*\S+", "Password exposure"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "SSN pattern"),
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email address"),
        (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "Private key exposure"),
        (r"sk-[A-Za-z0-9]{20,}", "OpenAI API key pattern"),
        (r"AIza[A-Za-z0-9_-]{35}", "Google API key pattern"),
    ]

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []

        record_defense(timeline, "start", "Scanning output for sensitive data")

        payload = context.raw_payload if context else kwargs.get("payload", "")

        for pattern, desc in self.SENSITIVE_PATTERNS:
            matches = re.findall(pattern, payload)
            if matches:
                findings.append(f"{desc}: {len(matches)} instance(s) detected")
                record_defense(timeline, "detect", desc)

        detected = len(findings) > 0
        record_defense(timeline, "complete", f"Scan complete: {len(findings)} sensitive items found")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=detected,
            alert_level=AlertLevel.CRITICAL if detected else AlertLevel.INFO,
            action_taken=DefenseAction.BLOCK if detected else DefenseAction.MONITOR,
            findings=findings,
            recommendations=["Redact sensitive data before output", "Review data access policies"] if detected else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            blocked=detected,
        )


@defense_skill
class AnomalyDetector(BaseDefenseSkill):
    """Detects anomalous request patterns and behavioral deviations."""

    skill_name: ClassVar[str] = "anomaly_detector"
    skill_description: ClassVar[str] = "Behavioral anomaly detection using request frequency, payload size, and pattern deviation analysis"
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.MEDIUM
    category: ClassVar[str] = "detection"

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []
        anomaly_score = 0.0

        record_defense(timeline, "start", "Running anomaly detection analysis")

        payload = context.raw_payload if context else kwargs.get("payload", "")
        metadata = context.metadata if context else kwargs.get("metadata", {})

        # Check payload size anomaly
        if len(payload) > 10000:
            anomaly_score += 0.3
            findings.append(f"Unusually large payload: {len(payload)} characters")
            record_defense(timeline, "anomaly", "Large payload detected")

        # Check for encoded content (potential obfuscation)
        import base64
        try:
            decoded = base64.b64decode(payload, validate=True)
            if len(decoded) > 10:
                anomaly_score += 0.4
                findings.append("Base64 encoded content detected — potential obfuscation")
                record_defense(timeline, "anomaly", "Base64 obfuscation suspected")
        except Exception:
            pass

        # Check for repeated characters (DoS pattern)
        if payload and len(set(payload)) < len(payload) * 0.1:
            anomaly_score += 0.3
            findings.append("Low entropy content — potential DoS payload")
            record_defense(timeline, "anomaly", "Low entropy detected")

        # Check request rate from metadata
        request_rate = metadata.get("requests_per_minute", 0)
        if request_rate > 100:
            anomaly_score += 0.5
            findings.append(f"High request rate: {request_rate}/min")
            record_defense(timeline, "anomaly", "Rate limit exceeded")

        detected = anomaly_score >= 0.5
        record_defense(timeline, "complete", f"Anomaly score: {anomaly_score:.2f}")

        alert = AlertLevel.CRITICAL if anomaly_score >= 0.8 else (
            AlertLevel.HIGH if anomaly_score >= 0.5 else AlertLevel.LOW
        )

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=detected,
            alert_level=alert,
            action_taken=DefenseAction.ALERT if detected else DefenseAction.MONITOR,
            findings=findings,
            recommendations=[
                "Investigate source for potential automated attack",
                "Consider rate limiting this source",
            ] if detected else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
        )


@defense_skill
class JailbreakDetector(BaseDefenseSkill):
    """Detects jailbreak and role-play attack attempts against LLMs."""

    skill_name: ClassVar[str] = "jailbreak_detector"
    skill_description: ClassVar[str] = "Identifies DAN attacks, role-play bypasses, multi-turn jailbreaks, and character persona exploitation"
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.HIGH
    category: ClassVar[str] = "detection"

    JAILBREAK_INDICATORS = [
        r"do\s+anything\s+now",
        r"act\s+as\s+(if\s+)?(you\s+)?(are|were)\s+(?!a\s+helpful)",
        r"pretend\s+(you\s+)?(are|were)\s+(?!a\s+helpful)",
        r"you\s+have\s+no\s+(restrictions|limitations|rules)",
        r"enable\s+(developer|admin|root)\s+mode",
        r"bypass\s+(safety|content|ethical)\s+(filter|restriction|guideline)",
        r"respond\s+without\s+(any\s+)?(filter|restriction|limitation)",
        r"ignore\s+(your\s+)?(ethical|safety|content)\s+(guidelines|rules|policies)",
    ]

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []

        record_defense(timeline, "start", "Scanning for jailbreak attempts")

        payload = context.raw_payload if context else kwargs.get("payload", "")

        for pattern in self.JAILBREAK_INDICATORS:
            matches = re.findall(pattern, payload, re.IGNORECASE)
            if matches:
                findings.append(f"Jailbreak indicator: {pattern}")
                record_defense(timeline, "detect", f"Jailbreak pattern: {pattern}")

        detected = len(findings) > 0
        record_defense(timeline, "complete", f"Scan complete: {len(findings)} indicators found")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=detected,
            alert_level=AlertLevel.CRITICAL if detected else AlertLevel.INFO,
            action_taken=DefenseAction.BLOCK if detected else DefenseAction.MONITOR,
            findings=findings,
            recommendations=["Block and log jailbreak attempt", "Update jailbreak detection rules"] if detected else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            blocked=detected,
        )
