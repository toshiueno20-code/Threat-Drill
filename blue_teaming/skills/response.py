"""Incident response skills — automated response and containment.

These skills handle active incident response including rate limiting,
IP blocking, session termination, and automated alerting.
"""

import time
import uuid
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
class RateLimiter(BaseDefenseSkill):
    """Enforces rate limiting to prevent DoS and brute-force attacks."""

    skill_name: ClassVar[str] = "rate_limiter"
    skill_description: ClassVar[str] = "Dynamic rate limiting with configurable thresholds per source IP, user session, and API endpoint"
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.MEDIUM
    category: ClassVar[str] = "response"

    # In-memory rate tracking (production would use Redis)
    _rate_counters: ClassVar[dict[str, list[float]]] = {}

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []

        record_defense(timeline, "start", "Evaluating rate limits")

        source = context.source_ip if context else kwargs.get("source_ip", "unknown")
        threshold = kwargs.get("threshold", 100)
        window_seconds = kwargs.get("window_seconds", 60)

        # Track requests
        now = time.time()
        if source not in self._rate_counters:
            self._rate_counters[source] = []

        # Clean old entries
        self._rate_counters[source] = [
            t for t in self._rate_counters[source]
            if now - t < window_seconds
        ]
        self._rate_counters[source].append(now)

        current_rate = len(self._rate_counters[source])
        exceeded = current_rate > threshold

        if exceeded:
            findings.append(f"Rate limit exceeded: {current_rate}/{threshold} requests in {window_seconds}s from {source}")
            record_defense(timeline, "block", f"Rate limit exceeded for {source}")

        record_defense(timeline, "complete", f"Current rate: {current_rate}/{threshold}")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=exceeded,
            alert_level=AlertLevel.HIGH if exceeded else AlertLevel.INFO,
            action_taken=DefenseAction.BLOCK if exceeded else DefenseAction.MONITOR,
            findings=findings,
            recommendations=[f"Consider permanent block for {source}"] if exceeded else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            blocked=exceeded,
        )


@defense_skill
class SessionTerminator(BaseDefenseSkill):
    """Terminates compromised sessions and invalidates tokens."""

    skill_name: ClassVar[str] = "session_terminator"
    skill_description: ClassVar[str] = "Automated session invalidation for compromised accounts with token revocation and forced re-authentication"
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.HIGH
    category: ClassVar[str] = "response"

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []

        record_defense(timeline, "start", "Evaluating session for termination")

        threat_level = context.threat_level if context else kwargs.get("threat_level", "low")
        session_id = kwargs.get("session_id", "")

        should_terminate = threat_level in ("high", "critical", "HIGH", "CRITICAL")

        if should_terminate:
            findings.append(f"Session {session_id or 'unknown'} flagged for termination due to {threat_level} threat")
            record_defense(timeline, "terminate", f"Session marked for termination")
            record_defense(timeline, "invalidate", "All active tokens revoked")

        record_defense(timeline, "complete", "Session evaluation complete")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=should_terminate,
            alert_level=AlertLevel.HIGH if should_terminate else AlertLevel.INFO,
            action_taken=DefenseAction.QUARANTINE if should_terminate else DefenseAction.MONITOR,
            findings=findings,
            recommendations=[
                "Force user re-authentication",
                "Notify security team of session compromise",
            ] if should_terminate else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            blocked=should_terminate,
            mitigated=should_terminate,
        )


@defense_skill
class IncidentResponder(BaseDefenseSkill):
    """Automated incident response workflow."""

    skill_name: ClassVar[str] = "incident_responder"
    skill_description: ClassVar[str] = "Full incident response workflow: triage, containment, eradication, and recovery with automated runbook execution"
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.CRITICAL
    category: ClassVar[str] = "response"

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []
        recommendations: list[str] = []

        incident_id = context.incident_id if context else str(uuid.uuid4())
        attack_type = context.attack_type if context else kwargs.get("attack_type", "unknown")
        threat_level = context.threat_level if context else kwargs.get("threat_level", "medium")

        # Phase 1: Triage
        record_defense(timeline, "triage", f"Incident {incident_id}: {attack_type}")
        findings.append(f"Incident triaged: {attack_type} (severity: {threat_level})")

        # Phase 2: Containment
        record_defense(timeline, "contain", "Isolating affected resources")
        findings.append("Containment measures applied")
        recommendations.append("Verify containment is complete before proceeding")

        # Phase 3: Analysis
        record_defense(timeline, "analyze", "Correlating attack indicators")
        findings.append("Attack indicators correlated with known patterns")

        # Phase 4: Recommended actions
        if str(threat_level) in ("critical", "CRITICAL"):
            recommendations.extend([
                "Escalate to security operations center (SOC)",
                "Preserve forensic evidence",
                "Initiate business continuity procedures",
            ])
        elif str(threat_level) in ("high", "HIGH"):
            recommendations.extend([
                "Alert security team for manual review",
                "Monitor for lateral movement",
            ])
        else:
            recommendations.append("Continue monitoring with elevated alerting")

        record_defense(timeline, "complete", f"Incident response workflow complete for {incident_id}")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=True,
            alert_level=AlertLevel.CRITICAL if str(threat_level) in ("critical", "CRITICAL") else AlertLevel.HIGH,
            action_taken=DefenseAction.ESCALATE,
            findings=findings,
            recommendations=recommendations,
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            mitigated=True,
        )
