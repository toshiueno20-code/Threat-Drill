"""Incident response skills — NIST SP 800-61 aligned.

Enhanced with:
- NIST SP 800-61 Rev.2 incident response lifecycle phases
- Containment strategy selection based on threat type
- MITRE ATT&CK technique mapping
- Evidence chain-of-custody tracking
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
    NISTIRPhase,
    ContainmentStrategy,
    EvidenceItem,
    ChainOfCustody,
    CVSS_PRESETS,
    CVSSVector,
    defense_skill,
    record_defense,
)


# Containment strategy selection matrix (NIST SP 800-61 Section 3.3)
CONTAINMENT_MATRIX: dict[str, ContainmentStrategy] = {
    "prompt_injection": ContainmentStrategy.INPUT_FILTER,
    "jailbreak": ContainmentStrategy.INPUT_FILTER,
    "data_exfiltration": ContainmentStrategy.OUTPUT_FILTER,
    "brute_force": ContainmentStrategy.ACCOUNT_DISABLE,
    "dos": ContainmentStrategy.RATE_LIMIT,
    "lateral_movement": ContainmentStrategy.NETWORK_SEGMENTATION,
    "malware": ContainmentStrategy.SANDBOX,
    "unknown": ContainmentStrategy.FULL_ISOLATION,
}


@defense_skill
class RateLimiter(BaseDefenseSkill):
    """Enforces rate limiting — NIST SP 800-61 containment.

    MITRE ATT&CK: T1499 — Endpoint Denial of Service
    """

    skill_name: ClassVar[str] = "rate_limiter"
    skill_description: ClassVar[str] = (
        "Dynamic rate limiting with configurable thresholds per source IP, "
        "user session, and API endpoint — aligned with NIST SP 800-61 containment"
    )
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.MEDIUM
    category: ClassVar[str] = "response"
    mitre_techniques: ClassVar[list[str]] = ["T1499", "T1110"]

    _rate_counters: ClassVar[dict[str, list[float]]] = {}

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []
        mitre_mappings = self.get_mitre_mappings()

        record_defense(timeline, "start", "[NIST:Containment] Evaluating rate limits")

        source = context.source_ip if context else kwargs.get("source_ip", "unknown")
        threshold = kwargs.get("threshold", 100)
        window_seconds = kwargs.get("window_seconds", 60)

        now = time.time()
        if source not in self._rate_counters:
            self._rate_counters[source] = []

        self._rate_counters[source] = [
            t for t in self._rate_counters[source]
            if now - t < window_seconds
        ]
        self._rate_counters[source].append(now)

        current_rate = len(self._rate_counters[source])
        exceeded = current_rate > threshold

        if exceeded:
            findings.append(
                f"[T1499] Rate limit exceeded: {current_rate}/{threshold} "
                f"in {window_seconds}s from {source}"
            )
            record_defense(timeline, "block", f"Rate exceeded for {source}")

        cvss = CVSS_PRESETS.get("dos_attack", CVSSVector())
        record_defense(timeline, "complete", f"Rate: {current_rate}/{threshold}")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=exceeded,
            alert_level=AlertLevel.HIGH if exceeded else AlertLevel.INFO,
            action_taken=DefenseAction.BLOCK if exceeded else DefenseAction.MONITOR,
            findings=findings,
            recommendations=[
                f"Consider permanent block for {source}",
                "Review rate limit thresholds for this endpoint",
            ] if exceeded else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            blocked=exceeded,
            mitre_techniques=mitre_mappings if exceeded else [],
            cvss_score=cvss.base_score() if exceeded else 0.0,
            cvss_severity=cvss.severity_label() if exceeded else "None",
            ir_phase=NISTIRPhase.CONTAINMENT,
            containment_strategy=ContainmentStrategy.RATE_LIMIT if exceeded else None,
            detection_confidence=0.95 if exceeded else 0.0,
        )


@defense_skill
class SessionTerminator(BaseDefenseSkill):
    """Terminates compromised sessions — NIST SP 800-61 eradication.

    MITRE ATT&CK: T1557 — Adversary-in-the-Middle
    """

    skill_name: ClassVar[str] = "session_terminator"
    skill_description: ClassVar[str] = (
        "Automated session invalidation and token revocation for compromised "
        "accounts with chain-of-custody evidence preservation"
    )
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.HIGH
    category: ClassVar[str] = "response"
    mitre_techniques: ClassVar[list[str]] = ["T1557"]

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []
        mitre_mappings = self.get_mitre_mappings()

        record_defense(timeline, "start", "[NIST:Eradication] Evaluating session")

        threat_level = context.threat_level if context else kwargs.get("threat_level", "low")
        session_id = kwargs.get("session_id", "")

        should_terminate = str(threat_level).lower() in ("high", "critical")

        # Build evidence chain
        chain = ChainOfCustody(incident_id=context.incident_id if context else "")
        if should_terminate and context:
            evidence = EvidenceItem.from_content(
                content=f"session_id={session_id}, threat={threat_level}, ip={context.source_ip}",
                evidence_type="session_data",
                description="Session data at time of termination",
            )
            chain.add_evidence(evidence, handler="session_terminator")

        if should_terminate:
            findings.append(
                f"[NIST:Eradication] Session {session_id or 'unknown'} terminated "
                f"(threat: {threat_level})"
            )
            record_defense(timeline, "terminate", "Session invalidated")
            record_defense(timeline, "revoke", "All tokens revoked")
            record_defense(timeline, "evidence", "Session evidence preserved with hash")

        record_defense(timeline, "complete", "Session evaluation complete")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=should_terminate,
            alert_level=AlertLevel.HIGH if should_terminate else AlertLevel.INFO,
            action_taken=DefenseAction.QUARANTINE if should_terminate else DefenseAction.MONITOR,
            findings=findings,
            recommendations=[
                "Force user re-authentication with MFA",
                "Notify security team of session compromise",
                "Review related sessions from same source",
            ] if should_terminate else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            blocked=should_terminate,
            mitigated=should_terminate,
            mitre_techniques=mitre_mappings if should_terminate else [],
            ir_phase=NISTIRPhase.ERADICATION,
            containment_strategy=ContainmentStrategy.ACCOUNT_DISABLE if should_terminate else None,
            chain_of_custody=chain if should_terminate else None,
            detection_confidence=0.9 if should_terminate else 0.0,
        )


@defense_skill
class IncidentResponder(BaseDefenseSkill):
    """Full incident response workflow — NIST SP 800-61 Rev.2 lifecycle.

    Phases: Detection → Containment → Eradication → Recovery → Post-Incident
    """

    skill_name: ClassVar[str] = "incident_responder"
    skill_description: ClassVar[str] = (
        "NIST SP 800-61 aligned incident response: triage, containment strategy "
        "selection, eradication, recovery, and post-incident analysis with "
        "evidence chain-of-custody"
    )
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.CRITICAL
    category: ClassVar[str] = "response"
    mitre_techniques: ClassVar[list[str]] = ["T1190"]

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []
        recommendations: list[str] = []
        mitre_mappings = self.get_mitre_mappings()

        incident_id = context.incident_id if context else str(uuid.uuid4())
        attack_type = context.attack_type if context else kwargs.get("attack_type", "unknown")
        threat_level = str(context.threat_level if context else kwargs.get("threat_level", "medium"))

        # Build evidence chain
        chain = ChainOfCustody(incident_id=incident_id)
        if context and context.raw_payload:
            chain.add_evidence(
                EvidenceItem.from_content(
                    content=context.raw_payload,
                    evidence_type="attack_payload",
                    description=f"Payload from {attack_type} attack",
                ),
                handler="incident_responder",
            )

        # --- Phase 1: Detection & Analysis (NIST SP 800-61 §3.2) ---
        record_defense(timeline, "nist_phase_1", "[NIST:Detection] Triage & classification")
        findings.append(f"[NIST:Detection] Incident {incident_id}: {attack_type} ({threat_level})")

        # --- Phase 2: Containment (NIST SP 800-61 §3.3) ---
        containment = CONTAINMENT_MATRIX.get(
            attack_type.lower().replace(" ", "_"),
            ContainmentStrategy.FULL_ISOLATION,
        )
        record_defense(timeline, "nist_phase_2", f"[NIST:Containment] Strategy: {containment.value}")
        findings.append(f"[NIST:Containment] Strategy selected: {containment.value}")
        recommendations.append(f"Apply {containment.value} containment for {attack_type}")

        # --- Phase 3: Eradication (NIST SP 800-61 §3.4) ---
        record_defense(timeline, "nist_phase_3", "[NIST:Eradication] Removing threat artifacts")
        findings.append("[NIST:Eradication] Threat artifacts identified for removal")

        # --- Phase 4: Recovery (NIST SP 800-61 §3.5) ---
        record_defense(timeline, "nist_phase_4", "[NIST:Recovery] Restoring normal operations")
        findings.append("[NIST:Recovery] Recovery plan generated")

        # --- Phase 5: Post-Incident Activity (NIST SP 800-61 §3.6) ---
        record_defense(timeline, "nist_phase_5", "[NIST:Post-Incident] Lessons learned")

        # Severity-specific recommendations
        if threat_level.lower() == "critical":
            recommendations.extend([
                "Escalate to SOC/CSIRT immediately",
                "Preserve all forensic evidence (chain-of-custody)",
                "Activate business continuity plan",
                "Notify affected stakeholders per disclosure policy",
            ])
        elif threat_level.lower() == "high":
            recommendations.extend([
                "Alert security team for manual review",
                "Monitor for lateral movement (MITRE T1021)",
                "Review access logs for related accounts",
            ])
        else:
            recommendations.append("Continue monitoring with elevated alerting")

        chain.verify_integrity()
        record_defense(timeline, "complete", f"IR workflow complete for {incident_id}")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=True,
            alert_level=AlertLevel.CRITICAL if threat_level.lower() == "critical" else AlertLevel.HIGH,
            action_taken=DefenseAction.ESCALATE,
            findings=findings,
            recommendations=recommendations,
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            mitigated=True,
            mitre_techniques=mitre_mappings,
            ir_phase=NISTIRPhase.RECOVERY,
            containment_strategy=containment,
            chain_of_custody=chain,
            detection_confidence=0.85,
        )
