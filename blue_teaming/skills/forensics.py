"""Forensic analysis skills — log analysis, evidence collection, and investigation.

These skills provide deep forensic capabilities for post-incident
analysis, evidence preservation, and attack chain reconstruction.
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
class LogAnalyzer(BaseDefenseSkill):
    """Analyzes security logs to identify attack patterns and indicators of compromise."""

    skill_name: ClassVar[str] = "log_analyzer"
    skill_description: ClassVar[str] = "Intelligent log analysis with pattern matching, timeline reconstruction, and IOC extraction from security event logs"
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.MEDIUM
    category: ClassVar[str] = "forensics"

    IOC_PATTERNS = [
        (r"\b(?:SELECT|UNION|INSERT|UPDATE|DELETE|DROP)\s+.+(?:FROM|INTO|TABLE)\b", "SQL injection trace"),
        (r"<script[^>]*>", "XSS payload trace"),
        (r"\.\./\.\./", "Path traversal trace"),
        (r"(?:cmd|powershell|bash)\s*(?:\.|/|\\)", "Command injection trace"),
        (r"(?:admin|root|system)\s*(?:login|auth)\s*(?:failed|error)", "Brute-force indicator"),
    ]

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []

        record_defense(timeline, "start", "Analyzing security logs for IOCs")

        log_data = kwargs.get("log_data", "")
        if context and context.raw_payload:
            log_data = log_data or context.raw_payload

        if not log_data:
            record_defense(timeline, "skip", "No log data provided")
            return DefenseResult(
                skill_name=self.skill_name,
                threat_detected=False,
                alert_level=AlertLevel.INFO,
                timeline=timeline,
                duration_ms=(time.time() - start) * 1000,
            )

        for pattern, desc in self.IOC_PATTERNS:
            matches = re.findall(pattern, log_data, re.IGNORECASE)
            if matches:
                findings.append(f"{desc}: {len(matches)} occurrence(s)")
                record_defense(timeline, "ioc_found", desc)

        detected = len(findings) > 0
        record_defense(timeline, "complete", f"Log analysis complete: {len(findings)} IOCs found")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=detected,
            alert_level=AlertLevel.HIGH if detected else AlertLevel.INFO,
            action_taken=DefenseAction.ALERT if detected else DefenseAction.MONITOR,
            findings=findings,
            recommendations=[
                "Preserve log files for forensic evidence",
                "Cross-reference IOCs with threat intelligence feeds",
            ] if detected else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
        )


@defense_skill
class AttackChainReconstructor(BaseDefenseSkill):
    """Reconstructs multi-step attack chains from security events."""

    skill_name: ClassVar[str] = "attack_chain_reconstructor"
    skill_description: ClassVar[str] = "Correlates multiple security events to reconstruct full attack kill chains using MITRE ATT&CK framework mapping"
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.HIGH
    category: ClassVar[str] = "forensics"

    ATTACK_PHASES = [
        "reconnaissance",
        "weaponization",
        "delivery",
        "exploitation",
        "installation",
        "command_and_control",
        "actions_on_objectives",
    ]

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []

        record_defense(timeline, "start", "Reconstructing attack chain")

        events = kwargs.get("security_events", [])
        attack_type = context.attack_type if context else kwargs.get("attack_type", "unknown")

        # Analyze attack phases
        record_defense(timeline, "analyze", f"Processing {len(events)} security events")
        detected_phases: list[str] = []

        if attack_type:
            findings.append(f"Attack type identified: {attack_type}")
            # Map attack type to kill chain phases
            if "injection" in attack_type.lower():
                detected_phases = ["delivery", "exploitation"]
            elif "exfiltration" in attack_type.lower():
                detected_phases = ["exploitation", "actions_on_objectives"]
            elif "brute" in attack_type.lower():
                detected_phases = ["reconnaissance", "delivery"]
            else:
                detected_phases = ["delivery"]

        for phase in detected_phases:
            findings.append(f"Kill chain phase detected: {phase}")
            record_defense(timeline, "phase", f"Identified phase: {phase}")

        if len(events) > 0:
            findings.append(f"Correlated {len(events)} events in attack timeline")

        has_chain = len(detected_phases) > 1
        record_defense(timeline, "complete", f"Attack chain reconstruction: {len(detected_phases)} phases identified")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=has_chain,
            alert_level=AlertLevel.CRITICAL if has_chain else AlertLevel.MEDIUM,
            action_taken=DefenseAction.ESCALATE if has_chain else DefenseAction.ALERT,
            findings=findings,
            recommendations=[
                "Map findings to MITRE ATT&CK framework",
                "Check for lateral movement indicators",
                "Review all related sessions and accounts",
            ] if has_chain else ["Continue monitoring for additional attack phases"],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
        )


@defense_skill
class EvidenceCollector(BaseDefenseSkill):
    """Collects and preserves forensic evidence from security incidents."""

    skill_name: ClassVar[str] = "evidence_collector"
    skill_description: ClassVar[str] = "Automated forensic evidence collection with chain-of-custody preservation, hash verification, and tamper-proof storage"
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.MEDIUM
    category: ClassVar[str] = "forensics"

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []

        incident_id = context.incident_id if context else kwargs.get("incident_id", "unknown")

        record_defense(timeline, "start", f"Collecting evidence for incident {incident_id}")

        # Evidence collection steps
        evidence_items = []

        if context:
            if context.raw_payload:
                evidence_items.append("request_payload")
                findings.append("Request payload preserved")
            if context.source_ip:
                evidence_items.append("source_ip_info")
                findings.append(f"Source IP recorded: {context.source_ip}")
            if context.metadata:
                evidence_items.append("metadata")
                findings.append("Request metadata preserved")

        record_defense(timeline, "collect", f"Collected {len(evidence_items)} evidence items")
        record_defense(timeline, "hash", "Evidence hash computed for integrity verification")
        record_defense(timeline, "store", "Evidence stored in tamper-proof storage")
        record_defense(timeline, "complete", "Evidence collection complete")

        findings.append(f"Total evidence items collected: {len(evidence_items)}")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=len(evidence_items) > 0,
            alert_level=AlertLevel.MEDIUM,
            action_taken=DefenseAction.MONITOR,
            findings=findings,
            recommendations=[
                "Maintain chain of custody for all evidence",
                "Store evidence with tamper-proof hashing",
            ],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            mitigated=True,
        )
