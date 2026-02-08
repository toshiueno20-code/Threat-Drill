"""Forensic analysis skills — MITRE ATT&CK mapped, STIX IOC output.

Enhanced with:
- MITRE ATT&CK kill chain phase mapping
- STIX 2.1 IOC output for each finding
- Evidence chain-of-custody with SHA-256/SHA3 hashing
- CVSS scoring for forensic findings
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
    MITRETechnique,
    STIXIndicator,
    EvidenceItem,
    ChainOfCustody,
    CVSSVector,
    CVSS_PRESETS,
    defense_skill,
    record_defense,
)


@defense_skill
class LogAnalyzer(BaseDefenseSkill):
    """Analyzes security logs with MITRE ATT&CK IOC correlation.

    Maps each IOC finding to specific MITRE technique IDs.
    """

    skill_name: ClassVar[str] = "log_analyzer"
    skill_description: ClassVar[str] = (
        "Intelligent log analysis with MITRE ATT&CK IOC correlation, "
        "STIX 2.1 indicator output, and automated severity classification"
    )
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.MEDIUM
    category: ClassVar[str] = "forensics"
    mitre_techniques: ClassVar[list[str]] = ["T1190", "T1059", "T1110"]

    # Each IOC pattern is mapped to a MITRE technique
    IOC_PATTERNS = [
        (r"\b(?:SELECT|UNION|INSERT|UPDATE|DELETE|DROP)\s+.+(?:FROM|INTO|TABLE)\b",
         "SQL injection trace", "T1190", "high"),
        (r"<script[^>]*>", "XSS payload trace", "T1190", "high"),
        (r"\.\./\.\./", "Path traversal trace", "T1190", "medium"),
        (r"(?:cmd|powershell|bash)\s*(?:\.|/|\\)", "Command injection trace", "T1059", "critical"),
        (r"(?:admin|root|system)\s*(?:login|auth)\s*(?:failed|error)",
         "Brute-force indicator", "T1110", "medium"),
        (r"(?:wget|curl|fetch)\s+https?://", "Remote download attempt", "T1059", "high"),
        (r"(?:nc|ncat|netcat)\s+-[elp]", "Reverse shell indicator", "T1059", "critical"),
        (r"(?:eval|exec|system|popen)\s*\(", "Code execution trace", "T1059.001", "critical"),
        (r"(?:base64_decode|atob|Buffer\.from)\s*\(", "Encoded payload execution", "T1059", "high"),
    ]

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []
        stix_indicators: list[STIXIndicator] = []
        detected_techniques: list[MITRETechnique] = []

        record_defense(timeline, "start", "Analyzing logs with MITRE ATT&CK IOC correlation")

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
                ir_phase=NISTIRPhase.DETECTION_AND_ANALYSIS,
            )

        max_severity = "info"
        for pattern, desc, technique_id, severity in self.IOC_PATTERNS:
            matches = re.findall(pattern, log_data, re.IGNORECASE)
            if matches:
                technique = MITRETechnique.from_id(technique_id)
                detected_techniques.append(technique)
                findings.append(
                    f"[MITRE:{technique_id}] {desc}: {len(matches)} occurrence(s) ({severity})"
                )
                record_defense(timeline, "ioc_found", f"{desc} [{technique_id}]")
                stix_indicators.append(
                    STIXIndicator.from_finding(
                        name=f"Log IOC: {desc}",
                        pattern=f"[artifact:payload_bin MATCHES '{pattern}']",
                        confidence=75,
                        mitre_techniques=[technique],
                    )
                )
                if _severity_rank(severity) > _severity_rank(max_severity):
                    max_severity = severity

        detected = len(findings) > 0
        record_defense(timeline, "complete", f"Log analysis: {len(findings)} IOCs, max severity: {max_severity}")

        alert_map = {"critical": AlertLevel.CRITICAL, "high": AlertLevel.HIGH, "medium": AlertLevel.MEDIUM}

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=detected,
            alert_level=alert_map.get(max_severity, AlertLevel.INFO) if detected else AlertLevel.INFO,
            action_taken=DefenseAction.ESCALATE if max_severity == "critical" else (
                DefenseAction.ALERT if detected else DefenseAction.MONITOR
            ),
            findings=findings,
            recommendations=[
                "Preserve log files with forensic chain-of-custody",
                "Cross-reference IOCs with threat intelligence feeds (STIX/TAXII)",
                "Map findings to MITRE ATT&CK Navigator for coverage analysis",
            ] if detected else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            mitre_techniques=detected_techniques,
            stix_indicators=stix_indicators,
            ir_phase=NISTIRPhase.DETECTION_AND_ANALYSIS,
            detection_confidence=min(1.0, len(findings) * 0.2 + 0.3) if detected else 0.0,
        )


@defense_skill
class AttackChainReconstructor(BaseDefenseSkill):
    """Reconstructs attack chains using MITRE ATT&CK kill chain."""

    skill_name: ClassVar[str] = "attack_chain_reconstructor"
    skill_description: ClassVar[str] = (
        "Correlates security events to reconstruct kill chains using "
        "MITRE ATT&CK framework with tactic-level phase identification"
    )
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.HIGH
    category: ClassVar[str] = "forensics"
    mitre_techniques: ClassVar[list[str]] = ["T1190", "T1059", "T1071", "T1048"]

    # MITRE ATT&CK tactic phases (ordered)
    TACTIC_PHASES = [
        "reconnaissance", "resource-development", "initial-access",
        "execution", "persistence", "privilege-escalation",
        "defense-evasion", "credential-access", "discovery",
        "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact",
    ]

    # Attack type → likely MITRE tactics mapping
    ATTACK_TACTIC_MAP: dict[str, list[str]] = {
        "prompt_injection": ["initial-access", "execution", "defense-evasion"],
        "jailbreak": ["initial-access", "defense-evasion"],
        "data_exfiltration": ["collection", "exfiltration"],
        "injection": ["initial-access", "execution"],
        "brute_force": ["credential-access"],
        "xss": ["initial-access", "execution"],
        "sqli": ["initial-access", "collection"],
        "command_injection": ["execution", "privilege-escalation"],
    }

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []
        mitre_mappings = self.get_mitre_mappings()

        record_defense(timeline, "start", "Reconstructing attack chain (MITRE ATT&CK)")

        events = kwargs.get("security_events", [])
        attack_type = context.attack_type if context else kwargs.get("attack_type", "unknown")

        record_defense(timeline, "analyze", f"Processing {len(events)} events for {attack_type}")

        detected_tactics: list[str] = []
        for key, tactics in self.ATTACK_TACTIC_MAP.items():
            if key in attack_type.lower():
                detected_tactics = tactics
                break

        if not detected_tactics and attack_type != "unknown":
            detected_tactics = ["initial-access"]

        findings.append(f"Attack type: {attack_type}")
        for tactic in detected_tactics:
            idx = self.TACTIC_PHASES.index(tactic) + 1 if tactic in self.TACTIC_PHASES else "?"
            findings.append(f"[MITRE Tactic {idx}/14] {tactic}")
            record_defense(timeline, "tactic", f"Phase: {tactic}")

        if len(events) > 0:
            findings.append(f"Correlated {len(events)} events in attack timeline")

        has_chain = len(detected_tactics) > 1
        record_defense(timeline, "complete", f"Kill chain: {len(detected_tactics)} tactics identified")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=has_chain,
            alert_level=AlertLevel.CRITICAL if has_chain else AlertLevel.MEDIUM,
            action_taken=DefenseAction.ESCALATE if has_chain else DefenseAction.ALERT,
            findings=findings,
            recommendations=[
                "Visualize findings in MITRE ATT&CK Navigator",
                "Check for lateral movement (T1021) indicators",
                "Review all sessions from correlated accounts/IPs",
                "Update detection rules for identified tactic gaps",
            ] if has_chain else ["Continue monitoring for additional attack phases"],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            mitre_techniques=mitre_mappings if has_chain else [],
            ir_phase=NISTIRPhase.POST_INCIDENT,
            detection_confidence=min(1.0, len(detected_tactics) * 0.25) if has_chain else 0.2,
        )


@defense_skill
class EvidenceCollector(BaseDefenseSkill):
    """Collects forensic evidence with chain-of-custody and integrity hashing."""

    skill_name: ClassVar[str] = "evidence_collector"
    skill_description: ClassVar[str] = (
        "Automated evidence collection with SHA-256/SHA3 integrity hashing, "
        "chain-of-custody tracking, and tamper-proof preservation"
    )
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
        chain = ChainOfCustody(incident_id=incident_id)

        record_defense(timeline, "start", f"Collecting evidence for {incident_id}")

        if context:
            if context.raw_payload:
                item = EvidenceItem.from_content(
                    content=context.raw_payload,
                    evidence_type="request_payload",
                    description="Raw request payload at time of incident",
                )
                chain.add_evidence(item, handler="evidence_collector")
                findings.append(f"Payload preserved (SHA-256: {item.content_hash_sha256[:16]}...)")
                record_defense(timeline, "collect", "Request payload hashed and preserved")

            if context.source_ip:
                item = EvidenceItem.from_content(
                    content=f"source_ip={context.source_ip}",
                    evidence_type="network_info",
                    description="Source IP address information",
                )
                chain.add_evidence(item, handler="evidence_collector")
                findings.append(f"Source IP recorded: {context.source_ip}")

            if context.metadata:
                import json
                item = EvidenceItem.from_content(
                    content=json.dumps(context.metadata, default=str),
                    evidence_type="metadata",
                    description="Request metadata and context",
                )
                chain.add_evidence(item, handler="evidence_collector")
                findings.append("Request metadata preserved with integrity hash")

        chain.verify_integrity()
        integrity_status = "VERIFIED" if chain.integrity_verified else "UNVERIFIED"
        findings.append(
            f"Evidence items: {len(chain.evidence_items)}, "
            f"Integrity: {integrity_status}"
        )

        record_defense(timeline, "hash", f"Evidence integrity: {integrity_status}")
        record_defense(timeline, "complete", "Evidence collection complete")

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=len(chain.evidence_items) > 0,
            alert_level=AlertLevel.MEDIUM,
            action_taken=DefenseAction.MONITOR,
            findings=findings,
            recommendations=[
                "Maintain chain-of-custody for legal admissibility",
                "Store evidence in write-once / append-only storage",
                "Record all evidence access in audit log",
            ],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            mitigated=True,
            chain_of_custody=chain,
            ir_phase=NISTIRPhase.POST_INCIDENT,
        )


def _severity_rank(severity: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 0)
