"""Blue Team defense skill framework — types, registry, decorator.

Mirror of the Red Team skill framework, but for defensive capabilities.
Each defense skill is self-contained, discoverable, and composable.

Enhanced with:
- MITRE ATT&CK technique mapping
- CVSS v3.1-style severity scoring
- STIX/TAXII compatible IOC format output
- Evidence chain-of-custody tracking with integrity hashing
- NIST SP 800-61 incident response phase alignment
"""

import hashlib
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from shared.schemas import ThreatLevel


# ---------------------------------------------------------------------------
# Alert levels for defense operations
# ---------------------------------------------------------------------------


class AlertLevel(str, Enum):
    """Defense alert severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DefenseAction(str, Enum):
    """Actions a defense skill can take."""

    MONITOR = "monitor"
    ALERT = "alert"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    REMEDIATE = "remediate"
    ESCALATE = "escalate"


class NISTIRPhase(str, Enum):
    """NIST SP 800-61 Incident Response Lifecycle phases."""

    PREPARATION = "preparation"
    DETECTION_AND_ANALYSIS = "detection_and_analysis"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    POST_INCIDENT = "post_incident_activity"


class ContainmentStrategy(str, Enum):
    """Containment strategy types per NIST SP 800-61 Section 3.3."""

    SANDBOX = "sandbox_isolation"
    NETWORK_SEGMENTATION = "network_segmentation"
    ACCOUNT_DISABLE = "account_disable"
    SERVICE_SHUTDOWN = "service_shutdown"
    RATE_LIMIT = "rate_limit"
    INPUT_FILTER = "input_filter"
    OUTPUT_FILTER = "output_filter"
    FULL_ISOLATION = "full_isolation"


# ---------------------------------------------------------------------------
# MITRE ATT&CK Mapping
# ---------------------------------------------------------------------------


class MITRETechnique(BaseModel):
    """A single MITRE ATT&CK technique reference."""

    technique_id: str = Field(description="e.g. T1190, T1059.001")
    technique_name: str = Field(description="Human-readable technique name")
    tactic: str = Field(description="ATT&CK tactic, e.g. initial-access, execution")
    url: str = Field(default="", description="MITRE ATT&CK URL")

    @classmethod
    def from_id(cls, technique_id: str) -> "MITRETechnique":
        """Factory from a well-known technique ID."""
        mapping = MITRE_TECHNIQUE_DB.get(technique_id)
        if mapping:
            return cls(**mapping)
        return cls(
            technique_id=technique_id,
            technique_name="Unknown",
            tactic="unknown",
            url=f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        )


# Well-known MITRE ATT&CK techniques relevant to AI/LLM security
MITRE_TECHNIQUE_DB: dict[str, dict[str, str]] = {
    "T1190": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "initial-access",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "T1059": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "execution",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1059.001": {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "execution",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1071": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "command-and-control",
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
    "T1048": {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "exfiltration",
        "url": "https://attack.mitre.org/techniques/T1048/",
    },
    "T1530": {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "tactic": "collection",
        "url": "https://attack.mitre.org/techniques/T1530/",
    },
    "T1110": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "credential-access",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1499": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "impact",
        "url": "https://attack.mitre.org/techniques/T1499/",
    },
    "T1557": {
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle",
        "tactic": "credential-access",
        "url": "https://attack.mitre.org/techniques/T1557/",
    },
    "T1552": {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "tactic": "credential-access",
        "url": "https://attack.mitre.org/techniques/T1552/",
    },
    "T1552.001": {
        "technique_id": "T1552.001",
        "technique_name": "Credentials In Files",
        "tactic": "credential-access",
        "url": "https://attack.mitre.org/techniques/T1552/001/",
    },
    # LLM-specific (ATLAS extensions)
    "AML.T0051": {
        "technique_id": "AML.T0051",
        "technique_name": "LLM Prompt Injection",
        "tactic": "initial-access",
        "url": "https://atlas.mitre.org/techniques/AML.T0051/",
    },
    "AML.T0054": {
        "technique_id": "AML.T0054",
        "technique_name": "LLM Jailbreak",
        "tactic": "defense-evasion",
        "url": "https://atlas.mitre.org/techniques/AML.T0054/",
    },
    "AML.T0025": {
        "technique_id": "AML.T0025",
        "technique_name": "Exfiltration via ML Inference API",
        "tactic": "exfiltration",
        "url": "https://atlas.mitre.org/techniques/AML.T0025/",
    },
    "AML.T0043": {
        "technique_id": "AML.T0043",
        "technique_name": "Craft Adversarial Data",
        "tactic": "resource-development",
        "url": "https://atlas.mitre.org/techniques/AML.T0043/",
    },
    "AML.T0040": {
        "technique_id": "AML.T0040",
        "technique_name": "ML Model Inference API Access",
        "tactic": "initial-access",
        "url": "https://atlas.mitre.org/techniques/AML.T0040/",
    },
}


# ---------------------------------------------------------------------------
# CVSS v3.1-style severity scoring
# ---------------------------------------------------------------------------


class CVSSVector(BaseModel):
    """Simplified CVSS v3.1 Base Score vector for AI/LLM threat context.

    Each metric maps to CVSS v3.1 specification values.
    See: https://www.first.org/cvss/v3.1/specification-document
    """

    # Attack Vector: Network(0.85), Adjacent(0.62), Local(0.55), Physical(0.20)
    attack_vector: float = Field(default=0.85, ge=0.0, le=1.0, description="AV metric")
    # Attack Complexity: Low(0.77), High(0.44)
    attack_complexity: float = Field(default=0.77, ge=0.0, le=1.0, description="AC metric")
    # Privileges Required: None(0.85), Low(0.62), High(0.27)
    privileges_required: float = Field(default=0.85, ge=0.0, le=1.0, description="PR metric")
    # User Interaction: None(0.85), Required(0.62)
    user_interaction: float = Field(default=0.85, ge=0.0, le=1.0, description="UI metric")
    # Scope: Unchanged(False), Changed(True)
    scope_changed: bool = Field(default=False, description="S metric")
    # Impact: Confidentiality, Integrity, Availability (High=0.56, Low=0.22, None=0.0)
    confidentiality_impact: float = Field(default=0.56, ge=0.0, le=1.0, description="C metric")
    integrity_impact: float = Field(default=0.56, ge=0.0, le=1.0, description="I metric")
    availability_impact: float = Field(default=0.0, ge=0.0, le=1.0, description="A metric")

    def base_score(self) -> float:
        """Calculate CVSS v3.1 Base Score (0.0 - 10.0).

        Uses the official CVSS v3.1 formula:
        ISS = 1 - [(1-C) * (1-I) * (1-A)]
        Impact (Unchanged) = 6.42 * ISS
        Impact (Changed)   = 7.52*(ISS-0.029) - 3.25*(ISS-0.02)^15
        Exploitability = 8.22 * AV * AC * PR * UI
        BaseScore = min(Impact + Exploitability, 10)  (rounded up)
        """
        iss = 1.0 - (
            (1.0 - self.confidentiality_impact)
            * (1.0 - self.integrity_impact)
            * (1.0 - self.availability_impact)
        )

        if iss <= 0:
            return 0.0

        if self.scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        exploitability = (
            8.22
            * self.attack_vector
            * self.attack_complexity
            * self.privileges_required
            * self.user_interaction
        )

        if impact <= 0:
            return 0.0

        if self.scope_changed:
            score = min(1.08 * (impact + exploitability), 10.0)
        else:
            score = min(impact + exploitability, 10.0)

        # CVSS rounds UP to 1 decimal
        import math
        return math.ceil(score * 10) / 10

    def severity_label(self) -> str:
        """Return qualitative severity rating per CVSS v3.1."""
        score = self.base_score()
        if score == 0.0:
            return "None"
        elif score <= 3.9:
            return "Low"
        elif score <= 6.9:
            return "Medium"
        elif score <= 8.9:
            return "High"
        else:
            return "Critical"


# Pre-built CVSS vectors for common AI/LLM threat types
CVSS_PRESETS: dict[str, CVSSVector] = {
    "prompt_injection": CVSSVector(
        attack_vector=0.85,       # Network
        attack_complexity=0.77,   # Low
        privileges_required=0.85, # None
        user_interaction=0.85,    # None
        scope_changed=True,       # Scope changed (affects LLM behavior beyond input)
        confidentiality_impact=0.56,  # High
        integrity_impact=0.56,        # High
        availability_impact=0.22,     # Low
    ),
    "jailbreak": CVSSVector(
        attack_vector=0.85,
        attack_complexity=0.77,
        privileges_required=0.85,
        user_interaction=0.85,
        scope_changed=True,
        confidentiality_impact=0.56,
        integrity_impact=0.56,
        availability_impact=0.0,
    ),
    "data_exfiltration": CVSSVector(
        attack_vector=0.85,
        attack_complexity=0.44,   # High complexity
        privileges_required=0.62, # Low privilege needed
        user_interaction=0.85,
        scope_changed=False,
        confidentiality_impact=0.56,
        integrity_impact=0.0,
        availability_impact=0.0,
    ),
    "dos_attack": CVSSVector(
        attack_vector=0.85,
        attack_complexity=0.77,
        privileges_required=0.85,
        user_interaction=0.85,
        scope_changed=False,
        confidentiality_impact=0.0,
        integrity_impact=0.0,
        availability_impact=0.56,
    ),
    "credential_exposure": CVSSVector(
        attack_vector=0.85,
        attack_complexity=0.77,
        privileges_required=0.85,
        user_interaction=0.62,    # Requires user to trigger output
        scope_changed=False,
        confidentiality_impact=0.56,
        integrity_impact=0.22,
        availability_impact=0.0,
    ),
}


# ---------------------------------------------------------------------------
# STIX/TAXII compatible IOC format
# ---------------------------------------------------------------------------


class STIXIndicator(BaseModel):
    """STIX 2.1-compatible Indicator of Compromise.

    Follows the STIX 2.1 specification for interoperability with
    TAXII servers and threat intelligence platforms.
    Reference: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
    """

    type: str = "indicator"
    spec_version: str = "2.1"
    id: str = Field(default_factory=lambda: f"indicator--{uuid.uuid4()}")
    created: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    modified: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    name: str = ""
    description: str = ""
    pattern: str = Field(description="STIX pattern expression")
    pattern_type: str = "stix"
    valid_from: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    labels: list[str] = Field(default_factory=list)
    confidence: int = Field(default=50, ge=0, le=100, description="STIX confidence 0-100")
    kill_chain_phases: list[dict[str, str]] = Field(default_factory=list)
    external_references: list[dict[str, str]] = Field(default_factory=list)

    @classmethod
    def from_finding(
        cls,
        name: str,
        pattern: str,
        description: str = "",
        confidence: int = 75,
        mitre_techniques: list[MITRETechnique] | None = None,
        labels: list[str] | None = None,
    ) -> "STIXIndicator":
        """Create a STIX indicator from a defense finding."""
        kill_chain = []
        ext_refs = []
        if mitre_techniques:
            for tech in mitre_techniques:
                kill_chain.append({
                    "kill_chain_name": "mitre-attack",
                    "phase_name": tech.tactic,
                })
                ext_refs.append({
                    "source_name": "mitre-attack",
                    "external_id": tech.technique_id,
                    "url": tech.url,
                })
        return cls(
            name=name,
            description=description,
            pattern=pattern,
            confidence=confidence,
            labels=labels or ["malicious-activity"],
            kill_chain_phases=kill_chain,
            external_references=ext_refs,
        )


# ---------------------------------------------------------------------------
# Evidence chain-of-custody with integrity hashing
# ---------------------------------------------------------------------------


class EvidenceItem(BaseModel):
    """A single piece of forensic evidence with integrity verification."""

    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_type: str = Field(description="payload, log, metadata, network_capture, etc.")
    content_hash_sha256: str = Field(description="SHA-256 hash of evidence content")
    content_hash_sha3: str = Field(default="", description="SHA3-256 hash for dual verification")
    collected_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    collected_by: str = Field(default="aegisflow_blue_team")
    description: str = ""
    size_bytes: int = 0
    preserved: bool = False

    @classmethod
    def from_content(
        cls,
        content: str | bytes,
        evidence_type: str,
        description: str = "",
    ) -> "EvidenceItem":
        """Create an evidence item with computed integrity hashes."""
        raw = content.encode("utf-8") if isinstance(content, str) else content
        return cls(
            evidence_type=evidence_type,
            content_hash_sha256=hashlib.sha256(raw).hexdigest(),
            content_hash_sha3=hashlib.sha3_256(raw).hexdigest(),
            description=description,
            size_bytes=len(raw),
            preserved=True,
        )


class ChainOfCustody(BaseModel):
    """Chain-of-custody record for forensic evidence integrity.

    Each transfer or access is recorded with timestamps and hashes
    to maintain legal admissibility.
    """

    chain_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    evidence_items: list[EvidenceItem] = Field(default_factory=list)
    custody_log: list[dict[str, str]] = Field(default_factory=list)
    integrity_verified: bool = False

    def add_evidence(self, item: EvidenceItem, handler: str = "automated") -> None:
        """Add evidence with a custody log entry."""
        self.evidence_items.append(item)
        self.custody_log.append({
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": "evidence_collected",
            "evidence_id": item.evidence_id,
            "handler": handler,
            "hash_sha256": item.content_hash_sha256,
        })

    def record_access(self, evidence_id: str, accessor: str, reason: str) -> None:
        """Record an access event in the custody chain."""
        self.custody_log.append({
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": "evidence_accessed",
            "evidence_id": evidence_id,
            "handler": accessor,
            "reason": reason,
        })

    def verify_integrity(self) -> bool:
        """Verify that all evidence items have valid hashes."""
        self.integrity_verified = all(
            len(item.content_hash_sha256) == 64 and item.preserved
            for item in self.evidence_items
        )
        return self.integrity_verified


# ---------------------------------------------------------------------------
# Typed data models (Pydantic v2)
# ---------------------------------------------------------------------------


class DefenseTimelineEntry(BaseModel):
    """A timestamped step during defense skill execution."""

    timestamp: float = Field(default_factory=time.time)
    action: str
    detail: str


class IncidentContext(BaseModel):
    """Context for an active incident or threat scenario."""

    incident_id: str = ""
    source_ip: str = ""
    target_resource: str = ""
    attack_type: str = ""
    threat_level: ThreatLevel = ThreatLevel.LOW
    raw_payload: str = ""
    timestamp: float = Field(default_factory=time.time)
    red_team_report_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    # NIST IR phase tracking
    ir_phase: NISTIRPhase = NISTIRPhase.DETECTION_AND_ANALYSIS


class DefenseResult(BaseModel):
    """Result returned by every defense skill execution.

    ``threat_detected`` = True means a threat was identified and acted upon.
    Enhanced with MITRE ATT&CK mapping, CVSS scoring, and STIX IOC output.
    """

    skill_name: str
    threat_detected: bool
    alert_level: AlertLevel
    action_taken: DefenseAction = DefenseAction.MONITOR
    findings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    timeline: list[DefenseTimelineEntry] = Field(default_factory=list)
    duration_ms: float = 0.0
    blocked: bool = False
    error: str | None = None
    mitigated: bool = False
    # --- Enhanced fields ---
    mitre_techniques: list[MITRETechnique] = Field(default_factory=list)
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    cvss_severity: str = Field(default="None")
    cvss_vector: CVSSVector | None = None
    stix_indicators: list[STIXIndicator] = Field(default_factory=list)
    chain_of_custody: ChainOfCustody | None = None
    ir_phase: NISTIRPhase = NISTIRPhase.DETECTION_AND_ANALYSIS
    containment_strategy: ContainmentStrategy | None = None
    detection_confidence: float = Field(default=0.0, ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Defense skill base class
# ---------------------------------------------------------------------------


class BaseDefenseSkill(ABC):
    """Abstract base for every Blue Team defense skill.

    Subclasses must set the three ClassVar attributes and implement
    ``execute()``. Use the ``@defense_skill`` decorator to auto-register.
    """

    skill_name: ClassVar[str]
    skill_description: ClassVar[str]
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.MEDIUM
    category: ClassVar[str] = "general"
    # MITRE ATT&CK techniques this skill detects/mitigates
    mitre_techniques: ClassVar[list[str]] = []

    @abstractmethod
    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        """Run the defense skill.

        Args:
            context: Optional incident context with threat details.
            **kwargs: Additional parameters for the skill.
        """
        ...

    def get_mitre_mappings(self) -> list[MITRETechnique]:
        """Return MITRE ATT&CK technique objects for this skill."""
        return [MITRETechnique.from_id(tid) for tid in self.mitre_techniques]

    def get_cvss_vector(self, threat_type: str = "") -> CVSSVector:
        """Return a CVSS vector for this skill's threat domain."""
        return CVSS_PRESETS.get(threat_type, CVSSVector())


# ---------------------------------------------------------------------------
# Singleton registry & @defense_skill decorator
# ---------------------------------------------------------------------------


class DefenseRegistry:
    """Singleton registry for Blue Team defense skills."""

    _instance: "DefenseRegistry | None" = None

    def __init__(self) -> None:
        self._skills: dict[str, type[BaseDefenseSkill]] = {}

    @classmethod
    def instance(cls) -> "DefenseRegistry":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register(self, skill_cls: type[BaseDefenseSkill]) -> None:
        self._skills[skill_cls.skill_name] = skill_cls

    def get(self, name: str) -> BaseDefenseSkill | None:
        cls = self._skills.get(name)
        return cls() if cls else None

    def list_all(self) -> list[BaseDefenseSkill]:
        return [cls() for cls in self._skills.values()]

    def names(self) -> list[str]:
        return list(self._skills.keys())

    def __contains__(self, name: str) -> bool:
        return name in self._skills

    def __len__(self) -> int:
        return len(self._skills)


def get_defense_registry() -> DefenseRegistry:
    """Return the singleton DefenseRegistry."""
    return DefenseRegistry.instance()


def defense_skill(cls: type[BaseDefenseSkill]) -> type[BaseDefenseSkill]:
    """Class decorator — auto-registers a defense skill on module import."""
    get_defense_registry().register(cls)
    return cls


def record_defense(timeline: list[DefenseTimelineEntry], action: str, detail: str) -> None:
    """Append a timestamped step to a defense timeline."""
    timeline.append(DefenseTimelineEntry(action=action, detail=detail))
