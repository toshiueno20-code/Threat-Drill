"""Blue Team defense skill framework — types, registry, decorator.

Mirror of the Red Team skill framework, but for defensive capabilities.
Each defense skill is self-contained, discoverable, and composable.
"""

import time
from abc import ABC, abstractmethod
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


class DefenseResult(BaseModel):
    """Result returned by every defense skill execution.

    ``threat_detected`` = True means a threat was identified and acted upon.
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
