"""Skill framework base — types, registry, decorator, helpers.

Design goals
------------
* Every attack capability is a *Skill*: self-contained, discoverable, composable.
* Skills are registered at import time via the ``@skill`` class decorator.
* The singleton ``SkillRegistry`` is the only place the orchestrator needs to
  look to find what is available.
* All I/O is typed with Pydantic v2 models so the router can serialise
  results with ``model_dump()`` without any manual conversion.
"""

import time
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from shared.schemas import ThreatLevel


# ---------------------------------------------------------------------------
# Typed data models (Pydantic v2)
# ---------------------------------------------------------------------------


class TimelineEntry(BaseModel):
    """A single timestamped step recorded during skill execution."""

    timestamp: float = Field(default_factory=time.time)
    action: str
    detail: str


class GeminiLogEntry(BaseModel):
    """A single Gemini AI interaction log entry."""

    timestamp: float = Field(default_factory=time.time)
    phase: str = ""           # e.g. "analysis", "verification", "planning"
    prompt_summary: str = ""  # truncated prompt sent to Gemini
    response_text: str = ""   # Gemini raw response text
    model: str = ""
    tokens_used: int = 0
    duration_ms: float = 0.0
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)


class SkillResult(BaseModel):
    """Typed result returned by every skill execution.

    ``success`` = True means a vulnerability was *confirmed* (red-team win).
    """

    skill_name: str
    success: bool
    severity: ThreatLevel
    evidence: list[str] = Field(default_factory=list)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    gemini_logs: list[GeminiLogEntry] = Field(default_factory=list)
    duration_ms: float = 0.0
    error: str | None = None


class ReconData(BaseModel):
    """Pre-computed page-recon snapshot.

    Collected once by the orchestrator before skills run so that no skill
    needs to re-fetch page structure independently.
    """

    url: str
    html: str = ""
    text: str = ""
    inputs: list[dict[str, str]] = Field(default_factory=list)
    forms: list[dict[str, Any]] = Field(default_factory=list)
    cookies: list[dict[str, Any]] = Field(default_factory=list)
    local_storage: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Skill base class
# ---------------------------------------------------------------------------


class BaseSkill(ABC):
    """Abstract base for every agent skill.

    Subclasses must set the three ``ClassVar`` attributes and implement
    ``execute()``.  Use the ``@skill`` decorator to auto-register.
    """

    skill_name: ClassVar[str]           # unique registry key, e.g. "xss"
    skill_description: ClassVar[str]    # human-readable one-liner
    default_severity: ClassVar[ThreatLevel] = ThreatLevel.MEDIUM
    verification_instructions: ClassVar[str] = ""  # AI verification guidance per threat

    @abstractmethod
    async def execute(
        self,
        server: Any,            # PlaywrightMCPServer  (Any avoids circular import)
        target_url: str,
        recon: ReconData | None = None,
    ) -> SkillResult:
        """Run the skill against *target_url*.

        Args:
            server: An already-started PlaywrightMCPServer.
            target_url: Validated localhost URL.
            recon: Optional pre-computed recon (avoids redundant fetches).
        """
        ...


# ---------------------------------------------------------------------------
# Singleton registry  &  @skill decorator
# ---------------------------------------------------------------------------


class SkillRegistry:
    """Singleton registry — discovery + instantiation of skills."""

    _instance: "SkillRegistry | None" = None

    def __init__(self) -> None:
        self._skills: dict[str, type[BaseSkill]] = {}

    # --- singleton ----------------------------------------------------------

    @classmethod
    def instance(cls) -> "SkillRegistry":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # --- mutation -----------------------------------------------------------

    def register(self, skill_cls: type[BaseSkill]) -> None:
        self._skills[skill_cls.skill_name] = skill_cls

    # --- query --------------------------------------------------------------

    def get(self, name: str) -> BaseSkill | None:
        """Instantiate the named skill, or return None."""
        cls = self._skills.get(name)
        return cls() if cls else None

    def list_all(self) -> list[BaseSkill]:
        """One fresh instance of every registered skill."""
        return [cls() for cls in self._skills.values()]

    def names(self) -> list[str]:
        return list(self._skills.keys())

    def skills_map(self) -> dict[str, type[BaseSkill]]:
        """Public copy of name → class mapping."""
        return dict(self._skills)

    def __contains__(self, name: str) -> bool:
        return name in self._skills

    def __len__(self) -> int:
        return len(self._skills)


def get_registry() -> SkillRegistry:
    """Return the singleton SkillRegistry."""
    return SkillRegistry.instance()


def skill(cls: type[BaseSkill]) -> type[BaseSkill]:
    """Class decorator — auto-registers a skill on module import."""
    get_registry().register(cls)
    return cls


# ---------------------------------------------------------------------------
# Shared helpers used by concrete skills
# ---------------------------------------------------------------------------


def build_selector(inp_info: dict[str, str]) -> str | None:
    """Build a CSS selector string from a JS-extracted element-info dict."""
    if inp_info.get("id"):
        return f"#{inp_info['id']}"
    if inp_info.get("name"):
        return f"[name={inp_info['name']}]"
    return None


def record(timeline: list[TimelineEntry], action: str, detail: str) -> None:
    """Append a timestamped step to a timeline list."""
    timeline.append(TimelineEntry(action=action, detail=detail))
