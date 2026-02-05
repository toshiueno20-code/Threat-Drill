"""AegisFlow Agent Skills — composable, auto-registered security-testing capabilities.

Importing this package populates the global SkillRegistry with every
concrete skill defined in the sub-modules below.
"""

from .base import (
    BaseSkill,
    SkillResult,
    ReconData,
    TimelineEntry,
    SkillRegistry,
    get_registry,
    skill,
    build_selector,
    record,
)

# Trigger @skill registration for all concrete skill modules
from . import web_attacks as _web  # noqa: F401
from . import ai_attacks as _ai  # noqa: F401
from . import auth_attacks as _auth  # noqa: F401

__all__ = [
    "BaseSkill",
    "SkillResult",
    "ReconData",
    "TimelineEntry",
    "SkillRegistry",
    "get_registry",
    "skill",
    "build_selector",
    "record",
]
