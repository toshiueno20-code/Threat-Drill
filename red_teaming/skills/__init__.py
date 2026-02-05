"""Threat Drill Agent Skills — composable, auto-registered security-testing capabilities.

Importing this package populates the global SkillRegistry with every
concrete skill defined in the sub-modules below.

Includes:
- OWASP Web Application Top 10 (2025) attacks
- OWASP LLM Top 10 (2025) attacks
- Traditional web attacks (XSS, SQLi, CSRF, etc.)
- Authentication and authorization attacks
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
from . import owasp_web_attacks as _owasp_web  # noqa: F401
from . import owasp_llm_attacks as _owasp_llm  # noqa: F401

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
