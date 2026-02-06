"""Threat Drill Agent Skills — composable, auto-registered security-testing capabilities.

Importing this package populates the global SkillRegistry with every
concrete skill defined in the sub-modules below.

Includes:
- OWASP Web Application Top 10 (2025) attacks
- OWASP LLM Top 10 (2025) attacks
- Traditional web attacks (XSS, SQLi, CSRF, etc.)
- Authentication and authorization attacks
"""

import logging

_logger = logging.getLogger(__name__)

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
_skill_modules = [
    ("web_attacks", "web_attacks"),
    ("ai_attacks", "ai_attacks"),
    ("auth_attacks", "auth_attacks"),
    ("owasp_web_attacks", "owasp_web_attacks"),
    ("owasp_llm_attacks", "owasp_llm_attacks"),
]

for _module_name, _display_name in _skill_modules:
    try:
        __import__(f"red_teaming.skills.{_module_name}", fromlist=[_module_name])
        _logger.debug(f"Loaded skill module: {_display_name}")
    except Exception as e:
        _logger.error(f"Failed to load skill module {_display_name}: {e}")

# Log registered skill count
_registry = get_registry()
_logger.info(f"Skills registered: {len(_registry)} skills loaded")

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
