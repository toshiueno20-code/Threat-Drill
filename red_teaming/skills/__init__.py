"""Threat Drill skill package.

This package only registers read-only vulnerability check skills.
Exploit-oriented attack skills are intentionally disabled by policy.
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

# Trigger @skill registration for approved (read-only) skill modules.
_skill_modules = [
    ("security_checks", "security_checks"),
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
