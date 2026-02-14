"""Threat Drill skill package.

This package registers skill modules for UI discovery.

Notes:
- Hackathon/demo deployments may restrict which skills are executable even if they are listed.
- Execution policy is enforced at the API layer (explicit approval + allowlists), not here.
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
    # Catalog modules (listed in UI; execution may be restricted by policy/allowlists).
    ("owasp_llm_attacks", "owasp_llm_attacks"),
    ("owasp_web_attacks", "owasp_web_attacks"),
    ("web_attacks", "web_attacks"),
    ("auth_attacks", "auth_attacks"),
    ("ai_attacks", "ai_attacks"),
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
