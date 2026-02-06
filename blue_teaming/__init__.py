"""Threat Drill Blue Team — defensive security capabilities.

The Blue Team module provides real-time threat detection, incident response,
forensic analysis, and policy enforcement. It works in coordination with the
Red Team module to form a complete Purple Team security mesh.

Includes:
- Threat detection and monitoring skills
- Incident response automation
- Log analysis and forensic investigation
- Policy enforcement and hardening
- Real-time alert management
"""

import logging

_logger = logging.getLogger(__name__)

from .skills.base import (
    BaseDefenseSkill,
    DefenseResult,
    DefenseRegistry,
    get_defense_registry,
    defense_skill,
    AlertLevel,
    IncidentContext,
)

# Trigger @defense_skill registration for all concrete skill modules
_skill_modules = [
    ("detection", "detection"),
    ("response", "response"),
    ("forensics", "forensics"),
    ("hardening", "hardening"),
]

for _module_name, _display_name in _skill_modules:
    try:
        __import__(f"blue_teaming.skills.{_module_name}", fromlist=[_module_name])
        _logger.debug(f"Loaded defense skill module: {_display_name}")
    except Exception as e:
        _logger.error(f"Failed to load defense skill module {_display_name}: {e}")

# Log registered skill count
_registry = get_defense_registry()
_logger.info(f"Defense skills registered: {len(_registry)} skills loaded")

__all__ = [
    "BaseDefenseSkill",
    "DefenseResult",
    "DefenseRegistry",
    "get_defense_registry",
    "defense_skill",
    "AlertLevel",
    "IncidentContext",
]
