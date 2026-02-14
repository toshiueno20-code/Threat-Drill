"""Security analysis endpoints.

This router provides:
- `/analyze`: lightweight threat analysis (currently a deterministic mock).
- `/events`: in-memory event list for UI visibility and troubleshooting.
"""

from __future__ import annotations

import os
import uuid
from collections import deque
from datetime import datetime
from typing import List

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from shared.schemas import MultimodalInput, SecurityEvent, ThreatAnalysisResult, ThreatLevel
from shared.utils import get_logger

logger = get_logger(__name__)
router = APIRouter()

_EVENT_BUFFER_SIZE = int(os.environ.get("SECURITY_EVENTS_BUFFER", "200"))
_EVENTS: "deque[SecurityEvent]" = deque(maxlen=max(10, min(_EVENT_BUFFER_SIZE, 2000)))


class SecurityAnalysisRequest(BaseModel):
    """Request payload for a single security analysis call."""

    inputs: List[MultimodalInput]
    user_id: str | None = None
    session_id: str | None = None
    context_history: List[dict] = []
    source_ip: str | None = None
    user_agent: str | None = None


class SecurityAnalysisResponse(BaseModel):
    """Response payload for a single security analysis call."""

    event_id: str
    threat_analysis: ThreatAnalysisResult
    blocked: bool
    timestamp: datetime
    message: str


@router.post("/analyze", response_model=SecurityAnalysisResponse)
async def analyze_security(
    request: SecurityAnalysisRequest,
    background_tasks: BackgroundTasks,
) -> SecurityAnalysisResponse:
    """Analyze multimodal inputs for suspicious patterns.

    Note: this endpoint currently returns a deterministic mock response and stores
    a `SecurityEvent` in an in-memory ring buffer.
    """
    event_id = str(uuid.uuid4())

    logger.info(
        "Security analysis started",
        event_id=event_id,
        user_id=request.user_id,
        input_count=len(request.inputs),
    )

    try:
        threat_analysis = ThreatAnalysisResult(
            threat_level=ThreatLevel.SAFE,
            confidence=0.95,
            reasoning="No high-confidence threat indicators were detected (mock analyzer).",
            detected_patterns=[],
            recommended_actions=[],
            deep_think_used=False,
            analysis_duration_ms=50.0,
            model_version="mock-security-analyzer",
            context_window_tokens=0,
        )

        blocked = threat_analysis.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)

        background_tasks.add_task(
            _store_security_event,
            event_id,
            request,
            threat_analysis,
            blocked,
        )

        return SecurityAnalysisResponse(
            event_id=event_id,
            threat_analysis=threat_analysis,
            blocked=blocked,
            timestamp=datetime.utcnow(),
            message="Analysis completed successfully" if not blocked else "Threat detected and blocked",
        )

    except Exception as exc:
        logger.error("Security analysis failed", event_id=event_id, error=str(exc))
        raise HTTPException(status_code=500, detail="Security analysis failed")


def _store_security_event(
    event_id: str,
    request: SecurityAnalysisRequest,
    threat_analysis: ThreatAnalysisResult,
    blocked: bool,
) -> None:
    """Store a security event in-memory (ring buffer)."""
    try:
        security_event = SecurityEvent(
            event_id=event_id,
            timestamp=datetime.utcnow(),
            user_id=request.user_id,
            session_id=request.session_id,
            inputs=request.inputs,
            threat_analysis=threat_analysis,
            blocked=blocked,
            source_ip=request.source_ip,
            user_agent=request.user_agent,
            context_history=request.context_history,
        )
        _EVENTS.append(security_event)
        logger.info("Security event stored", event_id=event_id, threat_level=threat_analysis.threat_level)
    except Exception as exc:
        logger.error("Failed to store security event", event_id=event_id, error=str(exc))


@router.get("/events", response_model=list[SecurityEvent])
async def list_security_events(limit: int = 50) -> list[SecurityEvent]:
    """List recent security events from the in-memory buffer."""
    safe_limit = max(1, min(int(limit or 50), len(_EVENTS) if _EVENTS else 200))
    return list(_EVENTS)[-safe_limit:]


@router.get("/events/{event_id}", response_model=SecurityEvent)
async def get_security_event(event_id: str) -> SecurityEvent:
    """Get a specific security event by ID from the in-memory buffer."""
    for ev in reversed(_EVENTS):
        if ev.event_id == event_id:
            return ev
    raise HTTPException(status_code=404, detail="Event not found")


@router.get("/health")
async def security_health() -> dict[str, str]:
    """Health check for the security module."""
    return {"status": "healthy", "module": "security"}

