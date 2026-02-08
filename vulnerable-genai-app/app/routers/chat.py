"""Chat API router.

VULNERABILITIES:
- [LLM01] Prompt Injection — user input goes directly to the model
- [LLM02] Sensitive Info Disclosure — model can leak system prompt secrets
- [LLM05] Improper Output Handling — HTML/JS in responses rendered as-is
- [LLM10] Unbounded Consumption — no rate limit, no max tokens, no session limit
- [A03]   Injection — user input reflected without sanitization
- [A09]   Security Logging Failures — no logging of suspicious inputs
"""

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.gemini_client import GeminiChat

router = APIRouter()

# [VULN: LLM10 - Global mutable state, no per-user isolation]
# [VULN: LLM10 - Conversation grows unbounded]
_sessions: dict[str, GeminiChat] = {}


def _get_session(session_id: str) -> GeminiChat:
    """Get or create a chat session.

    [VULN: No session validation, no max sessions limit]
    """
    if session_id not in _sessions:
        _sessions[session_id] = GeminiChat()
    return _sessions[session_id]


class ChatRequest(BaseModel):
    message: str
    session_id: str = "default"


class ChatResponse(BaseModel):
    response: str
    session_id: str


@router.post("/chat")
async def chat(request: ChatRequest) -> dict:
    """Chat endpoint.

    VULNERABILITIES:
    - No input length validation
    - No prompt injection detection
    - No output sanitization
    - No rate limiting
    - No authentication
    """
    session = _get_session(request.session_id)

    # [VULN: LLM01 - No filtering, no injection detection]
    # [VULN: LLM10 - No input length limit]
    response_text = await session.send_message(request.message)

    # [VULN: LLM05 - Model output returned raw, may contain HTML/JS]
    # [VULN: LLM02 - Model may have leaked sensitive info from system prompt]
    return {
        "response": response_text,
        "session_id": request.session_id,
    }


@router.get("/chat/history")
async def get_history(session_id: str = "default") -> dict:
    """Get conversation history.

    [VULN: A01 - No auth, anyone can read any session's history]
    [VULN: LLM02 - History may contain leaked sensitive data]
    """
    session = _get_session(session_id)
    return {
        "session_id": session_id,
        "history": session.get_history(),
    }


@router.post("/chat/clear")
async def clear_history(session_id: str = "default") -> dict:
    """Clear conversation history.

    [VULN: A01 - No auth, anyone can clear any session]
    """
    session = _get_session(session_id)
    session.clear_history()
    return {"status": "cleared", "session_id": session_id}


@router.get("/chat/sessions")
async def list_sessions() -> dict:
    """List all active sessions.

    [VULN: A01 - Exposes all active session IDs without auth]
    """
    return {
        "sessions": list(_sessions.keys()),
        "total": len(_sessions),
    }
