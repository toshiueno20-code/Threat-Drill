"""Gemini Chatbot — Main application.

A deliberately vulnerable AI chatbot for security testing with Threat Drill.

VULNERABILITIES SUMMARY:
- [A01]  Broken Access Control — admin endpoint with no auth
- [A02]  Cryptographic Failures — hardcoded secrets, .env committed
- [A03]  Injection — SQL injection via search, XSS via unescaped output
- [A05]  Security Misconfiguration — CORS *, debug mode, verbose errors
- [A07]  Auth Failures — weak password, no rate limit on login
- [A09]  Logging Failures — no security event logging
- [LLM01] Prompt Injection — no input filtering
- [LLM02] Sensitive Disclosure — model leaks secrets from system prompt
- [LLM05] Improper Output — raw HTML/JS in model responses rendered
- [LLM06] Excessive Agency — AI can call dangerous tools
- [LLM07] System Prompt Leakage — prompt accessible via API
- [LLM10] Unbounded Consumption — no rate limit, no token budget
"""

import os
import sqlite3

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import DEBUG, SECRET_KEY, ADMIN_PASSWORD, SYSTEM_PROMPT, INTERNAL_API_KEYS, DATABASE_CONFIG
from app.gemini_client import GeminiChat, ToolExecutor
from app.routers import chat, admin

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Gemini Chatbot",
    version="0.1.0",
    debug=DEBUG,  # [VULN: A05 - Debug mode in production]
)

# [VULN: A05 - CORS allows all origins]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# [VULN: A09 - No security logging middleware]
# [VULN: No rate limiting middleware]
# [VULN: No request size limiting middleware]


# ---------------------------------------------------------------------------
# ThreatDrill Sandbox Verification Endpoint
# ---------------------------------------------------------------------------
# This endpoint allows Threat Drill to verify this is an authorized
# test target before running attacks.

@app.get("/.well-known/threatdrill-sandbox")
async def sandbox_verify(challenge: str = "", timestamp: str = ""):
    """Sandbox verification for Threat Drill integration."""
    import hashlib
    import hmac

    sandbox_token = "vulnerable-app-sandbox-token"
    shared_secret = os.environ.get("THREATDRILL_SANDBOX_SECRET", "threatdrill-dev-secret")

    message = f"{challenge}:{sandbox_token}".encode()
    challenge_response = hmac.new(
        shared_secret.encode(), message, hashlib.sha256
    ).hexdigest()

    return {
        "challenge_response": challenge_response,
        "sandbox_token": sandbox_token,
        "environment": {
            "type": "local",
            "instance_id": "vulnerable-genai-app-001",
            "region": None,
            "extra": {"purpose": "security-testing"},
        },
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

app.include_router(chat.router, prefix="/api", tags=["chat"])
app.include_router(admin.router, prefix="/admin", tags=["admin"])


@app.get("/health")
async def health():
    return {"status": "healthy", "debug": DEBUG}


# [VULN: A05 - Exposes internal config in debug mode]
@app.get("/debug/config")
async def debug_config():
    """Debug endpoint — exposes all configuration.

    [VULN: A05/A02 - Internal configuration exposed without authentication]
    """
    if not DEBUG:
        return {"error": "Debug mode is disabled"}
    return {
        "system_prompt": SYSTEM_PROMPT,
        "api_keys": INTERNAL_API_KEYS,
        "database": DATABASE_CONFIG,
        "secret_key": SECRET_KEY,
        "admin_password": ADMIN_PASSWORD,
    }


# [VULN: LLM07 - System prompt directly accessible]
@app.get("/api/system-prompt")
async def get_system_prompt():
    """Returns the system prompt — no authentication required.

    [VULN: LLM07 - System prompt leakage via unauthenticated endpoint]
    """
    return {"system_prompt": SYSTEM_PROMPT}


# [VULN: LLM06 - Tool list and execution exposed without auth]
@app.get("/api/tools")
async def list_tools():
    """List all available AI tools."""
    return {"tools": ToolExecutor.TOOLS}


@app.post("/api/tools/execute")
async def execute_tool(request: Request):
    """Execute an AI tool directly.

    [VULN: LLM06 - No authentication, no authorization, no approval]
    [VULN: A03   - Arguments passed without sanitization]
    """
    data = await request.json()
    tool_name = data.get("tool_name", "")
    args = data.get("args", {})
    result = await ToolExecutor.execute(tool_name, args)
    return {"result": result}


# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(content=CHAT_HTML)


# Inline HTML template (for simplicity)
CHAT_HTML = """<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gemini Chatbot</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0f0f23; color: #e0e0e0; min-height: 100vh; display: flex; flex-direction: column; }
        .header { background: #1a1a2e; padding: 16px 24px; border-bottom: 1px solid #333; display: flex; align-items: center; gap: 12px; }
        .header h1 { font-size: 20px; color: #4fc3f7; }
        .header .badge { font-size: 10px; background: #ff5252; color: #fff; padding: 2px 8px; border-radius: 10px; }
        .chat-container { flex: 1; max-width: 800px; width: 100%; margin: 0 auto; padding: 20px; overflow-y: auto; }
        .message { margin-bottom: 16px; display: flex; gap: 12px; }
        .message.user { justify-content: flex-end; }
        .message .bubble { max-width: 70%; padding: 12px 16px; border-radius: 16px; line-height: 1.6; font-size: 14px; }
        .message.user .bubble { background: #1565c0; color: #fff; border-bottom-right-radius: 4px; }
        .message.bot .bubble { background: #1e1e3a; border: 1px solid #333; border-bottom-left-radius: 4px; }
        .input-area { background: #1a1a2e; padding: 16px 24px; border-top: 1px solid #333; }
        .input-row { max-width: 800px; margin: 0 auto; display: flex; gap: 8px; }
        .input-row input { flex: 1; padding: 12px 16px; background: #0f0f23; border: 1px solid #444; border-radius: 12px; color: #e0e0e0; font-size: 14px; outline: none; }
        .input-row input:focus { border-color: #4fc3f7; }
        .input-row button { padding: 12px 24px; background: #4fc3f7; color: #000; border: none; border-radius: 12px; font-weight: 600; cursor: pointer; }
        .input-row button:hover { background: #81d4fa; }
        .input-row button:disabled { opacity: 0.5; cursor: not-allowed; }
        .typing { color: #888; font-style: italic; font-size: 13px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Gemini Chatbot</h1>
        <span class="badge">DEMO</span>
    </div>
    <div class="chat-container" id="chatContainer">
        <div class="message bot">
            <div class="bubble">こんにちは！TechCorpのAIアシスタントです。何でもお気軽にご質問ください。</div>
        </div>
    </div>
    <div class="input-area">
        <div class="input-row">
            <input type="text" id="userInput" placeholder="メッセージを入力..." autocomplete="off"
                   onkeypress="if(event.key==='Enter')sendMessage()">
            <button id="sendBtn" onclick="sendMessage()">送信</button>
        </div>
    </div>
    <script>
        const chatContainer = document.getElementById('chatContainer');
        const userInput = document.getElementById('userInput');
        const sendBtn = document.getElementById('sendBtn');

        function addMessage(role, text) {
            const div = document.createElement('div');
            div.className = `message ${role}`;
            const bubble = document.createElement('div');
            bubble.className = 'bubble';
            // [VULN: LLM05/A03 - innerHTML used — XSS via model output]
            bubble.innerHTML = text;
            div.appendChild(bubble);
            chatContainer.appendChild(div);
            chatContainer.scrollTop = chatContainer.scrollHeight;
        }

        async function sendMessage() {
            const msg = userInput.value.trim();
            if (!msg) return;
            userInput.value = '';
            sendBtn.disabled = true;
            addMessage('user', msg.replace(/</g,'&lt;').replace(/>/g,'&gt;'));
            addMessage('bot', '<span class="typing">入力中...</span>');

            try {
                const res = await fetch('/api/chat', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({message: msg})
                });
                const data = await res.json();
                // Remove typing indicator
                chatContainer.lastChild.remove();
                // [VULN: LLM05 - Raw HTML from model rendered directly]
                addMessage('bot', data.response || 'エラーが発生しました');
            } catch(e) {
                chatContainer.lastChild.remove();
                addMessage('bot', 'エラーが発生しました: ' + e.message);
            }
            sendBtn.disabled = false;
            userInput.focus();
        }
    </script>
</body>
</html>
"""
