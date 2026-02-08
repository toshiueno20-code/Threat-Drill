"""Admin panel router.

VULNERABILITIES:
- [A01] Broken Access Control — admin routes accessible without proper auth
- [A03] Injection — SQL injection in user search
- [A07] Auth Failures — weak password, no rate limit, no MFA
- [A04] Insecure Design — password sent in query parameter
"""

import sqlite3
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.config import ADMIN_PASSWORD, SYSTEM_PROMPT, INTERNAL_API_KEYS

router = APIRouter()

# [VULN: A07 - Simple password auth, no session management]
_authenticated_ips: set[str] = set()


@router.post("/login")
async def admin_login(request: Request, password: str = Query(...)):
    """Admin login.

    VULNERABILITIES:
    - [A07] Password in query parameter (logged in server logs, browser history)
    - [A07] No rate limiting on login attempts (brute force)
    - [A07] No account lockout
    - [A07] Weak default password
    - [A04] IP-based auth (spoofable)
    """
    client_ip = request.client.host if request.client else "unknown"

    if password == ADMIN_PASSWORD:
        _authenticated_ips.add(client_ip)
        return {
            "status": "authenticated",
            "message": f"Welcome, admin! (IP: {client_ip})",
            # [VULN: A02 - Leaks internal info on successful login]
            "admin_password": ADMIN_PASSWORD,
        }

    # [VULN: A09 - No logging of failed login attempts]
    # [VULN: A07 - Different error messages for valid/invalid users]
    raise HTTPException(status_code=401, detail="Invalid password")


def _check_admin(request: Request) -> bool:
    """Check if request is from authenticated admin.

    [VULN: A01 - IP-based auth easily bypassed with X-Forwarded-For]
    """
    client_ip = request.client.host if request.client else "unknown"
    # [VULN: A01 - Localhost always allowed without password]
    if client_ip in ("127.0.0.1", "::1", "localhost"):
        return True
    return client_ip in _authenticated_ips


@router.get("/dashboard")
async def admin_dashboard(request: Request) -> dict:
    """Admin dashboard — shows all internal config.

    [VULN: A01 - Localhost bypass means no real auth needed locally]
    """
    if not _check_admin(request):
        raise HTTPException(status_code=403, detail="Not authenticated")

    return {
        "system_prompt": SYSTEM_PROMPT,
        "internal_keys": INTERNAL_API_KEYS,
        "active_sessions": len(_authenticated_ips),
    }


@router.get("/users/search")
async def search_users(request: Request, q: str = Query("")) -> dict:
    """Search users by name.

    [VULN: A03 - SQL injection via query parameter]
    [VULN: A01 - No auth check on this endpoint]
    """
    # [VULN: A03 - String concatenation for SQL query]
    query = f"SELECT * FROM users WHERE name LIKE '%{q}%'"

    # Simulated response (no actual DB, but the query is the vulnerability)
    return {
        "query_executed": query,
        "results": [
            {"id": 1, "name": "田中太郎", "email": "tanaka@techcorp.jp", "role": "admin"},
            {"id": 2, "name": "佐藤花子", "email": "sato@techcorp.jp", "role": "user"},
        ],
        "note": "Results are simulated, but the SQL query shown above is real and injectable",
    }


@router.get("/config/export")
async def export_config(request: Request) -> dict:
    """Export all configuration.

    [VULN: A01 - Auth bypass via localhost]
    [VULN: A02 - Exports all secrets]
    """
    if not _check_admin(request):
        raise HTTPException(status_code=403, detail="Not authenticated")

    from app.config import DATABASE_CONFIG

    return {
        "system_prompt": SYSTEM_PROMPT,
        "api_keys": INTERNAL_API_KEYS,
        "database": DATABASE_CONFIG,
        "admin_password": ADMIN_PASSWORD,
    }
