"""Auth-layer attack skills: Auth Bypass + Privilege Escalation."""

import json
import re
import time
from typing import Any

from shared.schemas import ThreatLevel
from .base import BaseSkill, SkillResult, ReconData, TimelineEntry, skill, record


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("user", "user"),
    ("admin", "admin123"),
    ("test", "test"),
    ("", ""),
]

_SECRET_PATTERNS: list[tuple[str, str]] = [
    ("api_key", r"api[_-]?key[\"']\s*[:=]\s*[\"']([A-Za-z0-9_-]{20,})"),
    ("bearer_token", r"bearer\s+([A-Za-z0-9._-]{30,})"),
    ("private_key", r"-----BEGIN"),
    ("aws_key", r"AKIA[0-9A-Z]{16}"),
]

_ADMIN_PATHS = ["/admin", "/admin/users", "/api/admin", "/api/users"]

_LOGIN_INDICATORS = ("logout", "dashboard", "welcome", "profile", "sign out")


# ===========================================================================
# Auth Bypass
# ===========================================================================


@skill
class AuthBypassSkill(BaseSkill):
    """Default-credential brute-force + secret / token leak detection."""

    skill_name = "auth_bypass"
    skill_description = "Auth bypass — default creds, secret leaks in source / localStorage / cookies"
    default_severity = ThreatLevel.CRITICAL

    async def execute(
        self, server: Any, target_url: str, recon: ReconData | None = None
    ) -> SkillResult:
        timeline: list[TimelineEntry] = []
        start = time.time()
        evidence: list[str] = []

        # --- Source-code secret scan -----------------------------------------
        record(timeline, "recon", "Scanning page source for secrets")
        html = recon.html if recon else (await server.call_tool("browser_get_html", {})).get("result", "")
        for label, pattern in _SECRET_PATTERNS:
            if re.search(pattern, html, re.IGNORECASE):
                evidence.append(f"{label} exposed in page source")
                record(timeline, "success", f"Secret: {label}")

        # --- localStorage token scan -----------------------------------------
        ls: dict[str, str] = (
            recon.local_storage
            if recon
            else json.loads((await server.call_tool("browser_get_local_storage", {})).get("result", "{}"))
        )
        for key, value in ls.items():
            if any(kw in key.lower() for kw in ("token", "secret", "key", "auth", "session")):
                evidence.append(f"Auth data in localStorage: '{key}' (len={len(value)})")
                record(timeline, "success", f"localStorage: {key}")

        # --- Cookie security-flag audit ---------------------------------------
        cookies: list[dict[str, Any]] = (
            recon.cookies
            if recon
            else json.loads((await server.call_tool("browser_get_cookies", {})).get("result", "[]"))
        )
        for ck in cookies:
            name = (ck.get("name") or "").lower()
            if any(kw in name for kw in ("session", "auth", "token")):
                flags: list[str] = []
                if not ck.get("secure"):
                    flags.append("Secure=false")
                if not ck.get("httpOnly"):
                    flags.append("HttpOnly=false")
                if flags:
                    evidence.append(f"Cookie '{ck.get('name')}' insecure: {flags}")
                    record(timeline, "success", f"Insecure cookie: {ck.get('name')}")

        # --- Default-credential login attempt ---------------------------------
        has_login = await server.call_tool(
            "browser_evaluate_js",
            {
                "script": (
                    "() => JSON.stringify({"
                    "  user: !!document.querySelector("
                    "    'input[name*=user i], input[name*=email i], input[type=email]'),"
                    "  pass: !!document.querySelector('input[type=password]'),"
                    "  form: !!document.querySelector('form')"
                    "})"
                )
            },
        )
        login_info = json.loads(has_login.get("result", "{}"))

        if login_info.get("user") and login_info.get("pass"):
            record(timeline, "recon", "Login form detected — default creds")

            for username, password in _DEFAULT_CREDS[:5]:
                await server.call_tool("browser_navigate", {"url": target_url})
                try:
                    await server.call_tool(
                        "browser_fill",
                        {"selector": "input[type=email], input[name*=user]", "value": username},
                    )
                    await server.call_tool(
                        "browser_fill",
                        {"selector": "input[type=password]", "value": password},
                    )
                    await server.call_tool("browser_submit_form", {"selector": "form"})
                    await server.call_tool("browser_wait_for", {"delay_ms": 1000})

                    page_text = (await server.call_tool("browser_get_text", {})).get("result", "").lower()
                    if any(ind in page_text for ind in _LOGIN_INDICATORS):
                        evidence.append(f"Default creds work: {username}:{password}")
                        record(timeline, "success", f"Login: {username}:{password}")
                        break
                except Exception:
                    continue

        return SkillResult(
            skill_name=self.skill_name,
            success=bool(evidence),
            severity=self.default_severity,
            evidence=evidence,
            timeline=timeline,
            duration_ms=round((time.time() - start) * 1000, 2),
        )


# ===========================================================================
# Privilege Escalation
# ===========================================================================


@skill
class PrivilegeEscalationSkill(BaseSkill):
    """Multi-step priv-esc: admin-route discovery, localStorage role swap, endpoint probing."""

    skill_name = "privilege_escalation"
    skill_description = "Privilege escalation — role manipulation via localStorage + admin endpoint probing"
    default_severity = ThreatLevel.HIGH

    async def execute(
        self, server: Any, target_url: str, recon: ReconData | None = None
    ) -> SkillResult:
        timeline: list[TimelineEntry] = []
        start = time.time()
        evidence: list[str] = []

        # --- Admin-route references in source --------------------------------
        html = recon.html if recon else (await server.call_tool("browser_get_html", {})).get("result", "")
        admin_refs = list(set(re.findall(r'["\']/(admin|dashboard|manage|settings|users)["\']', html)))
        if admin_refs:
            evidence.append(f"Admin routes in source: {admin_refs}")
            record(timeline, "recon", f"Admin routes: {admin_refs}")

        # --- localStorage role escalation ------------------------------------
        ls: dict[str, str] = (
            recon.local_storage
            if recon
            else json.loads((await server.call_tool("browser_get_local_storage", {})).get("result", "{}"))
        )
        for key, value in ls.items():
            if "role" in key.lower():
                record(timeline, "probe", f"Role key: {key}={value}")
                # Overwrite role → admin
                await server.call_tool(
                    "browser_evaluate_js",
                    {"script": f"() => {{ localStorage.setItem('{key}', 'admin'); return 'set' }}"},
                )
                # Reload and check for admin indicators
                await server.call_tool("browser_navigate", {"url": target_url})
                page_text = (await server.call_tool("browser_get_text", {})).get("result", "").lower()
                if "admin" in page_text or "dashboard" in page_text:
                    evidence.append(f"Priv escalation via localStorage '{key}' → 'admin'")
                    record(timeline, "success", "localStorage role escalated")

        # --- Admin endpoint probing ------------------------------------------
        base = target_url.rstrip("/")
        for path in _ADMIN_PATHS:
            nav = await server.call_tool("browser_navigate", {"url": base + path})
            if not nav.get("success"):
                continue
            await server.call_tool("browser_wait_for", {"delay_ms": 500})
            text = (await server.call_tool("browser_get_text", {})).get("result", "")
            if not any(kw in text.lower() for kw in ("unauthorized", "403", "login")):
                evidence.append(f"Admin endpoint without auth: {path}")
                record(timeline, "success", f"Open admin: {path}")

        return SkillResult(
            skill_name=self.skill_name,
            success=bool(evidence),
            severity=self.default_severity,
            evidence=evidence,
            timeline=timeline,
            duration_ms=round((time.time() - start) * 1000, 2),
        )
