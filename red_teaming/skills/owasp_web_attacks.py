"""OWASP Web Application Top 10 (2025) Attack Skills.

Implements security testing capabilities for:
- A01:2025 Broken Access Control
- A02:2025 Cryptographic Failures
- A03:2025 Injection (extended)
- A04:2025 Insecure Design
- A05:2025 Security Misconfiguration
- A06:2025 Vulnerable and Outdated Components
- A07:2025 Identification and Authentication Failures
- A08:2025 Software and Data Integrity Failures
- A09:2025 Security Logging and Monitoring Failures
- A10:2025 Server-Side Request Forgery (SSRF)
"""

import json
import re
import time
from typing import Any

from shared.schemas import ThreatLevel
from .base import BaseSkill, SkillResult, ReconData, TimelineEntry, skill, record


# ===========================================================================
# A01:2025 - Broken Access Control (IDOR, Horizontal/Vertical Escalation)
# ===========================================================================


@skill
class BrokenAccessControlSkill(BaseSkill):
    """OWASP A01:2025 - Broken Access Control via IDOR and path manipulation."""

    skill_name = "owasp_a01_broken_access_control"
    skill_description = "OWASP A01:2025 - Broken Access Control (IDOR, path manipulation, forced browsing)"
    default_severity = ThreatLevel.CRITICAL

    _IDOR_PATHS = [
        "/api/user/1",
        "/api/user/2",
        "/api/users/1",
        "/api/users/2",
        "/user/1",
        "/user/2",
        "/profile/1",
        "/profile/2",
        "/account/1",
        "/order/1",
        "/document/1",
    ]

    _ADMIN_PATHS = [
        "/admin",
        "/admin/dashboard",
        "/admin/users",
        "/api/admin",
        "/api/v1/admin",
        "/manage",
        "/management",
        "/console",
        "/_admin",
    ]

    async def execute(
        self, server: Any, target_url: str, recon: ReconData | None = None
    ) -> SkillResult:
        timeline: list[TimelineEntry] = []
        start = time.time()
        evidence: list[str] = []
        base = target_url.rstrip("/")

        # --- IDOR Testing ---
        record(timeline, "phase", "IDOR Testing")
        responses: dict[str, str] = {}

        for path in self._IDOR_PATHS[:6]:
            probe = base + path
            nav = await server.call_tool("browser_navigate", {"url": probe})
            if not nav.get("success"):
                continue
            await server.call_tool("browser_wait_for", {"delay_ms": 300})
            text = (await server.call_tool("browser_get_text", {})).get("result", "")

            # Check if we got actual data (not 403/404)
            if not any(kw in text.lower() for kw in ("404", "not found", "unauthorized", "forbidden")):
                responses[path] = text[:500]
                record(timeline, "probe", f"IDOR accessible: {path}")

        # Compare different IDs
        if len(responses) >= 2:
            paths = list(responses.keys())
            if responses[paths[0]] != responses[paths[1]]:
                evidence.append(f"IDOR vulnerability: Different data accessible at {paths[0]} vs {paths[1]}")
                record(timeline, "success", "IDOR confirmed - different user data accessible")

        # --- Forced Browsing to Admin ---
        record(timeline, "phase", "Admin Path Probing")
        for path in self._ADMIN_PATHS:
            probe = base + path
            nav = await server.call_tool("browser_navigate", {"url": probe})
            if not nav.get("success"):
                continue
            await server.call_tool("browser_wait_for", {"delay_ms": 300})
            text = (await server.call_tool("browser_get_text", {})).get("result", "").lower()

            if not any(kw in text for kw in ("login", "unauthorized", "403", "forbidden", "not found")):
                if any(kw in text for kw in ("admin", "dashboard", "users", "settings", "manage")):
                    evidence.append(f"Admin endpoint accessible without auth: {path}")
                    record(timeline, "success", f"Broken access control: {path}")

        return SkillResult(
            skill_name=self.skill_name,
            success=bool(evidence),
            severity=self.default_severity,
            evidence=evidence,
            timeline=timeline,
            duration_ms=round((time.time() - start) * 1000, 2),
        )


# ===========================================================================
# A02:2025 - Cryptographic Failures
# ===========================================================================


@skill
class CryptographicFailuresSkill(BaseSkill):
    """OWASP A02:2025 - Cryptographic Failures detection."""

    skill_name = "owasp_a02_cryptographic_failures"
    skill_description = "OWASP A02:2025 - Weak crypto, exposed secrets, insecure transmission"
    default_severity = ThreatLevel.HIGH

    _SENSITIVE_PATTERNS = [
        (r"password[\"']?\s*[:=]\s*[\"'][^\"']+", "hardcoded_password"),
        (r"api[_-]?key[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_-]{16,})", "api_key"),
        (r"secret[_-]?key[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_-]{16,})", "secret_key"),
        (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private_key"),
        (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
        (r"Bearer\s+[A-Za-z0-9._-]{20,}", "bearer_token"),
        (r"ghp_[A-Za-z0-9]{36}", "github_token"),
        (r"sk-[A-Za-z0-9]{48}", "openai_key"),
    ]

    async def execute(
        self, server: Any, target_url: str, recon: ReconData | None = None
    ) -> SkillResult:
        timeline: list[TimelineEntry] = []
        start = time.time()
        evidence: list[str] = []

        # --- Check page source for secrets ---
        record(timeline, "phase", "Source Code Secret Scan")
        html = recon.html if recon else (await server.call_tool("browser_get_html", {})).get("result", "")

        for pattern, label in self._SENSITIVE_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                evidence.append(f"Exposed {label} in page source")
                record(timeline, "success", f"Found: {label}")

        # --- Check localStorage for sensitive data ---
        record(timeline, "phase", "localStorage Sensitive Data Scan")
        ls_data = await server.call_tool("browser_get_local_storage", {})
        ls: dict[str, str] = json.loads(ls_data.get("result", "{}"))

        for key, value in ls.items():
            key_lower = key.lower()
            if any(kw in key_lower for kw in ("password", "secret", "token", "key", "credential")):
                evidence.append(f"Sensitive data in localStorage: {key}")
                record(timeline, "success", f"localStorage: {key}")

        # --- Check for HTTP (non-HTTPS) form submissions ---
        record(timeline, "phase", "Insecure Form Action Check")
        forms_js = await server.call_tool(
            "browser_evaluate_js",
            {"script": "() => JSON.stringify([...document.querySelectorAll('form')].map(f => f.action))"}
        )
        forms = json.loads(forms_js.get("result", "[]"))
        for action in forms:
            if action.startswith("http://") and "localhost" not in action:
                evidence.append(f"Form submits over HTTP: {action}")
                record(timeline, "success", f"Insecure form: {action}")

        # --- Check cookies for Secure flag ---
        record(timeline, "phase", "Cookie Security Check")
        cookies = json.loads((await server.call_tool("browser_get_cookies", {})).get("result", "[]"))
        for ck in cookies:
            name = ck.get("name", "").lower()
            if any(kw in name for kw in ("session", "auth", "token", "jwt")):
                if not ck.get("secure"):
                    evidence.append(f"Cookie '{ck.get('name')}' missing Secure flag")
                    record(timeline, "success", f"Insecure cookie: {ck.get('name')}")

        return SkillResult(
            skill_name=self.skill_name,
            success=bool(evidence),
            severity=self.default_severity,
            evidence=evidence,
            timeline=timeline,
            duration_ms=round((time.time() - start) * 1000, 2),
        )


# ===========================================================================
# A05:2025 - Security Misconfiguration
# ===========================================================================


@skill
class SecurityMisconfigurationSkill(BaseSkill):
    """OWASP A05:2025 - Security Misconfiguration detection."""

    skill_name = "owasp_a05_security_misconfiguration"
    skill_description = "OWASP A05:2025 - Debug endpoints, default configs, verbose errors, missing headers"
    default_severity = ThreatLevel.HIGH

    _DEBUG_PATHS = [
        "/__debug__",
        "/debug",
        "/debug/",
        "/_debug",
        "/phpinfo.php",
        "/server-status",
        "/server-info",
        "/.git/config",
        "/.env",
        "/.env.local",
        "/config.php",
        "/web.config",
        "/elmah.axd",
        "/trace.axd",
    ]

    _REQUIRED_HEADERS = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
    ]

    async def execute(
        self, server: Any, target_url: str, recon: ReconData | None = None
    ) -> SkillResult:
        timeline: list[TimelineEntry] = []
        start = time.time()
        evidence: list[str] = []
        base = target_url.rstrip("/")

        # --- Debug Endpoint Discovery ---
        record(timeline, "phase", "Debug Endpoint Discovery")
        for path in self._DEBUG_PATHS:
            probe = base + path
            nav = await server.call_tool("browser_navigate", {"url": probe})
            if not nav.get("success"):
                continue
            await server.call_tool("browser_wait_for", {"delay_ms": 200})
            text = (await server.call_tool("browser_get_text", {})).get("result", "")

            if "404" not in text.lower() and "not found" not in text.lower():
                if len(text) > 100:  # Has content
                    evidence.append(f"Debug/sensitive endpoint exposed: {path}")
                    record(timeline, "success", f"Exposed: {path}")

        # --- Verbose Error Detection ---
        record(timeline, "phase", "Error Message Analysis")
        error_probes = [
            base + "/api/nonexistent",
            base + "/?id='",
            base + "/user/999999999",
        ]
        for probe in error_probes:
            await server.call_tool("browser_navigate", {"url": probe})
            await server.call_tool("browser_wait_for", {"delay_ms": 300})
            text = (await server.call_tool("browser_get_text", {})).get("result", "").lower()

            error_indicators = ["stack trace", "traceback", "exception", "at line", "file path"]
            for indicator in error_indicators:
                if indicator in text:
                    evidence.append(f"Verbose error message exposed at {probe}")
                    record(timeline, "success", f"Verbose error: {indicator}")
                    break

        # --- Directory Listing ---
        record(timeline, "phase", "Directory Listing Check")
        dir_paths = ["/static/", "/uploads/", "/images/", "/files/", "/assets/"]
        for path in dir_paths:
            await server.call_tool("browser_navigate", {"url": base + path})
            await server.call_tool("browser_wait_for", {"delay_ms": 200})
            text = (await server.call_tool("browser_get_text", {})).get("result", "")
            if "index of" in text.lower() or "directory listing" in text.lower():
                evidence.append(f"Directory listing enabled: {path}")
                record(timeline, "success", f"Dir listing: {path}")

        return SkillResult(
            skill_name=self.skill_name,
            success=bool(evidence),
            severity=self.default_severity,
            evidence=evidence,
            timeline=timeline,
            duration_ms=round((time.time() - start) * 1000, 2),
        )


# ===========================================================================
# A07:2025 - Identification and Authentication Failures
# ===========================================================================


@skill
class AuthenticationFailuresSkill(BaseSkill):
    """OWASP A07:2025 - Identification and Authentication Failures."""

    skill_name = "owasp_a07_auth_failures"
    skill_description = "OWASP A07:2025 - Weak auth, session fixation, credential enumeration"
    default_severity = ThreatLevel.CRITICAL

    _WEAK_PASSWORDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("root", "root"),
        ("test", "test"),
        ("user", "user"),
        ("guest", "guest"),
    ]

    async def execute(
        self, server: Any, target_url: str, recon: ReconData | None = None
    ) -> SkillResult:
        timeline: list[TimelineEntry] = []
        start = time.time()
        evidence: list[str] = []

        # --- Check for login form ---
        record(timeline, "phase", "Login Form Analysis")
        login_check = await server.call_tool(
            "browser_evaluate_js",
            {"script": """() => JSON.stringify({
                hasUserInput: !!document.querySelector('input[name*=user i], input[name*=email i], input[type=email]'),
                hasPasswordInput: !!document.querySelector('input[type=password]'),
                hasForm: !!document.querySelector('form')
            })"""}
        )
        login_info = json.loads(login_check.get("result", "{}"))

        if not (login_info.get("hasUserInput") and login_info.get("hasPasswordInput")):
            record(timeline, "skip", "No login form detected")
            return SkillResult(
                skill_name=self.skill_name,
                success=False,
                severity=self.default_severity,
                evidence=["No login form found"],
                timeline=timeline,
                duration_ms=round((time.time() - start) * 1000, 2),
            )

        # --- Weak Password Testing ---
        record(timeline, "phase", "Weak Credential Testing")
        for username, password in self._WEAK_PASSWORDS[:4]:
            await server.call_tool("browser_navigate", {"url": target_url})
            await server.call_tool("browser_wait_for", {"delay_ms": 300})

            try:
                await server.call_tool(
                    "browser_fill",
                    {"selector": "input[type=email], input[name*=user], input[name*=email]", "value": username}
                )
                await server.call_tool(
                    "browser_fill",
                    {"selector": "input[type=password]", "value": password}
                )
                await server.call_tool("browser_submit_form", {"selector": "form"})
                await server.call_tool("browser_wait_for", {"delay_ms": 1000})

                text = (await server.call_tool("browser_get_text", {})).get("result", "").lower()
                if any(kw in text for kw in ("dashboard", "welcome", "logout", "profile", "home")):
                    evidence.append(f"Weak credentials accepted: {username}:{password}")
                    record(timeline, "success", f"Login: {username}:{password}")
                    break
            except Exception:
                continue

        # --- Username Enumeration Check ---
        record(timeline, "phase", "Username Enumeration Check")
        responses: list[str] = []
        test_users = ["admin", "nonexistent_user_xyz123"]

        for user in test_users:
            await server.call_tool("browser_navigate", {"url": target_url})
            await server.call_tool("browser_wait_for", {"delay_ms": 300})
            try:
                await server.call_tool(
                    "browser_fill",
                    {"selector": "input[type=email], input[name*=user]", "value": user}
                )
                await server.call_tool(
                    "browser_fill",
                    {"selector": "input[type=password]", "value": "wrongpassword"}
                )
                await server.call_tool("browser_submit_form", {"selector": "form"})
                await server.call_tool("browser_wait_for", {"delay_ms": 800})
                text = (await server.call_tool("browser_get_text", {})).get("result", "")
                responses.append(text)
            except Exception:
                pass

        if len(responses) == 2 and responses[0] != responses[1]:
            evidence.append("Username enumeration possible - different error messages for valid/invalid users")
            record(timeline, "success", "Username enumeration")

        return SkillResult(
            skill_name=self.skill_name,
            success=bool(evidence),
            severity=self.default_severity,
            evidence=evidence,
            timeline=timeline,
            duration_ms=round((time.time() - start) * 1000, 2),
        )


# ===========================================================================
# A10:2025 - Server-Side Request Forgery (SSRF)
# ===========================================================================


@skill
class SSRFSkill(BaseSkill):
    """OWASP A10:2025 - Server-Side Request Forgery detection."""

    skill_name = "owasp_a10_ssrf"
    skill_description = "OWASP A10:2025 - SSRF via URL parameters and form inputs"
    default_severity = ThreatLevel.HIGH

    _SSRF_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://metadata.google.internal/",  # GCP metadata
        "file:///etc/passwd",
        "dict://localhost:11211/",
    ]

    _URL_PARAMS = ["url", "link", "src", "source", "redirect", "uri", "path", "dest", "destination", "file", "page"]

    async def execute(
        self, server: Any, target_url: str, recon: ReconData | None = None
    ) -> SkillResult:
        timeline: list[TimelineEntry] = []
        start = time.time()
        evidence: list[str] = []
        base = target_url.rstrip("/")

        # --- URL Parameter SSRF ---
        record(timeline, "phase", "URL Parameter SSRF Testing")
        for param in self._URL_PARAMS[:5]:
            for payload in self._SSRF_PAYLOADS[:3]:
                probe = f"{base}?{param}={payload}"
                record(timeline, "probe", f"SSRF: {param}={payload[:30]}")

                nav = await server.call_tool("browser_navigate", {"url": probe})
                if not nav.get("success"):
                    continue
                await server.call_tool("browser_wait_for", {"delay_ms": 500})
                text = (await server.call_tool("browser_get_text", {})).get("result", "")

                # Check for internal data exposure
                if any(kw in text for kw in ("root:", "ami-id", "instance-id", "metadata")):
                    evidence.append(f"SSRF successful via ?{param}: internal data exposed")
                    record(timeline, "success", f"SSRF: {param}")
                    break

        # --- Form Input SSRF ---
        record(timeline, "phase", "Form Input SSRF Testing")
        inputs_js = await server.call_tool(
            "browser_evaluate_js",
            {"script": """() => JSON.stringify([...document.querySelectorAll('input')].map(i => ({
                name: i.name, type: i.type, id: i.id
            })))"""}
        )
        inputs = json.loads(inputs_js.get("result", "[]"))

        for inp in inputs:
            name = (inp.get("name") or "").lower()
            if any(param in name for param in self._URL_PARAMS):
                selector = f"[name='{inp.get('name')}']" if inp.get("name") else f"#{inp.get('id')}"
                for payload in self._SSRF_PAYLOADS[:2]:
                    try:
                        await server.call_tool("browser_fill", {"selector": selector, "value": payload})
                        await server.call_tool("browser_submit_form", {"selector": "form"})
                        await server.call_tool("browser_wait_for", {"delay_ms": 500})
                        text = (await server.call_tool("browser_get_text", {})).get("result", "")

                        if "root:" in text or "metadata" in text.lower():
                            evidence.append(f"SSRF via form input '{inp.get('name')}'")
                            record(timeline, "success", f"Form SSRF: {inp.get('name')}")
                    except Exception:
                        pass

        return SkillResult(
            skill_name=self.skill_name,
            success=bool(evidence),
            severity=self.default_severity,
            evidence=evidence,
            timeline=timeline,
            duration_ms=round((time.time() - start) * 1000, 2),
        )
