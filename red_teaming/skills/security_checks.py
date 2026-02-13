"""Read-only security assessment skills for web applications.

These skills intentionally avoid exploit execution. They only inspect
browser-visible state, response metadata, and configuration signals.
"""

from __future__ import annotations

import json
import re
import time
from urllib.parse import urljoin, urlparse
from typing import Any

from shared.schemas import ThreatLevel
from .base import BaseSkill, ReconData, SkillResult, TimelineEntry, record, skill


def _safe_json_loads(raw: str, fallback: Any) -> Any:
    try:
        return json.loads(raw)
    except Exception:
        return fallback


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _is_https(url: str) -> bool:
    try:
        return urlparse(url).scheme.lower() == "https"
    except Exception:
        return False


def _is_local_target(url: str) -> bool:
    return _host(url) in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _highest_severity(values: list[ThreatLevel], default: ThreatLevel) -> ThreatLevel:
    rank = {
        ThreatLevel.SAFE: 0,
        ThreatLevel.LOW: 1,
        ThreatLevel.MEDIUM: 2,
        ThreatLevel.HIGH: 3,
        ThreatLevel.CRITICAL: 4,
    }
    best = default
    best_rank = rank[default]
    for value in values:
        r = rank.get(value, 0)
        if r > best_rank:
            best = value
            best_rank = r
    return best


def _extract_path_candidates(html: str, base_url: str) -> list[str]:
    # Conservative parser: only inspect links/scripts/forms already exposed in page source.
    candidates: set[str] = set()
    for pattern in (
        r'href=["\']([^"\']+)["\']',
        r'src=["\']([^"\']+)["\']',
        r'action=["\']([^"\']+)["\']',
    ):
        for m in re.findall(pattern, html, re.IGNORECASE):
            abs_url = urljoin(base_url, m)
            parsed = urlparse(abs_url)
            if parsed.netloc and parsed.netloc != urlparse(base_url).netloc:
                continue
            if parsed.path:
                candidates.add(parsed.path.lower())
    return sorted(candidates)


def _response_headers(network_responses: list[dict[str, Any]], target_url: str) -> dict[str, str]:
    if not network_responses:
        return {}

    target_host = _host(target_url)
    best: dict[str, Any] | None = None
    for item in network_responses:
        if _host(item.get("url", "")) == target_host:
            best = item
            break

    if best is None:
        best = network_responses[0]

    raw_headers = best.get("headers") or {}
    return {str(k).lower(): str(v) for k, v in raw_headers.items()}


def _parse_html_attrs(raw_attrs: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for m in re.finditer(
        r'([^\s=/>]+)\s*=\s*("([^"]*)"|\'([^\']*)\'|([^\s>]+))',
        raw_attrs,
        re.IGNORECASE,
    ):
        key = str(m.group(1) or "").strip().lower()
        value = m.group(3) or m.group(4) or m.group(5) or ""
        attrs[key] = value
    return attrs


def _extract_script_descriptors(html: str) -> list[dict[str, Any]]:
    scripts: list[dict[str, Any]] = []
    for m in re.finditer(r"<script\b([^>]*)>(.*?)</script>", html, re.IGNORECASE | re.DOTALL):
        attrs = _parse_html_attrs(m.group(1) or "")
        src = str(attrs.get("src", ""))
        scripts.append(
            {
                "src": src,
                "integrity": str(attrs.get("integrity", "")),
                "inline": src == "",
            }
        )
    return scripts


@skill
class SecurityMisconfigurationReviewSkill(BaseSkill):
    """OWASP A05-style configuration posture review."""

    skill_name = "owasp_a05_security_misconfiguration"
    skill_description = (
        "OWASP A05-style read-only review: security headers, server disclosure, and debug artifacts"
    )
    default_severity = ThreatLevel.HIGH

    async def execute(self, server: Any, target_url: str, recon: ReconData | None = None) -> SkillResult:
        timeline: list[TimelineEntry] = []
        evidence: list[str] = []
        severities: list[ThreatLevel] = []
        start = time.time()

        network_raw = (await server.call_tool("browser_get_network_responses", {})).get("result", "[]")
        network = _safe_json_loads(network_raw, [])
        headers = _response_headers(network, target_url)
        record(timeline, "recon", f"captured_responses={len(network)}")

        required = [
            "x-content-type-options",
            "x-frame-options",
            "content-security-policy",
            "referrer-policy",
        ]
        missing = [h for h in required if h not in headers]
        if missing:
            evidence.append(f"Missing security headers: {', '.join(missing)}")
            severities.append(ThreatLevel.HIGH)

        if _is_https(target_url) and "strict-transport-security" not in headers:
            evidence.append("Missing Strict-Transport-Security on HTTPS origin")
            severities.append(ThreatLevel.HIGH)

        server_header = headers.get("server")
        if server_header:
            evidence.append(f"Server header discloses stack: '{server_header[:60]}'")
            severities.append(ThreatLevel.MEDIUM)

        combined = ((recon.text if recon else "") + "\n" + (recon.html if recon else "")).lower()
        debug_markers = ["stack trace", "traceback", "debug=true", "__debug__", "exception at"]
        found_debug = [m for m in debug_markers if m in combined]
        if found_debug:
            evidence.append(f"Debug/error artifacts visible in rendered content: {', '.join(found_debug)}")
            severities.append(ThreatLevel.HIGH)

        return SkillResult(
            skill_name=self.skill_name,
            success=bool(evidence),
            severity=_highest_severity(severities, self.default_severity),
            evidence=evidence,
            timeline=timeline,
            duration_ms=round((time.time() - start) * 1000, 2),
        )


@skill
class CryptographicPostureReviewSkill(BaseSkill):
    """OWASP A02-style transport/cookie/secret posture review."""

    skill_name = "owasp_a02_cryptographic_failures"
    skill_description = (
        "OWASP A02-style read-only review: cookie hardening, local secret exposure, and transport risks"
    )
    default_severity = ThreatLevel.HIGH

    _SECRET_PATTERNS = [
        (r"AKIA[0-9A-Z]{16}", "AWS key pattern"),
        (r"ghp_[A-Za-z0-9]{36}", "GitHub token pattern"),
        (r"sk-[A-Za-z0-9]{20,}", "LLM API key pattern"),
        (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private key material"),
        (r"(?i)api[_-]?key\s*[:=]\s*['\"][^'\"]{8,}", "hardcoded API key declaration"),
    ]

    async def execute(self, server: Any, target_url: str, recon: ReconData | None = None) -> SkillResult:
        timeline: list[TimelineEntry] = []
        evidence: list[str] = []
        severities: list[ThreatLevel] = []
        start = time.time()

        data = recon or ReconData(url=target_url)
        record(timeline, "recon", f"cookies={len(data.cookies)} local_storage_keys={len(data.local_storage)}")

        if not _is_https(target_url) and not _is_local_target(target_url):
            evidence.append("Target is not HTTPS; credentials may be exposed in transit")
            severities.append(ThreatLevel.HIGH)

        for ck in data.cookies:
            name = str(ck.get("name", "")).lower()
            if any(token in name for token in ("session", "auth", "token", "jwt")):
                if not ck.get("secure"):
                    evidence.append(f"Cookie '{ck.get('name')}' missing Secure flag")
                    severities.append(ThreatLevel.HIGH)
                if not ck.get("httpOnly"):
                    evidence.append(f"Cookie '{ck.get('name')}' missing HttpOnly flag")
                    severities.append(ThreatLevel.HIGH)
                same_site = str(ck.get("sameSite", "")).lower()
                if same_site in ("", "none"):
                    evidence.append(f"Cookie '{ck.get('name')}' has weak SameSite policy ({same_site or 'unset'})")
                    severities.append(ThreatLevel.MEDIUM)

        for key, value in data.local_storage.items():
            value_s = str(value or "")
            key_l = key.lower()
            if any(token in key_l for token in ("token", "secret", "api", "auth", "jwt", "password")):
                evidence.append(f"Sensitive-like key in localStorage: '{key}' (len={len(value_s)})")
                severities.append(ThreatLevel.MEDIUM)

        searchable = data.html + "\n" + data.text + "\n" + "\n".join(str(v or "") for v in data.local_storage.values())
        for pattern, label in self._SECRET_PATTERNS:
            if re.search(pattern, searchable):
                evidence.append(f"Potential secret exposure detected: {label}")
                severities.append(ThreatLevel.CRITICAL)

        return SkillResult(
            skill_name=self.skill_name,
            success=bool(evidence),
            severity=_highest_severity(severities, self.default_severity),
            evidence=evidence,
            timeline=timeline,
            duration_ms=round((time.time() - start) * 1000, 2),
        )


@skill
class BrokenAccessControlSurfaceReviewSkill(BaseSkill):
    """OWASP A01-style surface exposure review without forced actions."""

    skill_name = "owasp_a01_broken_access_control"
    skill_description = (
        "OWASP A01-style read-only review: exposed admin paths and access-control-sensitive routes"
    )
    default_severity = ThreatLevel.HIGH

    _SENSITIVE_TOKENS = (
        "/admin",
        "/manage",
        "/dashboard",
        "/internal",
        "/debug",
        "/console",
        "/actuator",
        "/private",
    )

    async def execute(self, server: Any, target_url: str, recon: ReconData | None = None) -> SkillResult:
        timeline: list[TimelineEntry] = []
        evidence: list[str] = []
        severities: list[ThreatLevel] = []
        start = time.time()

        html = recon.html if recon else (await server.call_tool("browser_get_html", {})).get("result", "")
        candidates = _extract_path_candidates(html, target_url)
        record(timeline, "recon", f"surface_paths={len(candidates)}")

        risky = [p for p in candidates if any(token in p for token in self._SENSITIVE_TOKENS)]
        if risky:
            evidence.append(
                "Sensitive route patterns are directly discoverable from client-side resources: "
                + ", ".join(risky[:8])
            )
            severities.append(ThreatLevel.MEDIUM)

        base = target_url.rstrip("/")
        for endpoint in ("/robots.txt", "/sitemap.xml"):
            nav = await server.call_tool("browser_navigate", {"url": f"{base}{endpoint}"})
            if not nav.get("success"):
                continue
            text = (await server.call_tool("browser_get_text", {})).get("result", "")
            if any(token in text.lower() for token in ("admin", "internal", "private", "debug")):
                evidence.append(f"{endpoint} exposes sensitive route hints")
                severities.append(ThreatLevel.MEDIUM)

        # Restore original page for downstream skills.
        await server.call_tool("browser_navigate", {"url": target_url})

        return SkillResult(
            skill_name=self.skill_name,
            success=bool(evidence),
            severity=_highest_severity(severities, self.default_severity),
            evidence=evidence,
            timeline=timeline,
            duration_ms=round((time.time() - start) * 1000, 2),
        )


@skill
class DataIntegrityReviewSkill(BaseSkill):
    """OWASP A08-style client integrity review."""

    skill_name = "owasp_a08_data_integrity_failures"
    skill_description = (
        "OWASP A08-style read-only review: external script integrity, unpinned assets, and inline script posture"
    )
    default_severity = ThreatLevel.MEDIUM

    async def execute(self, server: Any, target_url: str, recon: ReconData | None = None) -> SkillResult:
        timeline: list[TimelineEntry] = []
        evidence: list[str] = []
        severities: list[ThreatLevel] = []
        start = time.time()

        html = recon.html if recon else (await server.call_tool("browser_get_html", {})).get("result", "")
        scripts = _extract_script_descriptors(html)
        record(timeline, "recon", f"scripts={len(scripts)}")

        inline_count = 0
        for script in scripts:
            src = str(script.get("src", ""))
            integrity = str(script.get("integrity", ""))
            inline = bool(script.get("inline"))
            if inline:
                inline_count += 1
                continue
            if src.startswith("http://") and not _is_local_target(src):
                evidence.append(f"Insecure script transport (HTTP): {src}")
                severities.append(ThreatLevel.HIGH)
            if src.startswith("https://") and not integrity:
                evidence.append(f"External script without SRI: {src}")
                severities.append(ThreatLevel.MEDIUM)
            if "@latest" in src.lower() or "/latest/" in src.lower():
                evidence.append(f"Unpinned external dependency reference: {src}")
                severities.append(ThreatLevel.MEDIUM)

        if inline_count > 8:
            evidence.append(f"Large number of inline scripts ({inline_count}) increases XSS blast radius")
            severities.append(ThreatLevel.MEDIUM)

        return SkillResult(
            skill_name=self.skill_name,
            success=bool(evidence),
            severity=_highest_severity(severities, self.default_severity),
            evidence=evidence,
            timeline=timeline,
            duration_ms=round((time.time() - start) * 1000, 2),
        )


@skill
class PromptInjectionGuardrailReviewSkill(BaseSkill):
    """OWASP LLM01-style guardrail posture review without injection attempts."""

    skill_name = "owasp_llm01_prompt_injection"
    skill_description = (
        "OWASP LLM01-style read-only review: AI input surface and prompt-injection guardrail indicators"
    )
    default_severity = ThreatLevel.HIGH

    _AI_HINTS = ("chat", "assistant", "prompt", "message", "ask ai", "copilot")
    _GUARDRAIL_HINTS = (
        "cannot comply",
        "safety",
        "policy",
        "restricted",
        "guardrail",
        "do not reveal",
        "instructions are fixed",
    )

    async def execute(self, server: Any, target_url: str, recon: ReconData | None = None) -> SkillResult:
        timeline: list[TimelineEntry] = []
        evidence: list[str] = []
        severities: list[ThreatLevel] = []
        start = time.time()

        data = recon or ReconData(url=target_url)
        ai_inputs = []
        for inp in data.inputs:
            joined = " ".join(
                str(inp.get(k, "")).lower()
                for k in ("name", "id", "placeholder", "type", "tag")
            )
            if any(h in joined for h in self._AI_HINTS):
                ai_inputs.append(inp)

        record(timeline, "recon", f"ai_input_candidates={len(ai_inputs)}")

        if not ai_inputs:
            return SkillResult(
                skill_name=self.skill_name,
                success=False,
                severity=ThreatLevel.LOW,
                evidence=["No AI/chat input surface detected"],
                timeline=timeline,
                duration_ms=round((time.time() - start) * 1000, 2),
            )

        text_blob = f"{data.text}\n{data.html}".lower()
        guardrail_hits = [h for h in self._GUARDRAIL_HINTS if h in text_blob]
        if not guardrail_hits:
            evidence.append(
                "AI input surface is present but no visible guardrail/policy signals were detected"
            )
            severities.append(ThreatLevel.HIGH)
        else:
            evidence.append(
                "Guardrail indicators found, but should be validated server-side (not just UI text): "
                + ", ".join(guardrail_hits[:5])
            )
            severities.append(ThreatLevel.MEDIUM)

        return SkillResult(
            skill_name=self.skill_name,
            success=bool(evidence),
            severity=_highest_severity(severities, self.default_severity),
            evidence=evidence,
            timeline=timeline,
            duration_ms=round((time.time() - start) * 1000, 2),
        )


@skill
class FormProtectionReviewSkill(BaseSkill):
    """Read-only form security review for CSRF and transport posture."""

    skill_name = "web_form_protection_review"
    skill_description = (
        "Read-only form review: CSRF token presence, password field transport, and risky form design cues"
    )
    default_severity = ThreatLevel.MEDIUM

    async def execute(self, server: Any, target_url: str, recon: ReconData | None = None) -> SkillResult:
        timeline: list[TimelineEntry] = []
        evidence: list[str] = []
        severities: list[ThreatLevel] = []
        start = time.time()

        data = recon or ReconData(url=target_url)
        forms = data.forms
        inputs = data.inputs
        record(timeline, "recon", f"forms={len(forms)} inputs={len(inputs)}")

        if not forms:
            return SkillResult(
                skill_name=self.skill_name,
                success=False,
                severity=ThreatLevel.LOW,
                evidence=["No forms detected on the current page"],
                timeline=timeline,
                duration_ms=round((time.time() - start) * 1000, 2),
            )

        for form in forms:
            method = str(form.get("method", "get")).upper()
            action = str(form.get("action", ""))
            has_csrf = bool(form.get("hasCsrfToken"))
            if method in {"POST", "PUT", "PATCH", "DELETE"} and not has_csrf:
                evidence.append(
                    f"State-changing form lacks CSRF token (method={method}, action={action or 'current_page'})"
                )
                severities.append(ThreatLevel.HIGH)

            if action.startswith("http://") and _is_https(target_url):
                evidence.append(f"HTTPS page posts to insecure form action: {action}")
                severities.append(ThreatLevel.HIGH)

        pwd_inputs = [i for i in inputs if str(i.get("type", "")).lower() == "password"]
        if pwd_inputs and not _is_https(target_url) and not _is_local_target(target_url):
            evidence.append("Password input detected on non-HTTPS origin")
            severities.append(ThreatLevel.HIGH)

        return SkillResult(
            skill_name=self.skill_name,
            success=bool(evidence),
            severity=_highest_severity(severities, self.default_severity),
            evidence=evidence,
            timeline=timeline,
            duration_ms=round((time.time() - start) * 1000, 2),
        )
