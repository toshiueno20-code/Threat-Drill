"""Playwright MCP Server — localhost-only browser-automation tool server.

Exposes browser-control tools via the Model Context Protocol (MCP) so that
the Red Team AI can navigate pages, interact with forms, execute JS, and
take screenshots — all restricted to localhost targets only.
"""

import json
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from playwright.async_api import async_playwright, Page, BrowserContext

from shared.utils import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# URL Guard — localhost-only enforcement
# ---------------------------------------------------------------------------


class LocalhostGuardError(Exception):
    """Raised when a target URL does not resolve to localhost."""


def _resolve_host(hostname: str) -> List[str]:
    """DNS-resolve hostname → list of IP strings."""
    try:
        results = socket.getaddrinfo(hostname, None)
        return list({r[4][0] for r in results})
    except socket.gaierror:
        return []


_LOCALHOST_IPS = {"127.0.0.1", "::1", "0.0.0.0"}


def validate_localhost_url(url: str) -> str:
    """Validate that *url* targets a localhost address.

    Returns the validated URL on success.
    Raises LocalhostGuardError if the target resolves to an external IP.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        raise LocalhostGuardError(f"Invalid URL (no hostname): {url}")

    # Direct localhost names
    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return url

    # DNS resolution check
    resolved = _resolve_host(hostname)
    if not resolved or not resolved_is_localhost(resolved):
        raise LocalhostGuardError(
            f"Target '{hostname}' resolves to {resolved or ['<unresolvable>']}, "
            f"which is not localhost. Red Team attacks are restricted to localhost only."
        )

    return url


def resolved_is_localhost(ips: List[str]) -> bool:
    """True if ALL resolved IPs are localhost addresses."""
    return all(ip in _LOCALHOST_IPS for ip in ips)


# ---------------------------------------------------------------------------
# MCP Tool Definitions (schema registry)
# ---------------------------------------------------------------------------

MCP_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "browser_navigate",
        "description": "Navigate the browser to a given URL. URL MUST be localhost.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL (localhost only)"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "browser_screenshot",
        "description": "Capture a full-page screenshot as base64 PNG.",
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "browser_get_text",
        "description": "Extract all visible text content from the current page.",
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "browser_get_html",
        "description": "Return the full page HTML source.",
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "browser_click",
        "description": "Click on an element matching a CSS selector or text.",
        "input_schema": {
            "type": "object",
            "properties": {
                "selector": {
                    "type": "string",
                    "description": "CSS selector or visible text to click",
                },
            },
            "required": ["selector"],
        },
    },
    {
        "name": "browser_type",
        "description": "Type text into an input/textarea matched by CSS selector.",
        "input_schema": {
            "type": "object",
            "properties": {
                "selector": {"type": "string", "description": "CSS selector for the input"},
                "text": {"type": "string", "description": "Text to type"},
            },
            "required": ["selector", "text"],
        },
    },
    {
        "name": "browser_fill",
        "description": "Clear and fill an input element (faster than type for programmatic use).",
        "input_schema": {
            "type": "object",
            "properties": {
                "selector": {"type": "string", "description": "CSS selector for the input"},
                "value": {"type": "string", "description": "Value to set"},
            },
            "required": ["selector", "value"],
        },
    },
    {
        "name": "browser_select_option",
        "description": "Select an option in a <select> element.",
        "input_schema": {
            "type": "object",
            "properties": {
                "selector": {"type": "string", "description": "CSS selector for <select>"},
                "value": {"type": "string", "description": "Option value to select"},
            },
            "required": ["selector", "value"],
        },
    },
    {
        "name": "browser_submit_form",
        "description": "Submit a form matched by CSS selector.",
        "input_schema": {
            "type": "object",
            "properties": {
                "selector": {
                    "type": "string",
                    "description": "CSS selector for the <form> element",
                },
            },
            "required": ["selector"],
        },
    },
    {
        "name": "browser_evaluate_js",
        "description": "Execute arbitrary JavaScript in the page context and return the result.",
        "input_schema": {
            "type": "object",
            "properties": {
                "script": {"type": "string", "description": "JS code to evaluate"},
            },
            "required": ["script"],
        },
    },
    {
        "name": "browser_get_cookies",
        "description": "Return all cookies for the current page as a JSON array.",
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "browser_set_cookie",
        "description": "Inject a cookie into the current page context.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "value": {"type": "string"},
                "path": {"type": "string", "description": "Cookie path (default /)"},
            },
            "required": ["name", "value"],
        },
    },
    {
        "name": "browser_get_local_storage",
        "description": "Dump all keys from localStorage.",
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "browser_wait_for",
        "description": "Wait for a selector to appear or for a specified ms delay.",
        "input_schema": {
            "type": "object",
            "properties": {
                "selector": {
                    "type": "string",
                    "description": "CSS selector to wait for (optional)",
                },
                "delay_ms": {
                    "type": "integer",
                    "description": "Fixed delay in ms (used if no selector given)",
                },
            },
        },
    },
    {
        "name": "browser_get_network_responses",
        "description": "Return captured network response bodies for analysis (XHR/fetch).",
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
]


# ---------------------------------------------------------------------------
# PlaywrightMCPServer — stateful browser session manager
# ---------------------------------------------------------------------------


class PlaywrightMCPServer:
    """Manages a Playwright browser session and dispatches MCP tool calls.

    Lifecycle:
        server = PlaywrightMCPServer()
        await server.start()          # launches browser
        result = await server.call_tool("browser_navigate", {"url": "..."})
        await server.stop()           # closes browser + playwright
    """

    def __init__(self, headless: bool = True, timeout_ms: int = 30_000):
        self._headless = headless
        self._timeout_ms = timeout_ms
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        # Captured network responses (body, url, status) for exfil analysis
        self._network_log: List[Dict[str, Any]] = []

    # --- lifecycle ----------------------------------------------------------

    async def start(self) -> None:
        """Launch Chromium browser."""
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=self._headless)
        self._context = await self._browser.new_context()
        self._page = await self._context.new_page()
        self._page.on("response", self._capture_response)
        logger.info("PlaywrightMCPServer started", headless=self._headless)

    async def stop(self) -> None:
        """Gracefully close everything."""
        try:
            if self._page:
                await self._page.close()
            if self._context:
                await self._context.close()
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
        except Exception as e:
            logger.warning("Error during PlaywrightMCPServer stop", error=str(e))
        finally:
            self._page = None
            self._context = None
            self._browser = None
            self._playwright = None
            self._network_log = []
        logger.info("PlaywrightMCPServer stopped")

    # --- network capture ----------------------------------------------------

    async def _capture_response(self, response: Any) -> None:
        """Record XHR/fetch response for later inspection."""
        try:
            body = await response.text()
            self._network_log.append({
                "url": response.url,
                "status": response.status,
                "headers": dict(response.headers),
                "body": body[:4096],  # cap at 4KB per response
            })
        except Exception:
            pass  # binary/streaming responses may fail — skip silently

    # --- tool dispatch ------------------------------------------------------

    async def call_tool(self, tool_name: str, tool_input: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a single MCP tool call.

        Returns:
            {"success": bool, "result": <value>, "error": <str | None>}
        """
        if not self._page:
            return {"success": False, "result": None, "error": "Browser session not started"}

        logger.info("MCP tool called", tool=tool_name, input_keys=list(tool_input.keys()))

        try:
            handler = _TOOL_DISPATCH.get(tool_name)
            if handler is None:
                return {"success": False, "result": None, "error": f"Unknown tool: {tool_name}"}

            result = await handler(self, tool_input)
            return {"success": True, "result": result, "error": None}

        except LocalhostGuardError as e:
            logger.warning("Localhost guard blocked request", tool=tool_name, reason=str(e))
            return {"success": False, "result": None, "error": str(e)}
        except Exception as e:
            logger.error("Tool execution error", tool=tool_name, error=str(e))
            return {"success": False, "result": None, "error": str(e)}

    # --- list available tools -----------------------------------------------

    def list_tools(self) -> List[Dict[str, Any]]:
        """Return MCP tool schema list."""
        return MCP_TOOLS


# ---------------------------------------------------------------------------
# Individual tool implementations
# ---------------------------------------------------------------------------


async def _navigate(server: PlaywrightMCPServer, inp: Dict[str, Any]) -> str:
    url = validate_localhost_url(inp["url"])
    await server._page.goto(url, timeout=server._timeout_ms)
    return f"Navigated to {url}"


async def _screenshot(server: PlaywrightMCPServer, inp: Dict[str, Any]) -> str:
    import base64

    buf = await server._page.screenshot(full_page=True)
    return base64.b64encode(buf).decode()


async def _get_text(server: PlaywrightMCPServer, inp: Dict[str, Any]) -> str:
    return await server._page.inner_text("body")


async def _get_html(server: PlaywrightMCPServer, inp: Dict[str, Any]) -> str:
    return await server._page.content()


async def _click(server: PlaywrightMCPServer, inp: Dict[str, Any]) -> str:
    selector = inp["selector"]
    # Try as CSS selector first; fall back to text match
    try:
        await server._page.click(selector, timeout=server._timeout_ms)
    except Exception:
        await server._page.click(f"text={selector}", timeout=server._timeout_ms)
    return f"Clicked: {selector}"


async def _type(server: PlaywrightMCPServer, inp: Dict[str, Any]) -> str:
    await server._page.fill(inp["selector"], "")  # clear first
    await server._page.type(inp["selector"], inp["text"], delay=30)
    return f"Typed into {inp['selector']}"


async def _fill(server: PlaywrightMCPServer, inp: Dict[str, Any]) -> str:
    await server._page.fill(inp["selector"], inp["value"])
    return f"Filled {inp['selector']}"


async def _select_option(server: PlaywrightMCPServer, inp: Dict[str, Any]) -> str:
    await server._page.select_option(inp["selector"], inp["value"])
    return f"Selected '{inp['value']}' in {inp['selector']}"


async def _submit_form(server: PlaywrightMCPServer, inp: Dict[str, Any]) -> str:
    # Locate the form and trigger submit
    await server._page.evaluate(
        "sel => document.querySelector(sel).submit()",
        inp["selector"],
    )
    return f"Submitted form: {inp['selector']}"


async def _evaluate_js(server: PlaywrightMCPServer, inp: Dict[str, Any]) -> Any:
    result = await server._page.evaluate(inp["script"])
    # Serialise non-string results
    if not isinstance(result, str):
        result = json.dumps(result)
    return result


async def _get_cookies(server: PlaywrightMCPServer, inp: Dict[str, Any]) -> str:
    cookies = await server._context.cookies()
    return json.dumps(cookies)


async def _set_cookie(server: PlaywrightMCPServer, inp: Dict[str, Any]) -> str:
    cookie: Dict[str, Any] = {
        "name": inp["name"],
        "value": inp["value"],
        "domain": "localhost",
        "path": inp.get("path", "/"),
    }
    await server._context.add_cookies([cookie])
    return f"Cookie '{inp['name']}' set"


async def _get_local_storage(server: PlaywrightMCPServer, inp: Dict[str, Any]) -> str:
    data = await server._page.evaluate(
        "() => JSON.stringify(Object.fromEntries(Object.keys(localStorage).map(k => [k, localStorage.getItem(k)])))"
    )
    return data


async def _wait_for(server: PlaywrightMCPServer, inp: Dict[str, Any]) -> str:
    selector = inp.get("selector")
    delay = inp.get("delay_ms", 1000)
    if selector:
        await server._page.wait_for_selector(selector, timeout=server._timeout_ms)
        return f"Selector '{selector}' appeared"
    else:
        import asyncio

        await asyncio.sleep(delay / 1000.0)
        return f"Waited {delay}ms"


async def _get_network_responses(server: PlaywrightMCPServer, inp: Dict[str, Any]) -> str:
    return json.dumps(server._network_log)


# ---------------------------------------------------------------------------
# Dispatch table — maps tool name → handler
# ---------------------------------------------------------------------------

_TOOL_DISPATCH: Dict[str, Any] = {
    "browser_navigate": _navigate,
    "browser_screenshot": _screenshot,
    "browser_get_text": _get_text,
    "browser_get_html": _get_html,
    "browser_click": _click,
    "browser_type": _type,
    "browser_fill": _fill,
    "browser_select_option": _select_option,
    "browser_submit_form": _submit_form,
    "browser_evaluate_js": _evaluate_js,
    "browser_get_cookies": _get_cookies,
    "browser_set_cookie": _set_cookie,
    "browser_get_local_storage": _get_local_storage,
    "browser_wait_for": _wait_for,
    "browser_get_network_responses": _get_network_responses,
}
