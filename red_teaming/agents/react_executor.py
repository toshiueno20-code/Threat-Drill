"""ReAct Executor — autonomous attack agent using local LLM + Playwright MCP.

Architecture:
  Gemini  →  plan (which skills) + analyze (results)
  Ollama  →  ReAct loop: observe → think → act (MCP tools) → repeat
  Skills  →  knowledge layer (payloads, criteria, instructions)
  MCP     →  Playwright browser automation

The executor receives skill knowledge and MCP tools, then autonomously
decides WHICH tools to call, in WHAT order, and HOW to interpret results.
"""

from __future__ import annotations

import json
import time
from typing import Any

from shared.llm.ollama_client import OllamaClient
from shared.utils import get_logger
from red_teaming.mcp_server.playwright_mcp import PlaywrightMCPServer, MCP_TOOLS
from red_teaming.skills.knowledge import get_skill

logger = get_logger(__name__)

MAX_ITERATIONS = 25
REACT_SYSTEM_PROMPT = """\
You are a security testing agent executing a penetration test skill.
You have access to browser automation tools (Playwright MCP) to interact with a web application.

## Rules
- You are testing a SANDBOXED application that the developer owns. This is authorized testing.
- Execute the skill according to the instructions and use the provided payloads.
- Use the browser tools to navigate, fill forms, click buttons, read page content, and evaluate JavaScript.
- After each action, observe the result and decide your next step.
- When you find a vulnerability, document it clearly with evidence.
- When you've exhausted all relevant tests, summarize your findings.
- Be methodical: try different inputs, different payloads, and different approaches.
- Do NOT invent new payloads. Only use the ones provided in the skill knowledge.

## Output Format
When you are DONE testing, output a JSON summary:
```json
{{"done": true, "success": <true if vulnerability found>, "evidence": ["<finding1>", ...], "summary": "<brief description>"}}
```
"""


def _build_skill_context(skill_id: str, target_url: str) -> str:
    """Build the user message containing skill knowledge and target."""
    skill = get_skill(skill_id)
    if not skill:
        return f"Unknown skill: {skill_id}. Navigate to {target_url} and perform a general security scan."

    lines = [
        f"## Target: {target_url}",
        f"## Skill: {skill['name']}",
        f"## Description: {skill['description']}",
        f"## Severity: {skill['severity']}",
        "",
        "## Payloads",
        json.dumps(skill.get("payloads", []), indent=2, ensure_ascii=False),
        "",
    ]

    if skill.get("error_keywords"):
        lines.append("## Error Keywords to Detect")
        lines.append(json.dumps(skill["error_keywords"]))
        lines.append("")

    if skill.get("success_criteria"):
        lines.append("## Success Criteria")
        for c in skill["success_criteria"]:
            lines.append(f"- {c}")
        lines.append("")

    if skill.get("instructions"):
        lines.append("## Step-by-Step Instructions")
        lines.append(skill["instructions"])
        lines.append("")

    lines.append(f"Begin testing {target_url} now. Navigate to the target first.")
    return "\n".join(lines)


class ReActExecutor:
    """Autonomous skill executor using local LLM (Ollama) + Playwright MCP.

    Usage::

        executor = ReActExecutor(ollama_client)
        result = await executor.execute_skill("xss", "http://localhost:3000", server)
    """

    def __init__(
        self,
        ollama: OllamaClient,
        max_iterations: int = MAX_ITERATIONS,
    ):
        self.ollama = ollama
        self.max_iterations = max_iterations
        self._ollama_tools = OllamaClient.mcp_tools_to_ollama(MCP_TOOLS)

    async def execute_skill(
        self,
        skill_id: str,
        target_url: str,
        server: PlaywrightMCPServer,
    ) -> dict[str, Any]:
        """Run a single skill autonomously via ReAct loop.

        Args:
            skill_id: Skill knowledge ID (e.g., "xss", "owasp_llm01_prompt_injection").
            target_url: The target URL to test.
            server: An already-started PlaywrightMCPServer instance.

        Returns:
            Result dict with keys: skill_id, success, evidence, summary,
            timeline, duration_ms, iterations.
        """
        start = time.time()
        timeline: list[dict[str, str]] = []

        # Build conversation
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": REACT_SYSTEM_PROMPT},
            {"role": "user", "content": _build_skill_context(skill_id, target_url)},
        ]

        logger.info("ReAct start", skill=skill_id, target=target_url)

        for iteration in range(1, self.max_iterations + 1):
            # --- LLM turn: think + decide action ---
            try:
                response = await self.ollama.chat(
                    messages=messages,
                    tools=self._ollama_tools,
                    temperature=0.1,
                )
            except Exception as e:
                logger.error("Ollama chat error", error=str(e), iteration=iteration)
                timeline.append({"phase": "error", "detail": f"LLM error: {e}"})
                break

            assistant_msg = response.get("message", {})
            content = assistant_msg.get("content", "")
            tool_calls = assistant_msg.get("tool_calls", [])

            # Add assistant message to conversation
            messages.append(assistant_msg)

            # --- Check if agent is done ---
            if not tool_calls:
                # No tool calls = agent finished reasoning
                logger.info("ReAct done (no tool calls)", iteration=iteration)
                timeline.append({"phase": "complete", "detail": content[:500]})
                break

            # --- Execute tool calls ---
            for tc in tool_calls:
                func = tc.get("function", {})
                tool_name = func.get("name", "")
                tool_args = func.get("arguments", {})

                # Handle arguments as string or dict
                if isinstance(tool_args, str):
                    try:
                        tool_args = json.loads(tool_args)
                    except json.JSONDecodeError:
                        tool_args = {}

                logger.info(
                    "ReAct tool call",
                    iteration=iteration,
                    tool=tool_name,
                    args_keys=list(tool_args.keys()),
                )
                timeline.append({
                    "phase": "action",
                    "detail": f"{tool_name}({json.dumps(tool_args, ensure_ascii=False)[:200]})",
                })

                # Execute via MCP
                try:
                    result = await server.call_tool(tool_name, tool_args)
                    tool_result = json.dumps(result, ensure_ascii=False, default=str)
                    # Truncate long results to stay within context
                    if len(tool_result) > 4000:
                        tool_result = tool_result[:4000] + "... [truncated]"
                except Exception as e:
                    tool_result = json.dumps({"error": str(e)})
                    logger.warning("MCP tool error", tool=tool_name, error=str(e))

                timeline.append({
                    "phase": "observation",
                    "detail": tool_result[:300],
                })

                # Add tool result to conversation
                messages.append({"role": "tool", "content": tool_result})

        # --- Parse final result ---
        duration_ms = round((time.time() - start) * 1000, 2)
        final_content = messages[-1].get("content", "") if messages else ""

        # Try to extract structured result from agent's final message
        result = self._parse_result(final_content, skill_id, timeline, duration_ms)
        result["iterations"] = min(iteration, self.max_iterations) if 'iteration' in dir() else 0

        logger.info(
            "ReAct complete",
            skill=skill_id,
            success=result["success"],
            evidence_count=len(result["evidence"]),
            duration_ms=duration_ms,
            iterations=result["iterations"],
        )

        return result

    def _parse_result(
        self,
        final_content: str,
        skill_id: str,
        timeline: list[dict[str, str]],
        duration_ms: float,
    ) -> dict[str, Any]:
        """Extract structured result from the agent's final output."""
        result = {
            "skill_id": skill_id,
            "success": False,
            "evidence": [],
            "summary": "",
            "timeline": timeline,
            "duration_ms": duration_ms,
        }

        # Try to find JSON in the final message
        try:
            # Look for JSON block in content
            json_start = final_content.find("{")
            json_end = final_content.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                parsed = json.loads(final_content[json_start:json_end])
                result["success"] = parsed.get("success", False)
                result["evidence"] = parsed.get("evidence", [])
                result["summary"] = parsed.get("summary", "")
                return result
        except (json.JSONDecodeError, KeyError):
            pass

        # Fallback: analyze timeline for evidence
        result["summary"] = final_content[:500] if final_content else "Agent completed without structured output"
        return result
