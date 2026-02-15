"""Configuration settings for Gatekeeper."""

from __future__ import annotations

from typing import Optional

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class GatekeeperSettings(BaseSettings):
    """Gatekeeper configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Google Cloud Settings (optional with API-key mode)
    gcp_project_id: Optional[str] = Field(default=None, description="Google Cloud Project ID")
    gcp_location: str = Field(default="us-central1", description="Google Cloud region")

    # Gemini API (Google AI Studio)
    api_key: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("API_KEY", "GEMINI_API_KEY"),
        description="Google AI Studio API key",
    )
    gemini_api_base_url: str = Field(
        default="https://generativelanguage.googleapis.com/v1beta",
        description="Gemini REST API base URL",
    )
    gemini_flash_model: str = Field(default="gemini-2.5-flash", description="Flash model id")
    gemini_deep_model: str = Field(default="gemini-2.5-pro", description="Deep analysis model id")
    gemini_embed_model: str = Field(default="text-embedding-004", description="Embedding model id")
    enable_gemini_playwright_mcp: bool = Field(
        default=False,
        description="Enable Gemini SDK + Playwright MCP planning path",
    )
    playwright_mcp_command: str = Field(
        # Prefer the installed CLI (Docker/Cloud Run). For local dev without a global install,
        # you can set PLAYWRIGHT_MCP_COMMAND=npx and PLAYWRIGHT_MCP_ARGS="@playwright/mcp@<ver> ...".
        default="playwright-mcp",
        description="Command used to launch Playwright MCP server",
    )
    playwright_mcp_args: str = Field(
        default="--headless --isolated --output-dir .playwright-mcp",
        description="Arguments passed to Playwright MCP command",
    )
    gemini_mcp_max_remote_calls: int = Field(
        default=8,
        description="Maximum automatic MCP tool calls during Gemini planning",
    )

    # Backward-compatible Vertex field
    vertex_ai_endpoint: Optional[str] = None

    # Firestore Settings
    firestore_database: str = Field(default="(default)")

    # Pub/Sub Settings
    pubsub_security_events_topic: str = Field(default="threatdrill-security-events")
    pubsub_feedback_loop_topic: str = Field(default="threatdrill-feedback-loop")
    pubsub_policy_updates_topic: str = Field(default="threatdrill-policy-updates")
    pubsub_red_team_findings_topic: str = Field(default="threatdrill-red-team-findings")

    # Server Settings
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8080)
    workers: int = Field(default=4)
    reload: bool = Field(default=False)

    # Security Settings
    enable_deep_think: bool = Field(default=True)
    deep_think_confidence_threshold: float = Field(default=0.75)
    max_request_size_mb: int = Field(default=10)
    rate_limit_per_minute: int = Field(default=1000)

    # Hackathon / Demo
    hackathon_demo_mode: bool = Field(
        default=True,
        validation_alias=AliasChoices("HACKATHON_DEMO_MODE", "DEMO_MODE"),
        description="If true, only a curated subset of skills is executable; others are roadmap-only.",
    )

    # Logging
    log_level: str = Field(default="INFO")
    json_logs: bool = Field(default=True)

    # Redis Cache
    redis_host: str = Field(default="localhost")
    redis_port: int = Field(default=6379)
    redis_db: int = Field(default=0)
    redis_password: Optional[str] = None

    # Monitoring
    enable_prometheus: bool = Field(default=True)
    prometheus_port: int = Field(default=9090)

    # CORS
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000"],
        description="Allowed CORS origins",
    )

    # Authentication
    require_authentication: bool = Field(default=True)
    jwt_secret_key: Optional[str] = None
    jwt_algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=30)


settings = GatekeeperSettings()
