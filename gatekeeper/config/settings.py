"""Configuration settings for Gatekeeper."""

from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class GatekeeperSettings(BaseSettings):
    """Gatekeeper configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Google Cloud Settings
    gcp_project_id: str = Field(description="Google Cloud Project ID")
    gcp_location: str = Field(default="us-central1", description="Google Cloud Region")

    # Vertex AI Settings
    vertex_ai_endpoint: Optional[str] = None

    # Firestore Settings
    firestore_database: str = Field(default="(default)")

    # Pub/Sub Settings
    pubsub_security_events_topic: str = Field(default="aegisflow-security-events")

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
