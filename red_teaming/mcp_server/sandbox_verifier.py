"""Sandbox Environment Verification Protocol.

Implements a challenge-response handshake to verify that a target URL
is a legitimate sandbox environment that has opted-in to security testing.

Protocol:
1. Threat Drill sends a challenge (nonce) to target's well-known endpoint
2. Target must respond with:
   - The challenge nonce (proves liveness)
   - A sandbox token (proves authorization)
   - Environment metadata (proves sandbox nature)
3. Threat Drill verifies the response before allowing any attack

Target Implementation Requirements:
- Expose GET /.well-known/threatdrill-sandbox
- Return JSON with required fields
- Token must be pre-shared or derived from environment config
"""

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import httpx

from shared.utils import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SANDBOX_ENDPOINT = "/.well-known/threatdrill-sandbox"
HANDSHAKE_TIMEOUT_SECONDS = 10
NONCE_TTL_SECONDS = 300  # 5 minutes
REQUIRED_SANDBOX_FIELDS = ["challenge_response", "sandbox_token", "environment"]


@dataclass
class SandboxVerification:
    """Result of sandbox verification."""

    verified: bool
    target_url: str
    environment: Optional[str] = None
    error: Optional[str] = None
    metadata: Optional[dict] = None


@dataclass
class SandboxEnvironment:
    """Verified sandbox environment info."""

    url: str
    environment_type: str  # e.g., "cloud_run", "kubernetes", "docker", "local"
    instance_id: Optional[str] = None
    region: Optional[str] = None
    expires_at: Optional[float] = None


# ---------------------------------------------------------------------------
# Verification Errors
# ---------------------------------------------------------------------------


class SandboxVerificationError(Exception):
    """Raised when sandbox verification fails."""

    pass


class HandshakeTimeoutError(SandboxVerificationError):
    """Raised when handshake times out."""

    pass


class InvalidSandboxResponseError(SandboxVerificationError):
    """Raised when sandbox response is invalid."""

    pass


class UnauthorizedTargetError(SandboxVerificationError):
    """Raised when target is not authorized for testing."""

    pass


# ---------------------------------------------------------------------------
# Verifier Class
# ---------------------------------------------------------------------------


class SandboxVerifier:
    """Verifies that a target URL is a legitimate sandbox environment.

    Usage:
        verifier = SandboxVerifier(shared_secret="your-secret")
        result = await verifier.verify("https://my-sandbox.run.app")
        if result.verified:
            # Safe to attack
        else:
            raise UnauthorizedTargetError(result.error)
    """

    def __init__(
        self,
        shared_secret: Optional[str] = None,
        allow_localhost: bool = True,
        strict_mode: bool = True,
    ):
        """Initialize verifier.

        Args:
            shared_secret: Secret for HMAC verification. If None, uses env var.
            allow_localhost: If True, localhost URLs bypass verification.
            strict_mode: If True, requires all verification checks to pass.
        """
        self._shared_secret = shared_secret or self._get_default_secret()
        self._allow_localhost = allow_localhost
        self._strict_mode = strict_mode
        self._verified_cache: dict[str, SandboxEnvironment] = {}

    @staticmethod
    def _get_default_secret() -> str:
        """Get default secret from environment or generate one."""
        import os

        return os.environ.get("THREATDRILL_SANDBOX_SECRET", "threatdrill-dev-secret")

    def _is_localhost(self, url: str) -> bool:
        """Check if URL is localhost."""
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        return hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0")

    def _generate_challenge(self) -> tuple[str, float]:
        """Generate a challenge nonce and timestamp."""
        nonce = secrets.token_hex(32)
        timestamp = time.time()
        return nonce, timestamp

    def _compute_expected_response(self, challenge: str, sandbox_token: str) -> str:
        """Compute expected HMAC response for challenge."""
        message = f"{challenge}:{sandbox_token}".encode()
        return hmac.new(
            self._shared_secret.encode(), message, hashlib.sha256
        ).hexdigest()

    async def verify(self, target_url: str) -> SandboxVerification:
        """Verify that target URL is a legitimate sandbox.

        Args:
            target_url: The URL to verify

        Returns:
            SandboxVerification with result
        """
        target_url = target_url.rstrip("/")

        # Check cache first
        if target_url in self._verified_cache:
            cached = self._verified_cache[target_url]
            if cached.expires_at and cached.expires_at > time.time():
                logger.info("Using cached sandbox verification", url=target_url)
                return SandboxVerification(
                    verified=True,
                    target_url=target_url,
                    environment=cached.environment_type,
                    metadata={"cached": True, "instance_id": cached.instance_id},
                )

        # Localhost bypass (for local development)
        if self._allow_localhost and self._is_localhost(target_url):
            logger.info("Localhost target - bypassing verification", url=target_url)
            return SandboxVerification(
                verified=True,
                target_url=target_url,
                environment="localhost",
                metadata={"bypass": "localhost_allowed"},
            )

        # Perform handshake verification
        try:
            return await self._perform_handshake(target_url)
        except Exception as e:
            logger.error("Sandbox verification failed", url=target_url, error=str(e))
            return SandboxVerification(
                verified=False, target_url=target_url, error=str(e)
            )

    async def _perform_handshake(self, target_url: str) -> SandboxVerification:
        """Perform challenge-response handshake with target."""
        challenge, timestamp = self._generate_challenge()
        endpoint = f"{target_url}{SANDBOX_ENDPOINT}"

        logger.info("Initiating sandbox handshake", url=endpoint)

        async with httpx.AsyncClient(timeout=HANDSHAKE_TIMEOUT_SECONDS) as client:
            try:
                # Send challenge
                response = await client.get(
                    endpoint,
                    params={"challenge": challenge, "timestamp": str(timestamp)},
                    headers={"X-ThreatDrill-Verify": "handshake"},
                )

                if response.status_code == 404:
                    return SandboxVerification(
                        verified=False,
                        target_url=target_url,
                        error=f"Sandbox endpoint not found at {endpoint}. "
                        f"Target must implement {SANDBOX_ENDPOINT}",
                    )

                if response.status_code != 200:
                    return SandboxVerification(
                        verified=False,
                        target_url=target_url,
                        error=f"Sandbox endpoint returned {response.status_code}",
                    )

                # Parse response
                try:
                    data = response.json()
                except Exception:
                    return SandboxVerification(
                        verified=False,
                        target_url=target_url,
                        error="Invalid JSON response from sandbox endpoint",
                    )

                # Validate required fields
                missing = [f for f in REQUIRED_SANDBOX_FIELDS if f not in data]
                if missing:
                    return SandboxVerification(
                        verified=False,
                        target_url=target_url,
                        error=f"Missing required fields: {missing}",
                    )

                # Verify challenge response
                sandbox_token = data["sandbox_token"]
                expected = self._compute_expected_response(challenge, sandbox_token)
                actual = data["challenge_response"]

                if not hmac.compare_digest(expected, actual):
                    return SandboxVerification(
                        verified=False,
                        target_url=target_url,
                        error="Challenge response verification failed. "
                        "Token mismatch or invalid shared secret.",
                    )

                # Verify environment metadata
                env = data["environment"]
                if not isinstance(env, dict):
                    return SandboxVerification(
                        verified=False,
                        target_url=target_url,
                        error="Invalid environment metadata format",
                    )

                env_type = env.get("type", "unknown")
                instance_id = env.get("instance_id")
                region = env.get("region")

                # Cache the verification
                self._verified_cache[target_url] = SandboxEnvironment(
                    url=target_url,
                    environment_type=env_type,
                    instance_id=instance_id,
                    region=region,
                    expires_at=time.time() + NONCE_TTL_SECONDS,
                )

                logger.info(
                    "Sandbox verification successful",
                    url=target_url,
                    environment=env_type,
                    instance_id=instance_id,
                )

                return SandboxVerification(
                    verified=True,
                    target_url=target_url,
                    environment=env_type,
                    metadata={
                        "instance_id": instance_id,
                        "region": region,
                        "extra": env.get("extra", {}),
                    },
                )

            except httpx.TimeoutException:
                return SandboxVerification(
                    verified=False,
                    target_url=target_url,
                    error=f"Handshake timeout after {HANDSHAKE_TIMEOUT_SECONDS}s",
                )
            except httpx.ConnectError as e:
                return SandboxVerification(
                    verified=False,
                    target_url=target_url,
                    error=f"Connection failed: {e}",
                )

    def invalidate_cache(self, target_url: Optional[str] = None) -> None:
        """Invalidate cached verifications.

        Args:
            target_url: Specific URL to invalidate, or None for all.
        """
        if target_url:
            self._verified_cache.pop(target_url.rstrip("/"), None)
        else:
            self._verified_cache.clear()


# ---------------------------------------------------------------------------
# Helper: Generate Sandbox Response (for target implementations)
# ---------------------------------------------------------------------------


def generate_sandbox_response(
    challenge: str,
    sandbox_token: str,
    shared_secret: str,
    environment_type: str = "cloud_run",
    instance_id: Optional[str] = None,
    region: Optional[str] = None,
    extra: Optional[dict] = None,
) -> dict:
    """Generate a valid sandbox verification response.

    This helper is for implementing the sandbox endpoint on target apps.

    Usage in target app (FastAPI example):
        @app.get("/.well-known/threatdrill-sandbox")
        def sandbox_verify(challenge: str, timestamp: str):
            return generate_sandbox_response(
                challenge=challenge,
                sandbox_token=os.environ["THREATDRILL_SANDBOX_TOKEN"],
                shared_secret=os.environ["THREATDRILL_SANDBOX_SECRET"],
                environment_type="cloud_run",
                instance_id=os.environ.get("K_REVISION"),
                region=os.environ.get("CLOUD_RUN_REGION"),
            )

    Args:
        challenge: The challenge nonce from verifier
        sandbox_token: Your sandbox's unique token
        shared_secret: Shared secret with Threat Drill
        environment_type: Type of environment (cloud_run, kubernetes, etc.)
        instance_id: Optional instance identifier
        region: Optional region identifier
        extra: Optional additional metadata

    Returns:
        Dict ready to return as JSON response
    """
    message = f"{challenge}:{sandbox_token}".encode()
    challenge_response = hmac.new(
        shared_secret.encode(), message, hashlib.sha256
    ).hexdigest()

    return {
        "challenge_response": challenge_response,
        "sandbox_token": sandbox_token,
        "environment": {
            "type": environment_type,
            "instance_id": instance_id,
            "region": region,
            "extra": extra or {},
        },
    }


# ---------------------------------------------------------------------------
# Global Verifier Instance
# ---------------------------------------------------------------------------

_default_verifier: Optional[SandboxVerifier] = None


def get_verifier() -> SandboxVerifier:
    """Get or create the default verifier instance."""
    global _default_verifier
    if _default_verifier is None:
        _default_verifier = SandboxVerifier()
    return _default_verifier


async def verify_sandbox(target_url: str) -> SandboxVerification:
    """Convenience function to verify a sandbox URL."""
    return await get_verifier().verify(target_url)
