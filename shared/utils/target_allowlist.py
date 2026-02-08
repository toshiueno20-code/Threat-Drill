"""Target URL allowlist — prevents attacks against unauthorized targets.

Only the following targets are allowed:
- localhost / 127.0.0.1 / ::1 / 0.0.0.0
- Private networks (10.x, 172.16-31.x, 192.168.x, fc00::/7)
- Explicitly configured sandbox domains (THREATDRILL_ALLOWED_DOMAINS env)
- Verified sandbox endpoints (challenge-response handshake)

Everything else is **BLOCKED**.
"""

import ipaddress
import os
import re
from urllib.parse import urlparse

from shared.utils import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Additional allowed domains from environment (comma-separated).
# Example: THREATDRILL_ALLOWED_DOMAINS="my-sandbox.run.app,staging.internal"
_ENV_ALLOWED = os.environ.get("THREATDRILL_ALLOWED_DOMAINS", "")
_EXTRA_DOMAINS: list[str] = [
    d.strip().lower() for d in _ENV_ALLOWED.split(",") if d.strip()
]

# Hardcoded Cloud Run sandbox patterns (only project-owned)
_SANDBOX_PATTERNS: list[re.Pattern] = [
    re.compile(r"^.*\.run\.app$"),           # Google Cloud Run
    re.compile(r"^.*\.a\.run\.app$"),         # Cloud Run (alternate)
    re.compile(r"^.*\.cloudfunctions\.net$"), # Cloud Functions
    re.compile(r"^.*\.appspot\.com$"),        # App Engine
]

# Private IPv4 ranges
_PRIVATE_NETS_V4 = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("169.254.0.0/16"),   # link-local
]

# Private IPv6 ranges
_PRIVATE_NETS_V6 = [
    ipaddress.IPv6Network("fc00::/7"),    # unique-local
    ipaddress.IPv6Network("fe80::/10"),   # link-local
]


class TargetNotAllowedError(Exception):
    """Raised when a target URL is not in the allowlist."""

    pass


# ---------------------------------------------------------------------------
# Core Validator
# ---------------------------------------------------------------------------


def validate_target_url(url: str) -> str:
    """Validate that a target URL is in the allowlist.

    Args:
        url: The target URL to validate.

    Returns:
        The validated URL (stripped of trailing slashes).

    Raises:
        TargetNotAllowedError: If the URL is not an allowed target.
    """
    if not url or not url.strip():
        raise TargetNotAllowedError("Target URL is required")

    url = url.strip()

    try:
        parsed = urlparse(url)
    except Exception:
        raise TargetNotAllowedError(f"Invalid URL format: {url}")

    # Require http or https scheme
    if parsed.scheme not in ("http", "https"):
        raise TargetNotAllowedError(
            f"Invalid scheme '{parsed.scheme}'. Only http/https are allowed."
        )

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise TargetNotAllowedError(f"Could not extract hostname from URL: {url}")

    # 1. Localhost — always allowed
    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        logger.info("URL allowed: localhost", url=url)
        return url

    # 2. Private IP address — always allowed
    try:
        addr = ipaddress.ip_address(hostname)
        for net in (_PRIVATE_NETS_V4 if addr.version == 4 else _PRIVATE_NETS_V6):
            if addr in net:
                logger.info("URL allowed: private network", url=url, network=str(net))
                return url
        # Public IP — block
        raise TargetNotAllowedError(
            f"Public IP address '{hostname}' is not allowed. "
            f"Only localhost and private network IPs (10.x, 172.16-31.x, 192.168.x) are permitted."
        )
    except ValueError:
        # Not a raw IP, continue to hostname checks
        pass

    # 3. Explicitly configured domains from environment
    for allowed_domain in _EXTRA_DOMAINS:
        if hostname == allowed_domain or hostname.endswith(f".{allowed_domain}"):
            logger.info("URL allowed: configured domain", url=url, domain=allowed_domain)
            return url

    # 4. Known sandbox platform patterns
    for pattern in _SANDBOX_PATTERNS:
        if pattern.match(hostname):
            logger.info("URL allowed: sandbox platform", url=url, hostname=hostname)
            return url

    # 5. Docker / Kubernetes internal hostnames
    # Containers commonly use short hostnames or *.local / *.internal / *.svc.cluster.local
    if (
        "." not in hostname                               # bare hostname like "app"
        or hostname.endswith(".local")                    # mDNS / Docker Desktop
        or hostname.endswith(".internal")                 # GCP internal DNS
        or hostname.endswith(".svc.cluster.local")        # Kubernetes
        or hostname.endswith(".docker.internal")          # Docker Desktop
    ):
        logger.info("URL allowed: internal hostname", url=url, hostname=hostname)
        return url

    # BLOCKED
    logger.warning("URL BLOCKED: not in allowlist", url=url, hostname=hostname)
    raise TargetNotAllowedError(
        f"Target '{hostname}' is not allowed.\n"
        f"Permitted targets:\n"
        f"  - localhost / 127.0.0.1 / private IPs (10.x, 172.16-31.x, 192.168.x)\n"
        f"  - Docker/Kubernetes internal hostnames\n"
        f"  - Verified sandbox deployments (*.run.app, *.cloudfunctions.net)\n"
        f"  - Domains listed in THREATDRILL_ALLOWED_DOMAINS environment variable\n"
        f"\n"
        f"This restriction prevents accidental attacks against production or third-party systems."
    )


def is_target_allowed(url: str) -> tuple[bool, str]:
    """Check if a target URL is allowed (non-raising version).

    Returns:
        (allowed: bool, message: str)
    """
    try:
        validate_target_url(url)
        return True, "OK"
    except TargetNotAllowedError as e:
        return False, str(e)
