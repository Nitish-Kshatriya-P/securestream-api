import logging
import json
from datetime import datetime, timezone
from pathlib import Path

# Ensure logs directory exists
Path("logs").mkdir(exist_ok=True)

# Configure a dedicated security audit logger
audit_logger = logging.getLogger("securestream.audit")
audit_logger.setLevel(logging.INFO)

# File handler — writes to logs/audit.log
file_handler = logging.FileHandler("logs/audit.log")
file_handler.setLevel(logging.INFO)

# Formatter outputs raw JSON strings — no extra formatting
file_handler.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(file_handler)

# Also print to console during development
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(console_handler)


def log_security_event(
    event_type: str,
    username: str = None,
    source_ip: str = None,
    endpoint: str = None,
    response_code: int = None,
    details: str = None
):
    """
    Writes a structured JSON security event to logs/audit.log.

    Event types used in this project:
    - AUTH_SUCCESS: Successful login
    - AUTH_FAILURE: Failed login attempt
    - STREAM_ACCESS: Media token generated
    - HMAC_FAILURE: Invalid request signature detected
    - TOKEN_EXPIRED: Expired media token used
    - RATE_LIMIT_HIT: Client exceeded rate limit

    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "username": username or "anonymous",
        "source_ip": source_ip or "unknown",
        "endpoint": endpoint or "unknown",
        "response_code": response_code,
        "details": details or ""
    }

    audit_logger.info(json.dumps(event))