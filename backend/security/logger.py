"""
Structured JSON security logger.
All events are written to stdout (Heroku captures stdout/stderr to its log drain).
"""
import json
import logging
import time

# Heroku best practice: log to stdout, not a file
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
)

_logger = logging.getLogger("blockchain_auth")


def log_event(
    event_type: str,
    username: str,
    source_ip: str,
    details: str,
    severity: str = "INFO",
    success: bool = True,
    extra: dict | None = None,
) -> dict:
    """Build and emit a structured JSON security event."""
    event = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "details": details,
        "severity": severity,
        "success": success,
    }
    if extra:
        event.update(extra)

    line = json.dumps(event, ensure_ascii=False)
    if severity in ("CRITICAL", "ERROR"):
        _logger.error(line)
    elif severity == "WARNING":
        _logger.warning(line)
    else:
        _logger.info(line)

    return event
