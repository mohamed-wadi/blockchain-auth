"""
Custom rate limiter utilities — wraps flask-limiter with helpers.
The main limiter instance lives in app.py; this module
provides per-IP counters used by the anomaly detector.
"""
from collections import defaultdict
import time

_ip_windows: dict[str, list[float]] = defaultdict(list)


def record_request(ip: str) -> None:
    """Record a request timestamp for the given IP."""
    now = time.time()
    _ip_windows[ip].append(now)
    # Keep only last 10 minutes
    cutoff = now - 600
    _ip_windows[ip] = [t for t in _ip_windows[ip] if t > cutoff]


def get_request_count(ip: str, window_seconds: int = 60) -> int:
    """Return number of requests from IP in the last window_seconds."""
    now = time.time()
    cutoff = now - window_seconds
    return sum(1 for t in _ip_windows.get(ip, []) if t > cutoff)


def is_rate_limited(ip: str, max_per_minute: int = 30) -> bool:
    """Quick heuristic check — before flask-limiter kicks in."""
    return get_request_count(ip, 60) > max_per_minute


def clear_ip(ip: str) -> None:
    _ip_windows.pop(ip, None)
