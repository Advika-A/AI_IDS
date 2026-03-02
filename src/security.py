import time
from functools import wraps
from typing import Dict, Tuple

from flask import request, jsonify, current_app


API_KEY_CONFIG_KEY = "IDS_API_KEY"
RATE_LIMIT_CONFIG_KEY = "IDS_RATE_LIMIT"  # (max_requests, window_seconds)


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # ip -> (window_start_ts, count)
        self._store: Dict[str, Tuple[float, int]] = {}

    def is_allowed(self, ip: str) -> bool:
        now = time.time()
        window_start, count = self._store.get(ip, (now, 0))

        # reset window if expired
        if now - window_start > self.window_seconds:
            window_start, count = now, 0

        count += 1
        self._store[ip] = (window_start, count)
        return count <= self.max_requests


rate_limiter = RateLimiter(max_requests=20, window_seconds=60)


def get_client_ip() -> str:
    # Support running behind reverse proxies if properly configured
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        # first IP in the list is the original client
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def require_api_key(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        configured_key = current_app.config.get(API_KEY_CONFIG_KEY)
        incoming_key = request.headers.get("X-API-KEY")

        # In this research/teaching project we accept either:
        # - the configured key from Flask config, or
        # - the built-in demo key used by the SPA ("demo-secret-key").
        # This avoids confusing 401s during demos if the env key diverges.
        valid_keys = {k for k in (configured_key, "demo-secret-key") if k}

        if not valid_keys:
            return jsonify({"error": "API key not configured"}), 503

        if not incoming_key or incoming_key not in valid_keys:
            return jsonify({
                "error": "Unauthorized",
                "message": "Missing or invalid X-API-KEY",
            }), 401

        return view_func(*args, **kwargs)

    return wrapper


def apply_rate_limit(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        client_ip = get_client_ip()
        if not rate_limiter.is_allowed(client_ip):
            return (
                jsonify(
                    {
                        "error": "Too many requests. Please slow down.",
                        "status": 429,
                    }
                ),
                429,
            )
        return view_func(*args, **kwargs)

    return wrapper

