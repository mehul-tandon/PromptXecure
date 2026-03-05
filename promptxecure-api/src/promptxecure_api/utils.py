"""
API utility functions.
"""

import hashlib

from fastapi import Request


def hash_prompt(prompt: str) -> str:
    """SHA-256 hash of a prompt for deduplication and caching."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def get_client_ip(request: Request) -> str:
    """Extract client IP, respecting X-Forwarded-For behind proxy."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
