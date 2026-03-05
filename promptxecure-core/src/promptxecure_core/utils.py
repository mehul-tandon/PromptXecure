"""
Utility functions for PromptXecure Core.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any


def sha256_hash(text: str) -> str:
    """Generate SHA-256 hash of input text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def timer_ms() -> float:
    """Return current time in milliseconds for latency measurement."""
    return time.perf_counter() * 1000


def elapsed_ms(start: float) -> float:
    """Calculate elapsed time in milliseconds."""
    return timer_ms() - start


def truncate(text: str, max_length: int = 200) -> str:
    """Truncate text with ellipsis."""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."


def safe_json_serialize(obj: Any) -> Any:
    """Safely serialize objects for JSON output."""
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    return str(obj)
