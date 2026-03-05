"""
Redis cache service — verdict caching, rate limiting, burst detection.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from promptxecure_api.config import settings

logger = logging.getLogger(__name__)

_redis_client = None


def get_redis():
    """Get (or create) the global async Redis client."""
    global _redis_client
    if _redis_client is None:
        try:
            import redis.asyncio as aioredis
            _redis_client = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=3,
                socket_timeout=3,
                max_connections=20,
            )
        except Exception as e:
            logger.warning(f"Redis not available: {e}")
            _redis_client = None
    return _redis_client


async def get_cached_verdict(prompt_hash: str) -> dict | None:
    """
    Look up a cached analysis result by prompt hash.
    Returns the cached dict, or None if not cached.
    """
    client = get_redis()
    if not client:
        return None
    try:
        raw = await client.get(f"verdict:{prompt_hash}")
        if raw:
            logger.debug(f"Cache HIT for {prompt_hash[:12]}…")
            return json.loads(raw)
    except Exception as e:
        logger.warning(f"Redis GET failed: {e}")
    return None


async def cache_verdict(prompt_hash: str, result: dict, ttl: int | None = None) -> None:
    """
    Store an analysis result in Redis.
    TTL defaults to REDIS_VERDICT_TTL setting.
    """
    client = get_redis()
    if not client:
        return
    try:
        ttl = ttl or settings.REDIS_VERDICT_TTL
        await client.setex(
            f"verdict:{prompt_hash}",
            ttl,
            json.dumps(result),
        )
        logger.debug(f"Cache SET for {prompt_hash[:12]}… (TTL {ttl}s)")
    except Exception as e:
        logger.warning(f"Redis SET failed: {e}")


async def increment_rate_counter(ip: str, window_seconds: int = 60) -> int:
    """
    Increment and return the request count for this IP in the current window.
    Returns 0 if Redis is unavailable.
    """
    client = get_redis()
    if not client:
        return 0
    key = f"rate:{ip}"
    try:
        pipe = client.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_seconds)
        results = await pipe.execute()
        return results[0]
    except Exception as e:
        logger.warning(f"Rate counter failed: {e}")
        return 0


async def ping_redis() -> bool:
    """Check if Redis is reachable."""
    client = get_redis()
    if not client:
        return False
    try:
        return await client.ping()
    except Exception:
        return False
