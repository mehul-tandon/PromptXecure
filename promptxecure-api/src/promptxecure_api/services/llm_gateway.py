"""
LLM Gateway service — Unified LLM routing via LiteLLM.

Features:
- Async routing via litellm.acompletion
- Tenacity retry with exponential backoff for transient failures
- Langfuse observability via LiteLLM callback integration
"""

from __future__ import annotations

import logging
import os

import litellm
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from promptxecure_api.config import settings

logger = logging.getLogger(__name__)

# Configure LiteLLM
litellm.drop_params = True
litellm.set_verbose = settings.DEBUG

# ── Langfuse integration via LiteLLM callback ──────────────────────────────
def _configure_langfuse() -> None:
    """Wire Langfuse as a LiteLLM success/failure callback."""
    if not settings.LANGFUSE_PUBLIC_KEY or not settings.LANGFUSE_SECRET_KEY:
        logger.info("Langfuse not configured (keys missing) — LLM observability disabled")
        return
    try:
        os.environ.setdefault("LANGFUSE_PUBLIC_KEY", settings.LANGFUSE_PUBLIC_KEY)
        os.environ.setdefault("LANGFUSE_SECRET_KEY", settings.LANGFUSE_SECRET_KEY)
        os.environ.setdefault("LANGFUSE_HOST", settings.LANGFUSE_HOST)

        # NOTE: We do NOT use LiteLLM's Langfuse callback here.
        # Our own langfuse_service.py creates fully-named traces via the SDK.
        # Using the LiteLLM callback alongside our SDK would create orphan
        # "litellm-acompletion" root traces that pollute the Langfuse UI.
        logger.info(f"Langfuse env vars set (host={settings.LANGFUSE_HOST}) — tracing handled by langfuse_service")
    except Exception as e:
        logger.warning(f"Langfuse setup failed: {e}")


_configure_langfuse()


# ── Retry configuration ────────────────────────────────────────────────────
_RETRIABLE_EXCEPTIONS = (
    litellm.exceptions.RateLimitError,
    litellm.exceptions.ServiceUnavailableError,
    litellm.exceptions.Timeout,
)


@retry(
    retry=retry_if_exception_type(_RETRIABLE_EXCEPTIONS),
    wait=wait_exponential(multiplier=1, min=1, max=30),
    stop=stop_after_attempt(3),
    reraise=True,
)
async def call_llm(
    prompt: str,
    model: str = "",
    system_message: str = "You are a helpful AI assistant.",
    max_tokens: int = 0,
    temperature: float = 0.7,
    trace_id: str | None = None,
) -> tuple[str, dict]:
    """
    Send a prompt to the specified LLM via LiteLLM.

    Retries up to 3 times with exponential backoff on rate-limit or
    transient errors. Observability is handled externally via langfuse_service
    (no LiteLLM callback — avoids orphan litellm-acompletion traces).

    Returns (response_text, usage_dict) where usage_dict has:
        input_tokens, output_tokens, total_tokens, model
    """
    model = model or settings.LITELLM_DEFAULT_MODEL
    max_tokens = max_tokens or settings.LLM_MAX_TOKENS

    try:
        response = await litellm.acompletion(
            model=model,
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt},
            ],
            max_tokens=max_tokens,
            temperature=temperature,
            timeout=settings.LLM_TIMEOUT,
        )

        content = response.choices[0].message.content
        usage = {
            "input_tokens": getattr(response.usage, "prompt_tokens", 0) if response.usage else 0,
            "output_tokens": getattr(response.usage, "completion_tokens", 0) if response.usage else 0,
            "total_tokens": getattr(response.usage, "total_tokens", 0) if response.usage else 0,
            "model": model,
        }
        logger.info(
            f"LLM call succeeded: model={model} "
            f"tokens_used={usage['total_tokens']}"
        )
        return content, usage

    except litellm.exceptions.RateLimitError:
        logger.warning(f"Rate limit hit for model {model} — will retry")
        raise
    except litellm.exceptions.AuthenticationError:
        logger.error(f"Authentication failed for model {model}")
        raise
    except litellm.exceptions.ServiceUnavailableError:
        logger.warning(f"Service unavailable for model {model} — will retry")
        raise
    except Exception as e:
        logger.error(f"LLM call failed: {model} — {e}")
        raise
