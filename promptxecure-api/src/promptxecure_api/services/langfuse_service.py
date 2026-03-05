"""
PromptXecure — Langfuse Observability Service

Creates rich, human-readable traces for every pipeline run so that every
step is visible in the Langfuse UI:

  Trace name:  "analyze | BLOCKED | risk=0.82 | jailbreak,harmful_intent"
  ├── span:    "preprocessor"       { input, cleaned, latency_ms }
  ├── span:    "rule_engine"        { triggered, score, rule_ids, categories }
  ├── span:    "ml_classifier"      { triggered, score, method }
  ├── span:    "shadow_llm"         { triggered, score }
  ├── generation: "llm-call"        { model, prompt, response, tokens }
  └── span:    "output_validator"   { triggered, score }

  Scores:  risk_score  (0.0 – 1.0)
  Tags:    [status, risk_level, ...threat_categories]

Also provides a `training_sample()` helper that formats each trace result
into a dict ready for use by the ML classifier training pipeline.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# ── Lazy Langfuse client ───────────────────────────────────────────────────────

_langfuse_client = None


def _get_client():
    """Return a singleton Langfuse client, or None if unconfigured."""
    global _langfuse_client
    if _langfuse_client is not None:
        return _langfuse_client

    try:
        from promptxecure_api.config import settings
        if not settings.LANGFUSE_PUBLIC_KEY or not settings.LANGFUSE_SECRET_KEY:
            return None

        from langfuse import Langfuse
        _langfuse_client = Langfuse(
            public_key=settings.LANGFUSE_PUBLIC_KEY,
            secret_key=settings.LANGFUSE_SECRET_KEY,
            host=settings.LANGFUSE_HOST,
            debug=False,
        )
        logger.info(f"Langfuse SDK client initialised (host={settings.LANGFUSE_HOST})")
    except Exception as exc:
        logger.warning(f"Langfuse SDK init failed: {exc}")
        _langfuse_client = None

    return _langfuse_client


# ── Trace builder ─────────────────────────────────────────────────────────────

def _build_trace_name(endpoint: str, status: str, risk_score: float, categories: list[str]) -> str:
    """Return a human-readable trace name shown as the title in Langfuse.

    Examples:
        "analyze | BLOCKED  | risk=0.82 | jailbreak, harmful_intent"
        "playground | PASSED   | risk=0.00"
        "analyze | SANITIZED | risk=0.45 | pii_leakage"
    """
    cat_str = ", ".join(sorted(set(categories))) if categories else "none"
    return f"{endpoint} | {status.upper():10s} | risk={risk_score:.2f} | {cat_str}"


def _extract_categories(threats: list[dict]) -> list[str]:
    """Pull unique threat category/type values from the threats list."""
    return list({t.get("type", "") for t in threats if t.get("type")})


def record_pipeline_trace(
    *,
    endpoint: str,                 # "analyze" | "playground"
    prompt: str,                   # Original user prompt
    status: str,                   # "passed" | "sanitized" | "blocked"
    risk_score: float,
    risk_level: str,               # "safe" | "suspicious" | "malicious"
    threats: list[dict],
    layers: dict[str, dict],       # LayerResult.to_dict() keyed by name
    sanitized_prompt: str | None,
    llm_response: str | None,
    llm_model: str | None,
    llm_usage: dict | None = None, # {input_tokens, output_tokens, total_tokens, model}
    processing_ms: float = 0.0,
    client_ip: str | None = None,
    trace_id: str | None = None,   # Pre-generated UUID for this trace
) -> str | None:
    """
    Record one full pipeline run as a Langfuse trace.

    Returns the trace_id so it can be passed to `call_llm` for linking the
    LLM generation into this same trace.  Returns None if Langfuse is not set up.
    """
    lf = _get_client()
    if lf is None:
        return None

    try:
        categories = _extract_categories(threats)
        trace_name = _build_trace_name(endpoint, status, risk_score, categories)

        # ── Tags ───────────────────────────────────────────────────────────────
        tags = [status, risk_level, endpoint] + categories

        # ── Build concise threat summary for output field ──────────────────────
        threat_summary = [
            {
                "rule_id": t.get("rule_id"),
                "type": t.get("type"),
                "confidence": round(t.get("confidence", 0), 3),
                "description": t.get("description", ""),
            }
            for t in threats
        ]

        # ── Create trace (use pre-seeded ID so LiteLLM generations link here) ──
        trace_kwargs: dict[str, Any] = dict(
            name=trace_name,
            input={
                "prompt": prompt[:500],
                "endpoint": endpoint,
            },
            output={
                "status": status,
                "risk_score": round(risk_score, 4),
                "risk_level": risk_level,
                "threats_detected": threat_summary,
                "sanitized_prompt": (sanitized_prompt or "")[:300] if sanitized_prompt else None,
                "llm_response": (llm_response or "")[:300] if llm_response else None,
            },
            tags=tags,
            metadata={
                "endpoint": endpoint,
                "processing_ms": round(processing_ms, 1),
                "client_ip": client_ip,
                "rule_count": len(threats),
                "categories": categories,
                "llm_model": llm_model,
            },
        )
        if trace_id:
            trace_kwargs["id"] = trace_id
        trace = lf.trace(**trace_kwargs)

        # ── Numeric risk score ─────────────────────────────────────────────────
        trace.score(
            name="risk_score",
            value=round(risk_score, 4),
            comment=f"{status} — {len(threats)} threat(s) detected",
        )

        # ── Layer spans ────────────────────────────────────────────────────────
        _add_layer_spans(trace, layers, prompt)

        # ── LLM generation (if LLM was called) ────────────────────────────────
        if llm_response and llm_model:
            _add_llm_generation(
                trace=trace,
                model=llm_model,
                prompt=sanitized_prompt or prompt,
                response=llm_response,                usage=llm_usage,            )

        # Output validator span if present
        if "output_validator" in layers:
            ov = layers["output_validator"]
            span = trace.span(
                name="output_validator",
                input={"llm_response_preview": (llm_response or "")[:200]},
                output={
                    "triggered": ov.get("triggered", False),
                    "score": round(ov.get("score", 0.0), 4),
                },
                metadata={"latency_ms": ov.get("latency_ms", 0)},
            )
            span.end()

        lf.flush()
        return trace.id

    except Exception as exc:
        logger.warning(f"Langfuse trace recording failed: {exc}")
        return None


def _add_layer_spans(trace: Any, layers: dict[str, dict], prompt: str) -> None:
    """Create a child span for each detection layer."""
    LAYER_ORDER = ["preprocessor", "yaml_rules", "ml_classifier", "shadow_llm"]

    for layer_name in LAYER_ORDER:
        if layer_name not in layers:
            continue

        layer = layers[layer_name]
        triggered = layer.get("triggered", False)
        score = layer.get("score", 0.0)
        latency = layer.get("latency_ms", 0.0)
        matches = layer.get("matches", 0)
        meta = layer.get("metadata", {})

        # ── Per-layer descriptive names ────────────────────────────────────────
        display_names = {
            "preprocessor": "Preprocessor — text normalisation",
            "yaml_rules": "Rule Engine — YAML pattern matching",
            "ml_classifier": "ML Classifier — XGBoost + embeddings",
            "shadow_llm": "Shadow LLM — semantic detection",
        }
        display = display_names.get(layer_name, layer_name)

        # ── Build layer-specific input/output ──────────────────────────────────
        if layer_name == "preprocessor":
            inp = {"original_text_preview": prompt[:200]}
            out = {
                "modified": triggered,
                "latency_ms": round(latency, 2),
            }
        elif layer_name == "yaml_rules":
            rule_ids = [t.get("rule_id") for t in layer.get("threats", [])] if "threats" in layer else []
            categories = list({t.get("type", "") for t in layer.get("threats", []) if "threats" in layer})
            out = {
                "triggered": triggered,
                "score": round(score, 4),
                "matches": matches,
                "rule_ids": rule_ids,
                "categories": categories,
                "latency_ms": round(latency, 2),
            }
            inp = {"text_preview": prompt[:200]}
        elif layer_name == "ml_classifier":
            method = meta.get("method", "heuristic")
            out = {
                "triggered": triggered,
                "score": round(score, 4),
                "method": method,
                "category": layer.get("category", ""),
                "latency_ms": round(latency, 2),
            }
            inp = {"method": method, "text_preview": prompt[:200]}
        else:
            out = {
                "triggered": triggered,
                "score": round(score, 4),
                "latency_ms": round(latency, 2),
            }
            inp = {"text_preview": prompt[:200]}

        span = trace.span(
            name=display,
            input=inp,
            output=out,
            metadata={
                "layer": layer_name,
                "triggered": triggered,
                "latency_ms": round(latency, 2),
            },
        )
        span.end()


def _add_llm_generation(
    trace: Any,
    model: str,
    prompt: str,
    response: str,
    usage: dict | None = None,
) -> None:
    """Add an explicit LLM generation node to the trace with token usage."""
    try:
        # Convert our usage dict to Langfuse format
        lf_usage: dict | None = None
        if usage:
            lf_usage = {
                "input": usage.get("input_tokens", 0),
                "output": usage.get("output_tokens", 0),
                "total": usage.get("total_tokens", 0),
                "unit": "TOKENS",
            }

        gen = trace.generation(
            name="LLM Response — NVIDIA NIM",
            model=model,
            input=[
                {"role": "user", "content": prompt[:500]},
            ],
            output=response[:500],
            usage=lf_usage,
            metadata={
                "routed_via": "litellm",
                "input_tokens": lf_usage["input"] if lf_usage else None,
                "output_tokens": lf_usage["output"] if lf_usage else None,
            },
        )
        gen.end()
    except Exception as exc:
        logger.debug(f"Could not add LLM generation to trace: {exc}")

# ── Training sample helper ────────────────────────────────────────────────────

def to_training_sample(
    prompt: str,
    status: str,
    risk_score: float,
    threats: list[dict],
    trace_id: str | None = None,
) -> dict:
    """
    Return a dict in the format expected by train_classifier.py corpus files.

    label:
        1  =  malicious  (blocked)
        0  =  benign     (passed with risk_score < 0.3)
       -1  =  ambiguous  (sanitized / borderline) — excluded from training
    """
    if status == "blocked":
        label = 1
    elif status == "passed" and risk_score < 0.3:
        label = 0
    else:
        label = -1  # Ambiguous — exclude from auto-training

    categories = _extract_categories(threats)
    return {
        "prompt": prompt,
        "label": label,
        "auto_label": True,
        "status": status,
        "risk_score": round(risk_score, 4),
        "categories": categories,
        "trace_id": trace_id,
    }
