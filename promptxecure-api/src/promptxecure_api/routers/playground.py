"""
Playground and analytics routers.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text, cast, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from promptxecure_api.db.models import ScanLog, get_db
from promptxecure_api.schemas.request import PlaygroundRequest
from promptxecure_api.schemas.response import (
    AnalysisDetail,
    HealthResponse,
    LayerDetail,
    LogEntry,
    LogsResponse,
    PlaygroundResponse,
    StatsResponse,
    ThreatDetail,
)
from promptxecure_api.config import settings
from promptxecure_api.services.detection import get_pipeline
from promptxecure_api.services.llm_gateway import call_llm
from promptxecure_api.services.langfuse_service import record_pipeline_trace
from promptxecure_api.services.cache import ping_redis
from promptxecure_api.utils import hash_prompt

logger = logging.getLogger(__name__)

playground_router = APIRouter(prefix="/api/v1", tags=["playground"])
analytics_router = APIRouter(prefix="/api/v1", tags=["analytics"])
health_router = APIRouter(tags=["health"])


# ---- Playground ----

@playground_router.post(
    "/playground",
    response_model=PlaygroundResponse,
    summary="Interactive playground — analyze, sanitize, and get LLM response",
)
async def playground(body: PlaygroundRequest, db: AsyncSession = Depends(get_db)):
    pipeline = get_pipeline()
    trace_id = str(uuid.uuid4())   # Pre-seed so LiteLLM generation links here
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, pipeline.analyze, body.prompt)

    analysis = AnalysisDetail(
        risk_score=result.risk_score,
        risk_level=result.risk_level.value,
        threats_detected=[ThreatDetail(**t.to_dict()) for t in result.threats],
        layers={k: LayerDetail(**v.to_dict()) for k, v in result.layers.items()},
    )

    llm_response = None
    llm_usage: dict = {}
    prompt_to_send = result.sanitized_prompt or body.prompt
    if body.send_to_llm and prompt_to_send and not result.is_blocked:
        try:
            llm_response, llm_usage = await call_llm(
                prompt=prompt_to_send,
                model=body.model,
            )
            output_check = pipeline.analyze_output(llm_response)
            if output_check.triggered:
                llm_response = "[REDACTED — Output contained potential data leakage]"
        except Exception as e:
            logger.error(f"Playground LLM error: {e}")

    # Persist
    try:
        log = ScanLog(
            prompt_hash=hash_prompt(body.prompt),
            prompt_preview=body.prompt[:200],
            risk_score=result.risk_score,
            risk_level=result.risk_level.value,
            action=result.action.value,
            model_used=body.model,
            threats=[t.to_dict() for t in result.threats],
            layers={k: v.to_dict() for k, v in result.layers.items()},
            processing_ms=int(result.processing_ms),
        )
        db.add(log)
        await db.commit()
    except Exception as e:
        logger.error(f"Playground DB error: {e}")
        await db.rollback()

    # --- Langfuse trace (rich, human-readable) ---
    try:
        record_pipeline_trace(
            endpoint="playground",
            prompt=body.prompt,
            status=result.action.value,
            risk_score=result.risk_score,
            risk_level=result.risk_level.value,
            threats=[t.to_dict() for t in result.threats],
            layers={k: v.to_dict() for k, v in result.layers.items()},
            sanitized_prompt=result.sanitized_prompt,
            llm_response=llm_response,
            llm_model=body.model if llm_response else None,
            llm_usage=llm_usage if llm_response else None,
            processing_ms=result.processing_ms,
            trace_id=trace_id,
        )
    except Exception as e:
        logger.debug(f"Langfuse trace error (non-fatal): {e}")

    return PlaygroundResponse(
        status=result.action.value,
        original_prompt=body.prompt,
        sanitized_prompt=result.sanitized_prompt,
        llm_response=llm_response,
        analysis=analysis,
        processing_ms=result.processing_ms,
    )

# ---- Analytics ----

@analytics_router.get(
    "/analytics",
    response_model=StatsResponse,
    summary="Dashboard analytics — aggregated scan statistics",
)
async def analytics(
    hours: int = Query(default=24, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Total counts
    total_q = await db.execute(
        select(func.count()).where(ScanLog.timestamp >= cutoff)
    )
    total = total_q.scalar() or 0

    blocked_q = await db.execute(
        select(func.count()).where(ScanLog.timestamp >= cutoff, ScanLog.action == "blocked")
    )
    blocked = blocked_q.scalar() or 0

    sanitized_q = await db.execute(
        select(func.count()).where(ScanLog.timestamp >= cutoff, ScanLog.action == "sanitized")
    )
    sanitized = sanitized_q.scalar() or 0

    passed = total - blocked - sanitized

    # Avg risk score
    avg_q = await db.execute(
        select(func.avg(ScanLog.risk_score)).where(ScanLog.timestamp >= cutoff)
    )
    avg_risk = avg_q.scalar() or 0.0

    # Avg latency
    lat_q = await db.execute(
        select(func.avg(ScanLog.processing_ms)).where(ScanLog.timestamp >= cutoff)
    )
    avg_latency = lat_q.scalar() or 0.0

    # Top threat categories — aggregate from JSONB threats column
    top_categories: list[dict] = []
    try:
        cat_q = await db.execute(
            text("""
                SELECT threat->>'type' AS category, COUNT(*) AS cnt
                FROM scan_logs, jsonb_array_elements(threats) AS threat
                WHERE timestamp >= :cutoff
                GROUP BY category
                ORDER BY cnt DESC
                LIMIT 8
            """),
            {"cutoff": cutoff},
        )
        top_categories = [
            {"category": row[0] or "unknown", "count": int(row[1])}
            for row in cat_q.fetchall()
            if row[0]
        ]
    except Exception as e:
        logger.warning(f"top_categories query failed: {e}")

    # Hourly trend (last N hours, grouped into time buckets)
    hourly_trend: list[dict] = []
    try:
        bucket_size = "1 hour" if hours <= 48 else ("6 hours" if hours <= 336 else "1 day")
        trend_q = await db.execute(
            text(f"""
                SELECT
                    date_trunc(:bucket, timestamp) AS hour,
                    COUNT(*) AS total,
                    SUM(CASE WHEN action = 'blocked'   THEN 1 ELSE 0 END) AS blocked,
                    SUM(CASE WHEN action = 'sanitized' THEN 1 ELSE 0 END) AS sanitized
                FROM scan_logs
                WHERE timestamp >= :cutoff
                GROUP BY hour
                ORDER BY hour
            """),
            {"bucket": bucket_size.split()[1], "cutoff": cutoff},
        )
        hourly_trend = [
            {
                "hour": str(row[0])[:16] if row[0] else "",
                "total": int(row[1]),
                "blocked": int(row[2]),
                "sanitized": int(row[3]),
            }
            for row in trend_q.fetchall()
        ]
    except Exception as e:
        logger.warning(f"hourly_trend query failed: {e}")

    return StatsResponse(
        total_scans=total,
        blocked=blocked,
        sanitized=sanitized,
        passed=passed,
        block_rate=blocked / total if total > 0 else 0.0,
        avg_risk_score=round(float(avg_risk), 4),
        avg_latency_ms=round(float(avg_latency), 2),
        top_categories=top_categories,
        hourly_trend=hourly_trend,
    )


@analytics_router.get(
    "/logs",
    response_model=LogsResponse,
    summary="Scan log history with pagination and filtering",
)
async def logs(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    risk_level: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    query = select(ScanLog).order_by(ScanLog.timestamp.desc())

    if risk_level:
        query = query.where(ScanLog.risk_level == risk_level)

    # Count total
    count_q = select(func.count()).select_from(ScanLog)
    if risk_level:
        count_q = count_q.where(ScanLog.risk_level == risk_level)
    total_result = await db.execute(count_q)
    total = total_result.scalar() or 0

    # Paginate
    query = query.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    rows = result.scalars().all()

    entries = [
        LogEntry(
            id=str(row.id),
            timestamp=row.timestamp,
            prompt_preview=row.prompt_preview,
            risk_score=row.risk_score,
            risk_level=row.risk_level,
            action=row.action,
            model_used=row.model_used,
            processing_ms=row.processing_ms,
            threats_count=len(row.threats) if row.threats else 0,
        )
        for row in rows
    ]

    return LogsResponse(
        logs=entries,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=(total + per_page - 1) // per_page,
    )


# ---- Health ----

@health_router.get(
    "/api/v1/health",
    response_model=HealthResponse,
    summary="Health check endpoint",
)
async def health():
    pipeline = get_pipeline()
    return HealthResponse(
        status="healthy",
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        pipeline=pipeline.status,
        services={
            "database": "configured",
            "redis": "configured",
            "langfuse": "configured" if settings.LANGFUSE_PUBLIC_KEY else "disabled",
        },
    )
