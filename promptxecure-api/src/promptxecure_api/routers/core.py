"""
Core API routers — analyze, detect, sanitize.
"""

from __future__ import annotations

import asyncio
import logging
import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from promptxecure_api.db.models import ScanLog, get_db
from promptxecure_api.schemas.request import AnalyzeRequest, DetectRequest, SanitizeRequest
from promptxecure_api.schemas.response import (
    AnalysisDetail,
    AnalyzeResponse,
    DetectResponse,
    ErrorResponse,
    LayerDetail,
    SanitizeResponse,
    ThreatDetail,
)
from promptxecure_api.services.cache import cache_verdict, get_cached_verdict
from promptxecure_api.services.detection import get_pipeline
from promptxecure_api.services.llm_gateway import call_llm
from promptxecure_api.services.langfuse_service import record_pipeline_trace
from promptxecure_api.utils import hash_prompt, get_client_ip

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["core"])


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    summary="Full analysis pipeline — detect, sanitize, and optionally forward to LLM",
)
async def analyze(
    body: AnalyzeRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    pipeline = get_pipeline()
    p_hash = hash_prompt(body.prompt)
    trace_id = str(uuid.uuid4())   # Pre-seed so LiteLLM generation links here

    # --- Redis verdict cache lookup ---
    cached = await get_cached_verdict(p_hash)
    if cached:
        logger.debug(f"Returning cached verdict for {p_hash[:12]}")
        return AnalyzeResponse(**cached)

    # Run synchronous pipeline in thread-pool to avoid blocking the event loop
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, pipeline.analyze, body.prompt)

    # Build analysis detail
    analysis = AnalysisDetail(
        risk_score=result.risk_score,
        risk_level=result.risk_level.value,
        threats_detected=[
            ThreatDetail(**t.to_dict()) for t in result.threats
        ],
        layers={
            k: LayerDetail(**v.to_dict()) for k, v in result.layers.items()
        },
    )

    # Optionally forward to LLM
    llm_response = None
    llm_usage: dict = {}
    if body.send_to_llm and result.sanitized_prompt and not result.is_blocked:
        try:
            llm_response, llm_usage = await call_llm(
                prompt=result.sanitized_prompt,
                model=body.model,
            )

            # Validate output
            output_result = pipeline.analyze_output(llm_response)
            if output_result.triggered:
                logger.warning(f"Output validation flagged response: {output_result.score}")
                llm_response = "[REDACTED — Output validation detected potential data leakage]"

        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            llm_response = None

    # Persist to database
    try:
        log_entry = ScanLog(
            prompt_hash=p_hash,
            prompt_preview=body.prompt[:200],
            risk_score=result.risk_score,
            risk_level=result.risk_level.value,
            action=result.action.value,
            model_used=body.model,
            threats=[t.to_dict() for t in result.threats],
            layers={k: v.to_dict() for k, v in result.layers.items()},
            processing_ms=int(result.processing_ms),
            ip_address=get_client_ip(request),
            sanitized_prompt=result.sanitized_prompt[:500] if result.sanitized_prompt else None,
            llm_response_preview=llm_response[:500] if llm_response else None,
        )
        db.add(log_entry)
        await db.commit()
    except Exception as e:
        logger.error(f"DB persist error: {e}")
        await db.rollback()

    response = AnalyzeResponse(
        status=result.action.value,
        original_prompt=body.prompt,
        sanitized_prompt=result.sanitized_prompt,
        llm_response=llm_response,
        analysis=analysis,
        metadata={"processing_ms": result.processing_ms},
    )

    # --- Langfuse trace (rich, human-readable) ---
    try:
        record_pipeline_trace(
            endpoint="analyze",
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
            client_ip=get_client_ip(request),
            trace_id=trace_id,
        )
    except Exception as e:
        logger.debug(f"Langfuse trace error (non-fatal): {e}")

    # Cache the verdict (only cache non-LLM results to avoid stale responses)
    if not body.send_to_llm:
        await cache_verdict(p_hash, response.model_dump())

    return response


@router.post(
    "/detect",
    response_model=DetectResponse,
    summary="Detection only — returns risk assessment without LLM forwarding",
)
async def detect(body: DetectRequest):
    pipeline = get_pipeline()
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, pipeline.analyze, body.prompt)

    return DetectResponse(
        risk_score=result.risk_score,
        risk_level=result.risk_level.value,
        threats=[ThreatDetail(**t.to_dict()) for t in result.threats],
        layers={k: LayerDetail(**v.to_dict()) for k, v in result.layers.items()},
        processing_ms=result.processing_ms,
    )


@router.post(
    "/sanitize",
    response_model=SanitizeResponse,
    summary="Sanitize a prompt — returns cleaned version with attack elements removed",
)
async def sanitize(body: SanitizeRequest):
    pipeline = get_pipeline()
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, pipeline.analyze, body.prompt)

    return SanitizeResponse(
        original=body.prompt,
        sanitized=result.sanitized_prompt or body.prompt,
        changes_made=result.sanitized_prompt is not None and result.sanitized_prompt != body.prompt,
        risk_score=result.risk_score,
    )
