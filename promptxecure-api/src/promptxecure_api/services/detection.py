"""
Detection service — Pipeline singleton initialization.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Add core to path for standalone development
core_path = Path(__file__).parent.parent.parent.parent.parent / "promptxecure-core" / "src"
if core_path.exists():
    sys.path.insert(0, str(core_path))

from promptxecure_core.config import PipelineConfig
from promptxecure_core.pipeline import Pipeline

from promptxecure_api.config import settings

logger = logging.getLogger(__name__)

_pipeline: Pipeline | None = None


def init_pipeline() -> Pipeline:
    """Initialize the detection pipeline with settings from config."""
    global _pipeline

    config = PipelineConfig(
        rules_path=settings.RULES_PATH,
        model_path=settings.ML_MODEL_PATH,
        risk_threshold_suspicious=settings.RISK_THRESHOLD_SUSPICIOUS,
        risk_threshold_malicious=settings.RISK_THRESHOLD_MALICIOUS,
        ml_enabled=settings.ML_ENABLED,
        shadow_llm_enabled=settings.SHADOW_LLM_ENABLED,
        shadow_llm_model=settings.SHADOW_LLM_MODEL,
        shadow_llm_timeout=settings.SHADOW_LLM_TIMEOUT,
        output_validation_enabled=settings.OUTPUT_VALIDATION_ENABLED,
    )

    _pipeline = Pipeline(config=config)
    logger.info(f"Detection pipeline initialized: {_pipeline.status}")
    return _pipeline


def get_pipeline() -> Pipeline:
    """Get the pipeline singleton."""
    global _pipeline
    if _pipeline is None:
        _pipeline = init_pipeline()
    return _pipeline
