"""
PromptXecure Core — Multi-layered prompt injection detection engine.

Usage:
    from promptxecure_core import Pipeline

    pipeline = Pipeline(rules_path="path/to/rules/", model_path="path/to/model/")
    result = pipeline.analyze("Ignore previous instructions")
    # result.risk_level → "malicious"
    # result.risk_score → 0.95
    # result.action → "blocked"
"""

from promptxecure_core.models import (
    AnalysisResult,
    ContainmentAction,
    LayerResult,
    RiskLevel,
    ThreatResult,
)
from promptxecure_core.pipeline import Pipeline

__version__ = "0.1.0"
__all__ = [
    "Pipeline",
    "AnalysisResult",
    "ContainmentAction",
    "LayerResult",
    "RiskLevel",
    "ThreatResult",
]
