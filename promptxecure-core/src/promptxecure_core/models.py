"""
Data models for PromptXecure Core.

Defines all dataclasses used throughout the detection pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    """Risk classification levels."""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class ContainmentAction(str, Enum):
    """Actions taken by the containment engine."""
    PASSED = "passed"
    SANITIZED = "sanitized"
    BLOCKED = "blocked"


@dataclass
class ThreatResult:
    """A single detected threat from any layer."""
    rule_id: str
    type: str                   # e.g. "direct_injection", "jailbreak"
    layer: str                  # "yaml_rules", "ml_classifier", "shadow_llm", "output_validator"
    confidence: float           # 0.0 to 1.0
    description: str = ""
    pattern_matched: str = ""   # The specific pattern or keyword that matched
    severity: float = 0.0       # 0.0 to 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "type": self.type,
            "layer": self.layer,
            "confidence": self.confidence,
            "description": self.description,
            "pattern_matched": self.pattern_matched,
            "severity": self.severity,
        }


@dataclass
class LayerResult:
    """Result from a single detection layer."""
    name: str                       # "yaml_rules", "ml_classifier", etc.
    triggered: bool = False
    score: float = 0.0              # Risk score from this layer
    category: str = ""              # Predicted category
    matches: int = 0                # Number of rule matches
    latency_ms: float = 0.0        # Processing time
    metadata: dict[str, Any] = field(default_factory=dict)
    threats: list[ThreatResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "triggered": self.triggered,
            "score": self.score,
            "category": self.category,
            "matches": self.matches,
            "latency_ms": round(self.latency_ms, 2),
            "metadata": self.metadata,
        }


@dataclass
class AnalysisResult:
    """Complete analysis result from the detection pipeline."""
    original_prompt: str
    preprocessed_prompt: str = ""
    sanitized_prompt: str | None = None
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.SAFE
    action: ContainmentAction = ContainmentAction.PASSED
    threats: list[ThreatResult] = field(default_factory=list)
    layers: dict[str, LayerResult] = field(default_factory=dict)
    processing_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_prompt": self.original_prompt,
            "preprocessed_prompt": self.preprocessed_prompt,
            "sanitized_prompt": self.sanitized_prompt,
            "risk_score": round(self.risk_score, 4),
            "risk_level": self.risk_level.value,
            "action": self.action.value,
            "threats": [t.to_dict() for t in self.threats],
            "layers": {k: v.to_dict() for k, v in self.layers.items()},
            "processing_ms": round(self.processing_ms, 2),
        }

    @property
    def is_safe(self) -> bool:
        return self.risk_level == RiskLevel.SAFE

    @property
    def is_blocked(self) -> bool:
        return self.action == ContainmentAction.BLOCKED

    @property
    def threat_count(self) -> int:
        return len(self.threats)
