"""Pydantic response models — strict, no sensitive data leakage."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ThreatDetail(BaseModel):
    """Individual detected threat."""
    rule_id: str
    type: str
    layer: str
    confidence: float
    description: str = ""
    pattern_matched: str = ""
    severity: float = 0.0


class LayerDetail(BaseModel):
    """Result from a single detection layer."""
    name: str
    triggered: bool
    score: float
    category: str = ""
    matches: int = 0
    latency_ms: float = 0.0


class AnalysisDetail(BaseModel):
    """Full analysis breakdown."""
    risk_score: float
    risk_level: str
    threats_detected: list[ThreatDetail] = []
    layers: dict[str, LayerDetail] = {}


class AnalyzeResponse(BaseModel):
    """Response for POST /api/v1/analyze."""
    status: str = Field(description="safe | sanitized | blocked")
    original_prompt: str
    sanitized_prompt: str | None = None
    llm_response: str | None = None
    analysis: AnalysisDetail
    metadata: dict = {}


class DetectResponse(BaseModel):
    """Response for POST /api/v1/detect."""
    risk_score: float
    risk_level: str
    threats: list[ThreatDetail] = []
    layers: dict[str, LayerDetail] = {}
    processing_ms: float = 0.0


class SanitizeResponse(BaseModel):
    """Response for POST /api/v1/sanitize."""
    original: str
    sanitized: str
    changes_made: bool
    risk_score: float


class PlaygroundResponse(BaseModel):
    """Response for POST /api/v1/playground."""
    status: str
    original_prompt: str
    sanitized_prompt: str | None = None
    llm_response: str | None = None
    analysis: AnalysisDetail
    processing_ms: float = 0.0


class StatsResponse(BaseModel):
    """Response for GET /api/v1/analytics."""
    total_scans: int = 0
    blocked: int = 0
    sanitized: int = 0
    passed: int = 0
    block_rate: float = 0.0
    avg_risk_score: float = 0.0
    avg_latency_ms: float = 0.0
    top_categories: list[dict] = []
    hourly_trend: list[dict] = []


class LogEntry(BaseModel):
    """Single log entry."""
    id: str
    timestamp: datetime
    prompt_preview: str
    risk_score: float
    risk_level: str
    action: str
    model_used: str | None = None
    processing_ms: int = 0
    threats_count: int = 0


class LogsResponse(BaseModel):
    """Response for GET /api/v1/logs."""
    logs: list[LogEntry] = []
    total: int = 0
    page: int = 1
    per_page: int = 20
    total_pages: int = 0


class HealthResponse(BaseModel):
    """Response for GET /api/v1/health."""
    status: str = "healthy"
    version: str
    environment: str
    pipeline: dict = {}
    services: dict = {}


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    detail: str = ""
    status_code: int = 500
