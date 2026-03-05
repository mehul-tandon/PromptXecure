"""Pydantic request models — strict validation, no unknown fields."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class AnalyzeOptions(BaseModel):
    """Options for the analyze endpoint."""
    strict_mode: bool = False
    return_analysis: bool = True
    sanitize_only: bool = False

    model_config = {"extra": "forbid"}


class AnalyzeRequest(BaseModel):
    """Request body for POST /api/v1/analyze."""
    prompt: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="The user prompt to analyze",
    )
    model: str = Field(
        default="nvidia_nim/meta/llama-3.1-8b-instruct",
        description="LLM model to use",
    )
    send_to_llm: bool = Field(
        default=False,
        description="If True and prompt is safe, forward sanitized prompt to the LLM",
    )
    options: AnalyzeOptions = Field(default_factory=AnalyzeOptions)

    model_config = {"extra": "forbid"}

    @field_validator("prompt")
    @classmethod
    def prompt_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Prompt cannot be empty or whitespace only")
        return v

    @field_validator("model")
    @classmethod
    def valid_model(cls, v: str) -> str:
        allowed = {
            # NVIDIA NIM
            "nvidia_nim/meta/llama-3.1-8b-instruct",
            "nvidia_nim/meta/llama-3.1-70b-instruct",
            "nvidia_nim/meta/llama-3.3-70b-instruct",
            "nvidia_nim/nvidia/llama-3.1-nemotron-70b-instruct",
            "nvidia_nim/mistralai/mistral-7b-instruct-v0.3",
            "nvidia_nim/mistralai/mixtral-8x7b-instruct-v0.1",
            "nvidia_nim/microsoft/phi-3-mini-128k-instruct",
            # OpenAI
            "gpt-4", "gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo",
            # Anthropic
            "claude-3-opus", "claude-3-sonnet", "claude-3-haiku",
            # Google Gemini
            "gemini-pro", "gemini-1.5-pro", "gemini-1.5-flash",
            "gemini/gemini-1.5-flash", "gemini/gemini-1.5-pro", "gemini/gemini-pro",
            "gemini-2.0-flash", "gemini-2.0-flash-lite",
            "gemini/gemini-2.0-flash", "gemini/gemini-2.0-flash-lite", "gemini/gemini-2.0-flash-exp",
            # Ollama local
            "llama3", "llama3:8b", "mistral", "mixtral",
            "ollama/llama3", "ollama/mistral",
        }
        if v not in allowed:
            raise ValueError(f"Unsupported model: {v}. Allowed: {', '.join(sorted(allowed))}")
        return v


class DetectRequest(BaseModel):
    """Request body for POST /api/v1/detect — detection only."""
    prompt: str = Field(..., min_length=1, max_length=10000)

    model_config = {"extra": "forbid"}


class SanitizeRequest(BaseModel):
    """Request body for POST /api/v1/sanitize — sanitization only."""
    prompt: str = Field(..., min_length=1, max_length=10000)

    model_config = {"extra": "forbid"}


class PlaygroundRequest(BaseModel):
    """Request body for POST /api/v1/playground — interactive mode."""
    prompt: str = Field(..., min_length=1, max_length=10000)
    model: str = Field(default="nvidia_nim/meta/llama-3.1-8b-instruct")
    send_to_llm: bool = Field(default=True, description="Whether to forward safe prompts to LLM")

    model_config = {"extra": "forbid"}

    @field_validator("model")
    @classmethod
    def valid_model(cls, v: str) -> str:
        # Reuse the same allowed set as AnalyzeRequest
        return AnalyzeRequest.valid_model(v)


class AnalyticsQuery(BaseModel):
    """Query params for GET /api/v1/analytics."""
    hours: int = Field(default=24, ge=1, le=720, description="Lookback window in hours")

    model_config = {"extra": "forbid"}


class LogsQuery(BaseModel):
    """Query params for GET /api/v1/logs."""
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=20, ge=1, le=100)
    risk_level: str | None = Field(default=None)
    search: str | None = Field(default=None, max_length=200)

    model_config = {"extra": "forbid"}
