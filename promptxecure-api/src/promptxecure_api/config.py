"""
PromptXecure API — Configuration via Pydantic BaseSettings.

Loads from environment variables with secure defaults.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # App
    APP_NAME: str = "PromptXecure API"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"  # development | staging | production

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    CORS_ORIGINS: str = "http://localhost:5173"
    MAX_REQUEST_SIZE: int = 1_048_576  # 1MB

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://promptxecure:secret@localhost:5432/promptxecure"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_VERDICT_TTL: int = 300       # 5 minutes
    REDIS_RATE_LIMIT_RPM: int = 60     # Requests per minute

    # LLM
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    GOOGLE_API_KEY: str = ""
    LITELLM_DEFAULT_MODEL: str = "gpt-4o-mini"
    LLM_TIMEOUT: int = 30             # seconds
    LLM_MAX_TOKENS: int = 2048

    # Detection
    RULES_PATH: str = "../promptxecure-rules/rules/"
    ML_MODEL_PATH: str = "../promptxecure-core/data/model/"
    RISK_THRESHOLD_SUSPICIOUS: float = 0.3
    RISK_THRESHOLD_MALICIOUS: float = 0.7
    ML_ENABLED: bool = True
    SHADOW_LLM_ENABLED: bool = False
    SHADOW_LLM_MODEL: str = "ollama/llama3"
    SHADOW_LLM_TIMEOUT: int = 10
    OUTPUT_VALIDATION_ENABLED: bool = True

    # Langfuse
    LANGFUSE_PUBLIC_KEY: str = ""
    LANGFUSE_SECRET_KEY: str = ""
    LANGFUSE_HOST: str = "http://localhost:3000"

    # Security
    API_KEY: str = ""                  # Optional API key for auth
    ENABLE_DOCS: bool = True           # Disable /docs in production
    FORCE_HTTPS: bool = False

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",")]

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


settings = Settings()
