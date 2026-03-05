"""
PromptXecure API — FastAPI application entry point.

Production-hardened with:
- Security headers middleware
- Request size limiting
- HTTPS redirect (configurable)
- API key auth (optional)
- Rate limiting
- CORS with strict origin config
- Global exception handlers
- Traceback suppression in production
"""

from __future__ import annotations

import logging
import traceback
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from promptxecure_api.config import settings
from promptxecure_api.db.models import init_db
from promptxecure_api.middleware.security import (
    APIKeyMiddleware,
    HTTPSRedirectMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
from promptxecure_api.routers.core import router as core_router
from promptxecure_api.routers.playground import (
    analytics_router,
    health_router,
    playground_router,
)
from promptxecure_api.services.detection import init_pipeline

# ── Structured JSON logging (Loki-compatible) ──────────────────────────────
def _configure_logging() -> None:
    try:
        from pythonjsonlogger import jsonlogger  # type: ignore[import]

        handler = logging.StreamHandler()
        formatter = jsonlogger.JsonFormatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        handler.setFormatter(formatter)
        root = logging.getLogger()
        root.handlers = [handler]
        root.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
    except ImportError:
        # Fallback to plain-text logging if package not installed
        logging.basicConfig(
            level=logging.DEBUG if settings.DEBUG else logging.INFO,
            format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        )


_configure_logging()
logger = logging.getLogger(__name__)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Environment: {settings.ENVIRONMENT}")

    # Initialize detection pipeline (pre-load models)
    init_pipeline()

    # Initialize database
    try:
        await init_db()
        logger.info("Database initialized")
    except Exception as e:
        logger.warning(f"Database init skipped (will retry on first request): {e}")

    yield

    logger.info("Shutting down...")


# Create app — disable docs in production if configured
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    docs_url="/docs" if settings.ENABLE_DOCS else None,
    redoc_url="/redoc" if settings.ENABLE_DOCS else None,
    openapi_url="/openapi.json" if settings.ENABLE_DOCS else None,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---- Middleware (order matters: bottom = first to execute) ----

# CORS — strict origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization"],
    max_age=600,
)

# Security headers
app.add_middleware(SecurityHeadersMiddleware)

# Request body size limit
app.add_middleware(RequestSizeLimitMiddleware)

# HTTPS redirect
if settings.FORCE_HTTPS:
    app.add_middleware(HTTPSRedirectMiddleware)

# API key auth
if settings.API_KEY:
    app.add_middleware(APIKeyMiddleware)


# ---- Global exception handlers ----

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """Custom validation error response — no stack traces."""
    errors = []
    for error in exc.errors():
        errors.append({
            "field": ".".join(str(x) for x in error["loc"]),
            "message": error["msg"],
            "type": error["type"],
        })
    return JSONResponse(
        status_code=422,
        content={"error": "Validation Error", "detail": errors},
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all handler — no tracebacks in production."""
    logger.error(f"Unhandled exception: {exc}")
    if settings.DEBUG:
        logger.error(traceback.format_exc())

    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "detail": str(exc) if settings.DEBUG else "An unexpected error occurred.",
        },
    )


# ---- Register routers ----

app.include_router(core_router)
app.include_router(playground_router)
app.include_router(analytics_router)
app.include_router(health_router)


# ---- Root redirect ----

@app.get("/", include_in_schema=False)
async def root():
    return {"service": settings.APP_NAME, "version": settings.APP_VERSION, "docs": "/docs"}
