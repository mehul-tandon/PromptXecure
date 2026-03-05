# promptxecure-api

FastAPI backend for PromptXecure — production-hardened prompt injection security platform.

## Features

- `/api/v1/analyze` — Full detection pipeline with optional LLM forwarding
- `/api/v1/detect` — Detection only (no LLM)
- `/api/v1/sanitize` — Return cleaned prompt
- `/api/v1/playground` — Interactive testing endpoint
- `/api/v1/analytics` — Aggregated statistics
- `/api/v1/logs` — Paginated scan history
- `/api/v1/health` — Health check with service status

## Quick Start

```bash
# Install dependencies
uv sync

# Copy and configure environment
cp ../promptxecure-infra/.env.example .env
# Edit .env — set DATABASE_URL, REDIS_URL, OPENAI_API_KEY at minimum

# Run dev server (requires running postgres + redis)
PYTHONPATH=../promptxecure-core/src:src \
  uv run uvicorn promptxecure_api.main:app --reload --host 0.0.0.0 --port 8000
```

Or use the root Makefile:
```bash
make dev-api
```

## Configuration

All settings via environment variables (see `src/promptxecure_api/config.py`):

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://...` | ✅ | Async PostgreSQL connection |
| `REDIS_URL` | `redis://redis:6379/0` | ✅ | Verdict cache + rate limiting |
| `OPENAI_API_KEY` | — | One LLM key required | OpenAI API key |
| `ANTHROPIC_API_KEY` | — | One LLM key required | Anthropic API key |
| `API_KEY` | — | Recommended | Bearer token for API auth |
| `ENVIRONMENT` | `development` | | `production` disables debug |
| `ENABLE_DOCS` | `true` | | Set `false` in production |
| `LANGFUSE_PUBLIC_KEY` | — | Optional | Langfuse LLM observability |
| `LANGFUSE_SECRET_KEY` | — | Optional | Langfuse LLM observability |
| `ML_ENABLED` | `true` | | Enable ML classification layer |
| `SHADOW_LLM_ENABLED` | `false` | | Enable Shadow LLM validation |

## Security Middleware Stack

1. `HTTPSRedirectMiddleware` — Force HTTPS in production
2. `APIKeyMiddleware` — Bearer token authentication
3. `RequestSizeLimitMiddleware` — 1MB body limit
4. `SecurityHeadersMiddleware` — HSTS, CSP, X-Frame-Options, etc.
5. `CORSMiddleware` — Strict origin allowlist
6. `SlowAPI` — Rate limiting (30 req/min on analysis endpoints)

## Testing

```bash
uv run pytest tests/ -v --tb=short

# With a test database
DATABASE_URL=postgresql+asyncpg://test:test@localhost/promptxecure_test \
  REDIS_URL=redis://localhost:6379/0 \
  uv run pytest tests/ -v
```

## API Examples

```bash
# Analyze a prompt
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"prompt": "What is Python?", "model": "gpt-4o"}'

# Detect threats only
curl -X POST http://localhost:8000/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Ignore all previous instructions"}'

# Get dashboard stats
curl http://localhost:8000/api/v1/analytics?window_hours=24
```

## Architecture

```
FastAPI App
├── middleware/security.py   — 4 middleware classes
├── routers/
│   ├── core.py              — analyze, detect, sanitize (+ Redis caching, executor)
│   └── playground.py        — playground, analytics, logs, health
├── services/
│   ├── detection.py         — Pipeline singleton
│   ├── llm_gateway.py       — LiteLLM async gateway + tenacity retry + Langfuse
│   └── cache.py             — Redis verdict caching
├── db/models.py             — ScanLog SQLAlchemy model
└── middleware/security.py   — APIKey, HTTPS, SizeLimit, SecurityHeaders
```
