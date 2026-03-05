# promptxecure-infra

Docker Compose infrastructure for the full PromptXecure platform.

## Services

| Service | Image | Port (internal) | External |
|---------|-------|-----------------|----------|
| `nginx` | nginx:1.25-alpine | 80 | ✅ 80 / 443 |
| `api` | Dockerfile.api | 8000 | ❌ via nginx |
| `dashboard` | Dockerfile.dashboard | 3001 | ❌ via nginx |
| `postgres` | postgres:15-alpine | 5432 | ❌ internal |
| `redis` | redis:7-alpine | 6379 | ❌ internal |
| `langfuse` | langfuse/langfuse | 3000 | ❌ via nginx |
| `loki` | grafana/loki | 3100 | ❌ internal |
| `grafana` | grafana/grafana | 3000 | ❌ via nginx |

All services communicate on the `promptxecure_network` internal bridge. Only Nginx is externally reachable.

## URL Routing (via Nginx)

| Path | Destination |
|------|-------------|
| `/` | React SPA (dashboard) |
| `/api/v1/*` | FastAPI backend |
| `/grafana/*` | Grafana |
| `/langfuse/*` | Langfuse |

## Quick Start

```bash
# 1. Copy and fill in environment variables
cp .env.example .env
# Edit .env — set passwords, API keys, domain

# 2. Start all services
docker compose up -d

# 3. Check health
docker compose ps
curl http://localhost/api/v1/health
```

Or use the root Makefile:
```bash
make prod    # Start all services (requires .env)
make stop    # Stop all services
make logs    # Tail all logs
make clean   # Destroy volumes (DESTRUCTIVE)
```

## First-Time Setup

After `docker compose up`:

1. **Langfuse** — Visit `http://localhost/langfuse` → create account → copy public + secret keys → add to `.env` → restart API
2. **Grafana** — Visit `http://localhost/grafana` → login with `GRAFANA_USER` / `GRAFANA_PASSWORD` → dashboards are auto-provisioned from `grafana/provisioning/`

## Environment Variables

Copy `.env.example` to `.env` and fill in values. Required variables:

```bash
# Database
POSTGRES_USER=promptxecure
POSTGRES_PASSWORD=<strong-password>
POSTGRES_DB=promptxecure

# Redis
REDIS_PASSWORD=<strong-password>

# LLM (at least one required)
OPENAI_API_KEY=sk-...
# ANTHROPIC_API_KEY=sk-ant-...

# Langfuse (fill after first login)
LANGFUSE_PUBLIC_KEY=pk-lf-...
LANGFUSE_SECRET_KEY=sk-lf-...
LANGFUSE_NEXTAUTH_SECRET=<openssl rand -base64 32>
LANGFUSE_SALT=<openssl rand -base64 16>

# Grafana
GRAFANA_USER=admin
GRAFANA_PASSWORD=<strong-password>
```

## Docker Images

### API (`Dockerfile.api`)
- Multi-stage: `builder` (uv install) → `runtime` (python:3.11-slim)
- Non-root user `promptxecure` (UID 1000)
- Pre-downloads `all-MiniLM-L6-v2` sentence-transformer model
- Healthcheck: `GET /api/v1/health`

### Dashboard (`Dockerfile.dashboard`)
- Multi-stage: `builder` (node:20-alpine + vite build) → `runtime` (nginx:1.25-alpine)
- Serves prebuilt static assets on port 3001
- Healthcheck: `GET /`

## Observability

- **Logs** → Loki (via Docker `json-file` log driver) → Grafana
- **LLM traces** → Langfuse (via LiteLLM callback)
- **Grafana dashboard** → pre-provisioned from `grafana/provisioning/dashboards/promptxecure.json`

## Volumes

| Volume | Contents |
|--------|----------|
| `postgres_data` | PostgreSQL scan log database |
| `redis_data` | Redis AOF persistence |
| `loki_data` | Loki log chunks |
| `grafana_data` | Grafana settings + additional dashboards |
| `langfuse_data` | Langfuse database |

## CI/CD

GitHub Actions are in `.github/workflows/ci.yml` and run on every push to `main`/`develop`:
- Lint (ruff + ESLint)
- Test (pytest core + api, Vite build)
- Security scan (bandit, pip-audit, Trivy)
- Docker build smoke test
