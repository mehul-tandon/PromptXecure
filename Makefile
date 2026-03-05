##############################################################################
#  PromptXecure — Makefile
#  Shortcuts for development and production operations.
#  Requires: uv, docker, docker compose, npm
##############################################################################

.PHONY: help dev prod stop clean logs test build install

INFRA_DIR := promptxecure-infra

help:           ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Development ──────────────────────────────────────────────────────────────

install:        ## Install all Python + Node dependencies
	cd promptxecure-core && uv sync
	cd promptxecure-api  && uv sync
	cd promptxecure-dashboard && npm install

dev-api:        ## Run FastAPI in dev mode (hot-reload)
	cd promptxecure-api && PYTHONPATH=../promptxecure-core/src:src uv run uvicorn \
		promptxecure_api.main:app --reload --host 0.0.0.0 --port 8000

dev-dash:       ## Run Vite dev server
	cd promptxecure-dashboard && npm run dev

train:          ## Train the ML classifier
	cd promptxecure-core && uv run python scripts/train_classifier.py

# ── Testing ───────────────────────────────────────────────────────────────────

test-core:      ## Run core unit tests
	cd promptxecure-core && uv run pytest tests/ -v --tb=short

test-api:       ## Run API tests
	cd promptxecure-api && uv run pytest tests/ -v --tb=short

test:           ## Run all tests
	$(MAKE) test-core
	$(MAKE) test-api

# ── Docker / Production ───────────────────────────────────────────────────────

build:          ## Build all Docker images
	docker compose -f $(INFRA_DIR)/docker-compose.yml build

prod:           ## Start all services in production mode
	@test -f $(INFRA_DIR)/.env || (echo "ERROR: Create $(INFRA_DIR)/.env from .env.example first" && exit 1)
	docker compose -f $(INFRA_DIR)/docker-compose.yml --env-file $(INFRA_DIR)/.env up -d

stop:           ## Stop all services
	docker compose -f $(INFRA_DIR)/docker-compose.yml down

logs:           ## Tail all service logs
	docker compose -f $(INFRA_DIR)/docker-compose.yml logs -f

logs-api:       ## Tail API logs only
	docker compose -f $(INFRA_DIR)/docker-compose.yml logs -f api

clean:          ## Remove containers + volumes (DESTRUCTIVE)
	docker compose -f $(INFRA_DIR)/docker-compose.yml down -v --remove-orphans
	docker image prune -f

# ── Validation ────────────────────────────────────────────────────────────────

validate-rules: ## Validate YAML rule syntax
	cd promptxecure-rules && python tests/validate_rules.py

health:         ## Check API health
	curl -s http://localhost:8000/api/v1/health | python -m json.tool
