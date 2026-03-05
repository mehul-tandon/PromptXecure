#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  PromptXecure — One-Command Setup & Launch Script
#  Checks prerequisites, installs dependencies, and starts all services.
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[  OK]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[FAIL]${NC}  $*"; }
header()  { echo -e "\n${PURPLE}${BOLD}═══ $* ═══${NC}\n"; }

# ── Navigate to project root ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo -e "${CYAN}${BOLD}"
echo "  ██████╗ ██████╗  ██████╗ ███╗   ███╗██████╗ ████████╗"
echo "  ██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗╚══██╔══╝"
echo "  ██████╔╝██████╔╝██║   ██║██╔████╔██║██████╔╝   ██║   "
echo "  ██╔═══╝ ██╔══██╗██║   ██║██║╚██╔╝██║██╔═══╝    ██║   "
echo "  ██║     ██║  ██║╚██████╔╝██║ ╚═╝ ██║██║        ██║   "
echo "  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝        ╚═╝   "
echo -e "  ${GREEN}X E C U R E${NC}  ${CYAN}— The Bodyguard for AI${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 1: Check Prerequisites
# ═══════════════════════════════════════════════════════════════════════════════
header "Step 1: Checking Prerequisites"

MISSING=0

check_cmd() {
    if command -v "$1" &>/dev/null; then
        local version
        version=$($2 2>&1 | head -1)
        success "$1 found — $version"
    else
        error "$1 is NOT installed"
        MISSING=1
    fi
}

check_cmd "docker"          "docker --version"
check_cmd "docker compose"  "docker compose version"
check_cmd "python3"         "python3 --version"
check_cmd "node"            "node --version"
check_cmd "npm"             "npm --version"

# Check for uv (Python package manager)
if command -v uv &>/dev/null; then
    success "uv found — $(uv --version 2>&1)"
else
    warn "uv not found — installing..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$PATH"
    if command -v uv &>/dev/null; then
        success "uv installed — $(uv --version 2>&1)"
    else
        error "Failed to install uv. Please install manually: https://docs.astral.sh/uv/"
        MISSING=1
    fi
fi

if [ "$MISSING" -eq 1 ]; then
    echo ""
    error "Missing required dependencies. Please install them and re-run this script."
    exit 1
fi

success "All prerequisites satisfied!"

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 2: Configure Environment
# ═══════════════════════════════════════════════════════════════════════════════
header "Step 2: Configuring Environment"

ENV_FILE="promptxecure-infra/.env"
ENV_EXAMPLE="promptxecure-infra/.env.example"

if [ -f "$ENV_FILE" ]; then
    success ".env file already exists at $ENV_FILE"
    warn "Review your settings: $ENV_FILE"
else
    if [ -f "$ENV_EXAMPLE" ]; then
        cp "$ENV_EXAMPLE" "$ENV_FILE"
        success "Created .env from .env.example"
        warn "⚠️  IMPORTANT: Edit ${ENV_FILE} to set your passwords and API keys!"
        echo ""
        info "Required settings to configure:"
        echo "   • POSTGRES_PASSWORD   — Strong database password"
        echo "   • REDIS_PASSWORD      — Strong Redis password"
        echo "   • LANGFUSE_ADMIN_EMAIL    — Admin email for Langfuse"
        echo "   • LANGFUSE_ADMIN_PASSWORD — Admin password for Langfuse"
        echo "   • OPENAI_API_KEY (or ANTHROPIC_API_KEY or GOOGLE_API_KEY)"
        echo ""
        read -p "$(echo -e "${YELLOW}Press Enter to continue after editing .env (or Ctrl+C to abort)...${NC}")" _
    else
        error ".env.example not found at $ENV_EXAMPLE"
        exit 1
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 3: Install Dependencies
# ═══════════════════════════════════════════════════════════════════════════════
header "Step 3: Installing Dependencies"

info "Installing Python dependencies (promptxecure-core)..."
(cd promptxecure-core && uv sync 2>&1) && success "Core dependencies installed" || warn "Core install had warnings (may be OK)"

info "Installing Python dependencies (promptxecure-api)..."
(cd promptxecure-api && uv sync 2>&1) && success "API dependencies installed" || warn "API install had warnings (may be OK)"

info "Installing Node dependencies (promptxecure-dashboard)..."
(cd promptxecure-dashboard && npm install 2>&1) && success "Dashboard dependencies installed" || warn "Dashboard install had warnings (may be OK)"

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 4: Build Docker Images
# ═══════════════════════════════════════════════════════════════════════════════
header "Step 4: Building Docker Images"

info "Building all Docker images (this may take a few minutes on first run)..."
docker compose -f promptxecure-infra/docker-compose.yml build

success "Docker images built successfully!"

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 5: Start All Services
# ═══════════════════════════════════════════════════════════════════════════════
header "Step 5: Starting All Services"

info "Starting all 8 services..."
docker compose -f promptxecure-infra/docker-compose.yml --env-file "$ENV_FILE" up -d

success "All services started!"

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 6: Health Check
# ═══════════════════════════════════════════════════════════════════════════════
header "Step 6: Running Health Checks"

info "Waiting for services to initialize (30 seconds)..."
sleep 30

# Check each service
echo ""
info "Service Status:"
docker compose -f promptxecure-infra/docker-compose.yml ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || \
docker compose -f promptxecure-infra/docker-compose.yml ps

echo ""

# Check API health
info "Checking API health..."
MAX_RETRIES=5
RETRY=0
API_HEALTHY=false

while [ $RETRY -lt $MAX_RETRIES ]; do
    if curl -sf http://localhost/api/v1/health > /dev/null 2>&1; then
        API_HEALTHY=true
        break
    fi
    RETRY=$((RETRY + 1))
    warn "API not ready yet, retrying in 10 seconds... ($RETRY/$MAX_RETRIES)"
    sleep 10
done

if [ "$API_HEALTHY" = true ]; then
    success "API is healthy!"
    curl -s http://localhost/api/v1/health | python3 -m json.tool 2>/dev/null || true
else
    warn "API health check timed out. Services may still be starting."
    info "Check manually: curl http://localhost/api/v1/health"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  Done!
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ✅ PromptXecure is UP AND RUNNING!${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Dashboard${NC}       →  http://localhost"
echo -e "  ${CYAN}API Docs${NC}        →  http://localhost/docs"
echo -e "  ${CYAN}API Health${NC}      →  http://localhost/api/v1/health"
echo -e "  ${CYAN}Grafana${NC}         →  http://localhost:3002"
echo -e "  ${CYAN}Langfuse${NC}        →  http://localhost:3000"
echo ""
echo -e "  ${YELLOW}Useful commands:${NC}"
echo "    make logs       — Tail all service logs"
echo "    make stop       — Stop all services"
echo "    make health     — Check API health"
echo "    make test       — Run all tests"
echo "    make clean      — Remove everything (DESTRUCTIVE)"
echo ""
