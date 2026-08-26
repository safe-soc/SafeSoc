#!/usr/bin/env bash
# SafeSOC one-command installer/quickstart (SS-072, Linux/macOS).
#
# Verifies Docker is installed and running, copies .env.example to .env
# if one doesn't exist yet, brings up the full docker-compose stack
# (OpenSearch, PostgreSQL, Redis, backend, Celery worker, Celery beat),
# waits for the backend's own /health check to report healthy, and
# prints the next step (provisioning a demo tenant).
#
# Safe to re-run: every step is idempotent - an already-running stack
# is left alone (docker compose up is itself idempotent), and an
# existing .env is never overwritten.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_PORT="${BACKEND_PORT:-8000}"

step()    { printf '\033[36m==> %s\033[0m\n' "$1"; }
success() { printf '\033[32mOK  %s\033[0m\n' "$1"; }
failure() { printf '\033[31mFAIL %s\033[0m\n' "$1"; }

step "Checking Docker is installed"
if ! command -v docker >/dev/null 2>&1; then
  failure "Docker was not found on PATH. Install Docker: https://docs.docker.com/get-docker/"
  exit 1
fi
success "Docker found: $(command -v docker)"

step "Checking the Docker daemon is running"
if ! docker info >/dev/null 2>&1; then
  failure "Docker daemon is not reachable. Start Docker and re-run this script."
  exit 1
fi
success "Docker daemon is reachable"

step "Checking for a .env file"
if [ -f "$REPO_ROOT/.env" ]; then
  success ".env already exists - leaving it untouched"
elif [ -f "$REPO_ROOT/.env.example" ]; then
  cp "$REPO_ROOT/.env.example" "$REPO_ROOT/.env"
  success "Copied .env.example -> .env (every setting has a working local-dev default; edit .env to add real API keys/tokens later)"
else
  printf '\033[33mNo .env.example found - every service has a working default without one, continuing.\033[0m\n'
fi

step "Starting the SafeSOC stack (docker compose up --build -d)"
(cd "$REPO_ROOT" && docker compose up --build -d)
success "Containers started"

step "Waiting for the backend to report healthy (up to 2 minutes)"
healthy=false
for _ in $(seq 1 24); do
  if curl -sf "http://localhost:${BACKEND_PORT}/health" 2>/dev/null | grep -q '"status":"healthy"'; then
    healthy=true
    break
  fi
  sleep 5
done

if [ "$healthy" != true ]; then
  failure "Backend did not report healthy within 2 minutes. Check logs: docker compose logs backend"
  exit 1
fi
success "Backend is healthy at http://localhost:${BACKEND_PORT}/health"

cat <<EOF

SafeSOC is running.
  API:        http://localhost:${BACKEND_PORT}
  API docs:   http://localhost:${BACKEND_PORT}/docs

Next step - provision a demo tenant with realistic data:
  python injector/demo.py

Then run the frontend dashboard separately:
  cd frontend && npm install && npm run dev
EOF
