# SafeSOC — Deployment

## 1. Current State vs. Report

The Phase 1 report (§4.5, §5.6) describes a root `docker-compose.yml` orchestrating two services (`opensearch`, `backend`) for single-command startup. This now exists and has been verified working end-to-end (SS-001).

| Artifact | Location | Status |
|---|---|---|
| Backend Dockerfile | `backend/Dockerfile` | Implemented |
| Root `docker-compose.yml` (SafeSOC backend + OpenSearch) | `docker-compose.yml` | **Implemented** — healthcheck-gated startup, verified end-to-end |
| CloudLens `docker-compose.yml` | `cloud/docker-compose.yml` | Implemented, but scoped only to CloudLens (Django + React), independent of the SafeSOC backend |
| `.env.example` | repo root | Implemented — documents every setting in `core/config.py`, tagged `[ACTIVE]`/`[PHASE 2]` |

## 2. Backend Dockerfile (Implemented)

`backend/Dockerfile`:
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
```

This image alone is not sufficient to run SafeSOC — it needs a reachable OpenSearch instance. `docker-compose.yml` (below) provisions and wires that up automatically.

## 3. Running the Backend with Docker Compose (Recommended)

From the repository root:

```bash
docker compose up --build
```

This starts two services, defined in `docker-compose.yml`:

- **`opensearch`** — single-node OpenSearch 2.x, security plugin disabled for local dev, persisted to a named volume (`opensearch-data`), with a healthcheck (`curl .../_cluster/health`) polled every 10s.
- **`backend`** — builds `backend/Dockerfile`, waits for `opensearch`'s healthcheck to report healthy (`depends_on: condition: service_healthy`) before starting, mounts `./backend` into the container for live-reload during development, and is pointed at the `opensearch` service by container hostname (`OPENSEARCH_HOST=opensearch`) rather than `localhost`.

No `.env` file is required to start — both services have working defaults. Verify it's up:

```bash
curl http://localhost:8000/health
# {"status":"healthy","version":"1.0.0","checks":{"opensearch":"connected"}}
```

Generate test data:

```bash
python injector/injector.py http://localhost:8000/api/v1/ingest 20
```

**Port overrides:** if `9200` or `8000` are already in use on your machine (e.g. by another OpenSearch/Wazuh setup), override the host-side ports without editing the compose file:

```bash
OPENSEARCH_PORT=9201 BACKEND_PORT=8001 docker compose up --build
```

**Restart policy:** both services are configured `restart: unless-stopped`, matching the SRS non-functional requirement that Docker services restart automatically on failure.

**Stopping:** `docker compose down` (add `-v` to also delete the OpenSearch data volume).

## 4. Running the Backend Without Docker (Alternative, for local debugging)

1. Start an OpenSearch instance reachable from your machine — the compose file above is the easiest way, or run one standalone: `docker run -p 9200:9200 -e "discovery.type=single-node" -e "DISABLE_SECURITY_PLUGIN=true" opensearchproject/opensearch:2`.
2. Copy `.env.example` to `backend/.env` and adjust `OPENSEARCH_*` values if your instance isn't on `localhost:9200`.
3. Install dependencies and run:
   ```bash
   cd backend
   pip install -r requirements.txt
   uvicorn app.main:app --reload
   ```
4. Verify: `GET http://localhost:8000/health` should report `"opensearch": "connected"`.

## 5. CloudLens Deployment (Implemented, Separate)

`cloud/docker-compose.yml` provisions CloudLens (Django backend + React frontend) independently. See `cloud/README.md` / `cloud/AWS-IAM-backend/README.md` for its own setup instructions. It is **not** part of the SafeSOC backend's deployment and requires no OpenSearch — it uses its own SQLite/PostgreSQL database. It is not orchestrated by the root `docker-compose.yml`; the two remain separate stacks until CloudLens integration (see `docs/roadmap-issues.md` SS-038–041) lands.

## 6. CI/CD

`.github/workflows/ci.yml` runs three smoke-check jobs on every push/PR (backend import check, CloudLens Django `manage.py check`, CloudLens frontend lint/typecheck/build) — see `docs/testing.md`. It does not yet run a real backend test suite (`backend/tests/` has no test cases beyond empty fixtures — see `docs/roadmap-issues.md` SS-002/SS-003).

## 7. Planned (not yet built)

- Index Lifecycle Management for OpenSearch (90-day retention) — `docs/roadmap-issues.md` SS-006.
- A production compose/deployment path once PostgreSQL, Redis, and the Processing-layer services exist — SS-007 onward.
- Automated backend test suite wired into CI — SS-002/SS-003.
