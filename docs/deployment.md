# SafeSOC — Deployment

## 1. Current State vs. Report

The Phase 1 report (§4.5, §5.6) describes a root `docker-compose.yml` for single-command startup. This now exists and has grown from the original 2-service (`opensearch`, `backend`) stack to a 6-service stack as the Postgres/Redis/Celery tiers landed (SS-001, SS-007, SS-010, SS-011) — verified working end-to-end.

| Artifact | Location | Status |
|---|---|---|
| Backend Dockerfile | `backend/Dockerfile` | Implemented |
| Root `docker-compose.yml` (OpenSearch, PostgreSQL, Redis, backend, Celery worker, Celery beat) | `docker-compose.yml` | **Implemented** — healthcheck-gated startup, verified end-to-end |
| CloudLens `docker-compose.yml` | `cloud/docker-compose.yml` | Implemented, but scoped only to CloudLens (Django + React), independent of the SafeSOC backend |
| `.env.example` | repo root | Implemented — documents settings in `core/config.py`, tagged `[ACTIVE]`/`[PHASE 2]` |

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

This starts six services, defined in `docker-compose.yml`:

- **`opensearch`** — single-node OpenSearch 2.x, security plugin disabled for local dev, persisted to a named volume (`opensearch-data`), with a healthcheck (`curl .../_cluster/health`) polled every 10s.
- **`postgres`** — PostgreSQL 16, healthcheck-gated, persisted to a named volume.
- **`redis`** — Redis 7, healthcheck-gated.
- **`backend`** — builds `backend/Dockerfile`, waits for all three healthchecks above before starting, mounts `./backend` into the container for live-reload during development, and is pointed at each dependency by container hostname (`OPENSEARCH_HOST=opensearch`, `POSTGRES_HOST=postgres`, `REDIS_HOST=redis`) rather than `localhost`.
- **`worker`** — `celery -A app.tasks.celery_app worker`, runs the enrichment/correlation/scoring/reporting/notification background tasks.
- **`beat`** — `celery -A app.tasks.celery_app beat`, dispatches the scheduled risk-recalculation and weekly-report tasks on their configured intervals.

No `.env` file is required to start — both services have working defaults. Verify it's up:

```bash
curl http://localhost:8000/health
# {"status":"healthy","version":"1.0.0","checks":{"opensearch":"connected"}}
```

Every endpoint except `/health` requires a JWT (SS-016). The fastest way to get one plus a realistic demo tenant:

```bash
python injector/demo.py
```

Or generate additional ad-hoc test data against that same tenant:

```bash
python injector/injector.py --scenario brute_force
```

`injector.py` logs in automatically (see `README.md`'s quickstart for the `--tenant-id`/`--email`/`--password`/`--no-auth` options).

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

`cloud/docker-compose.yml` provisions CloudLens (Django backend + React frontend) independently. See `cloud/README.md` / `cloud/AWS-IAM-backend/README.md` for its own setup instructions. It is **not** part of the SafeSOC backend's deployment and requires no OpenSearch — it uses its own SQLite/PostgreSQL database. It is not orchestrated by the root `docker-compose.yml`; the two remain separate stacks, though CloudLens's own container now pushes findings into SafeSOC's running backend over HTTP (`POST /api/v1/cloud/findings`, SS-038–041) — separate deployments, integrated data flow.

## 6. CI/CD

`.github/workflows/ci.yml` runs on every push/PR: the `safesoc-backend` job installs deps, runs an import smoke check, then runs the real backend `pytest` suite (545 tests); the two `cloudlens-*` jobs remain smoke checks (Django `manage.py check`, frontend lint/typecheck/build) — see `docs/testing.md`.

## 7. Not Yet Built

- A production-hardened deployment path (this compose file is a dev/demo setup — single OpenSearch node, no TLS termination, no secrets manager).
- `SS-071` (audit log) and `SS-072` (installer/setup script) — see `PRODUCT_ROADMAP.md`.
