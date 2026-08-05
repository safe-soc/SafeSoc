# SafeSOC — Deployment

## 1. Current State vs. Report

The Phase 1 report (§4.5, §5.6) describes a root `docker-compose.yml` orchestrating two services (`opensearch`, `backend`) for single-command startup. **This file does not exist in the repository.** What exists:

| Artifact | Location | Status |
|---|---|---|
| Backend Dockerfile | `backend/Dockerfile` | Implemented |
| Root `docker-compose.yml` (SafeSOC backend + OpenSearch) | — | **Missing / TODO** |
| CloudLens `docker-compose.yml` | `cloud/docker-compose.yml` | Implemented, but scoped only to CloudLens (Django + React), independent of the SafeSOC backend |
| `.env.example` | repo root | **Present but empty** — no documented environment variables, despite `core/config.py` defining ~30 settings |

This is the single biggest gap between the report's deployment story ("single command, no manual configuration") and the current repo: **there is currently no one-command way to run the SafeSOC backend.**

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

This image alone is not sufficient to run SafeSOC — it needs a reachable OpenSearch instance (`OPENSEARCH_HOST`/`OPENSEARCH_PORT` env vars, defaulting to `localhost:9200`), which nothing in this repo currently provisions for the backend.

## 3. Running the Backend Today (Manual Steps)

Until a root compose file is added, the backend can be run manually:

1. **Start an OpenSearch instance** (not provided by this repo for the SafeSOC backend — you must supply one, e.g. via the official `opensearchproject/opensearch` image, with the security plugin disabled for dev as described in the report §5.4).
2. **Set environment variables** (or create a `.env` in `backend/`) matching the settings in `backend/app/core/config.py` — at minimum `OPENSEARCH_HOST`, `OPENSEARCH_PORT`, `OPENSEARCH_USER`, `OPENSEARCH_PASSWORD`. `.env.example` at the repo root is currently empty and does not document these.
3. **Install dependencies and run:**
   ```
   cd backend
   pip install -r requirements.txt
   uvicorn app.main:app --reload
   ```
   Or build/run the Dockerfile directly, pointing `OPENSEARCH_HOST` at wherever OpenSearch is reachable from the container.
4. **Verify:** `GET http://localhost:8000/health` should report `"opensearch": "connected"`.
5. **Generate test data:** `python injector/injector.py http://localhost:8000/api/v1/ingest <count>`.

## 4. CloudLens Deployment (Implemented, Separate)

`cloud/docker-compose.yml` provisions CloudLens (Django backend + React frontend) independently. See `cloud/README.md` / `cloud/AWS-IAM-backend/README.md` for its own setup instructions. It is **not** part of the SafeSOC backend's deployment and requires no OpenSearch — it uses its own SQLite/PostgreSQL database.

## 5. CI/CD

`.github/workflows/ci.yml` exists but is **empty** — no lint, test, or build steps run automatically on push/PR. This is a Planned item, not a broken pipeline (there is simply no pipeline yet).

## 6. Planned (per report, not yet built)

- Root `docker-compose.yml` defining `opensearch` + `backend` services with health checks and restart policies (report §4.5).
- Populated `.env.example` documenting every setting in `core/config.py`.
- Index Lifecycle Management for OpenSearch (90-day retention).
- A production compose/deployment path once PostgreSQL, Redis, and the Processing-layer services exist.
- CI pipeline (lint, test, build) in `.github/workflows/ci.yml`.
