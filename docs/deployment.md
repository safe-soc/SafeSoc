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
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"]
```

(Abridged: the real file also installs Pango for WeasyPrint.)

**Migrations run automatically.** The default `CMD` runs `alembic upgrade head` before uvicorn starts, so a fresh Postgres volume (first `docker compose up`, or after `docker compose down -v`) gets its schema before the API serves a request. This used to be a manual step; without it, `injector/demo.py` failed on a fresh volume with `relation "tenants" does not exist`. The command is idempotent: on an up-to-date database alembic connects, finds nothing to apply, and uvicorn starts normally. If a migration fails, the `&&` stops uvicorn from starting, and the container exits and restarts (`restart: unless-stopped`) rather than serving against a half-migrated schema.

This image alone is not sufficient to run SafeSOC — it needs a reachable OpenSearch instance. `docker-compose.yml` (below) provisions and wires that up automatically.

## 3. Running the Backend with Docker Compose (Recommended)

**One-command quickstart (SS-072):** `scripts/install.ps1` (Windows/PowerShell) or `scripts/install.sh` (Linux/macOS) checks Docker is installed and running, copies `.env.example` to `.env` if one doesn't exist yet (never overwrites an existing one), runs `docker compose up --build -d`, and polls `/health` until the backend reports healthy:

```bash
./scripts/install.sh          # Linux/macOS
./scripts/install.ps1         # Windows
```

Safe to re-run any time — every step is idempotent.

Or run the same steps manually, from the repository root:

```bash
docker compose up --build
```

This starts six services, defined in `docker-compose.yml`:

- **`opensearch`** — single-node OpenSearch 2.x, security plugin disabled for local dev, persisted to a named volume (`opensearch-data`), with a healthcheck (`curl .../_cluster/health`) polled every 10s.
- **`postgres`** — PostgreSQL 16, healthcheck-gated, persisted to a named volume.
- **`redis`** — Redis 7, healthcheck-gated.
- **`backend`** — builds `backend/Dockerfile`, waits for all three healthchecks above before starting, mounts `./backend` into the container for live-reload during development, and is pointed at each dependency by container hostname (`OPENSEARCH_HOST=opensearch`, `POSTGRES_HOST=postgres`, `REDIS_HOST=redis`) rather than `localhost`.
- **`backend`** also has a healthcheck: a small Python `urllib` request to its own `/health`, since `python:3.12-slim` ships no `curl`. `/health` answers 200 even when a dependency is degraded, so passing it means "migrations done, uvicorn serving".
- **`worker`** — `celery -A app.tasks.celery_app worker`, runs the enrichment/correlation/scoring/reporting/notification background tasks. Reads the same root `.env` as `backend`, so both always agree on which LLM provider and model are in use.
- **`beat`** — `celery -A app.tasks.celery_app beat`, dispatches the scheduled risk-recalculation and weekly-report tasks on their configured intervals.

Only `backend` migrates. `worker` and `beat` build from the same image but override its `command:`, so they never run `alembic upgrade`; concurrent upgrades would race on the same schema. Instead they `depends_on: backend: condition: service_healthy`, so they start only after the backend has migrated and is serving.

No `.env` file is required to start — every service has working defaults. Where one exists, `docker-compose.yml` loads the **root `.env`** into `backend`, `worker` and `beat` (`env_file`, `required: false`), so the AI features are configured in one place: set `LLM_PROVIDER=ollama` with the model pulled on the Docker host (`ollama pull llama3.2:3b`), or `LLM_PROVIDER=groq` with a real `GROQ_API_KEY`. The same file supplies `VT_API_KEY`, `ABUSEIPDB_API_KEY` and `TELEGRAM_*`; only the container hostnames (`OPENSEARCH_HOST`, `POSTGRES_HOST`, `REDIS_HOST`, `OLLAMA_HOST`) stay in compose's own `environment:`, because those must override `.env`'s `localhost` values. Without a configured, reachable provider the AI summary and incident chat fall back to their templated text rather than failing.

Verify it's up:

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

For a fully populated presentation-ready environment (dozens of endpoints/users, a realistic severity distribution, several coherent multi-alert incidents, and a software/vulnerability inventory) instead of `demo.py`'s smaller quick-start set, use the deterministic simulation generator — see `README.md`'s "Full SOC Simulation" section:

```bash
python injector/simulate.py --reset --seed   # clean slate, then populate everything
python injector/simulate.py --seed           # populate only (idempotent, safe to re-run)
python injector/simulate.py --reset          # wipe this simulation's data only
```

**Port overrides:** if `9200` or `8000` are already in use on your machine (e.g. by another OpenSearch/Wazuh setup), override the host-side ports without editing the compose file:

```bash
OPENSEARCH_PORT=9201 BACKEND_PORT=8001 docker compose up --build
```

**Restart policy:** both services are configured `restart: unless-stopped`, matching the SRS non-functional requirement that Docker services restart automatically on failure.

**Stopping:** `docker compose down`. Add `-v` to also delete the named volumes (OpenSearch, Postgres, Redis); the next `docker compose up` re-creates the schema automatically (see §2), after which `python injector/demo.py` re-provisions the demo tenant.

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

`.github/workflows/ci.yml` runs on every push/PR: the `safesoc-backend` job installs deps, runs an import smoke check, then runs the real backend `pytest` suite; `release-scripts` (SS-076) runs `scripts/changelog_extract.py`'s own tests; the two `cloudlens-*` jobs remain smoke checks (Django `manage.py check`, frontend lint/typecheck/build) — see `docs/testing.md`. `.github/workflows/docs.yml` (SS-073) and `release.yml` (SS-076) are separate, path/tag-triggered workflows — see `docs/release-process.md`.

## 7. Not Yet Built

- A production-hardened deployment path (this compose file is a dev/demo setup — single OpenSearch node, no TLS termination, no secrets manager).
- `SS-071` (audit log, `services/audit.py`) and `SS-072` (this section's installer script) are both now implemented — see `PRODUCT_ROADMAP.md` for the rest of the v1.1+/v2.0 backlog (plugin SDK, docs site, contribution guide, security policy, release automation, observability, Kubernetes/Helm, and beyond).
