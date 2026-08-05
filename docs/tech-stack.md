# SafeSOC — Technology Stack

Two independent codebases exist in this repository with two independent stacks: the SafeSOC backend (`backend/`) and CloudLens (`cloud/`). This document covers both, plus what the report targets but isn't installed yet.

## 1. SafeSOC Backend

### 1.1 Actually declared (`backend/requirements.txt`)

| Package | Version constraint | Role |
|---|---|---|
| `fastapi` | `>=0.110.0` | Web framework |
| `uvicorn[standard]` | `>=0.27.0` | ASGI server |
| `opensearch-py` | `>=2.6.0` | OpenSearch client |
| `pydantic` | `>=2.6.0` | Data validation / `NormalizedLog` schema |
| `pydantic-settings` | `>=2.1.0` | Env-based config (`core/config.py`) |
| `python-dotenv` | `>=1.0.0` | `.env` loading |
| `requests` | `>=2.31.0` | Used by `injector/injector.py` (and would be used by TI clients once built) |

This is exactly enough to run the implemented ingestion/alerts/health surface. **Nothing else is installed.**

### 1.2 Referenced in code/config but not yet a dependency

`backend/app/core/config.py` already defines settings for services whose client libraries aren't in `requirements.txt` yet:

| Target technology | Config present? | Package present in `requirements.txt`? |
|---|---|---|
| PostgreSQL (async) | Yes — `postgres_url` property | No — needs `sqlalchemy`, `asyncpg`, `alembic` |
| Redis | Yes — `redis_url` property | No — needs `redis` |
| JWT auth | Yes — `JWT_SECRET`, `JWT_ALGORITHM`, `JWT_EXPIRY_HOURS` | No — needs `python-jose` or `pyjwt`, plus `bcrypt`/`passlib` |
| Ollama (local LLM) | Yes — `OLLAMA_HOST/PORT/MODEL`, `ollama_url` | No — `clients/ollama.py` is an empty stub |
| Groq (cloud LLM) | Yes — `GROQ_API_KEY`, `GROQ_MODEL` | No — `clients/groq.py` is an empty stub |
| VirusTotal | Yes — `VT_API_KEY`, rate limit | No — `clients/virustotal.py` is an empty stub |
| AbuseIPDB | Yes — `ABUSEIPDB_API_KEY`, rate limit | No — `clients/abuseipdb.py` is an empty stub |
| Telegram (notifications) | No dedicated setting yet | No — `clients/telegram.py` is an empty stub |
| Celery (background tasks) | No dedicated setting | No — `tasks/celery_app.py` is an empty stub; no message broker (e.g. `celery`, `redis`/`rabbitmq`) declared |
| WeasyPrint (PDF reports) | `REPORT_OUTPUT_DIR` etc. defined | No |
| Isolation Forest (anomaly detection) | `ANOMALY_MODEL_PATH`, `ANOMALY_THRESHOLD` defined | No — needs `scikit-learn`; `ml/` directory is empty |
| Wazuh integration | `LogSource.WAZUH` enum only | No adapter/library |

This is a config-first codebase: settings were scaffolded ahead of the code that will consume them, per the modular directory layout described in the report (§5.2).

### 1.3 Deployment/runtime

| Component | Status |
|---|---|
| `backend/Dockerfile` | Implemented — `python:3.12-slim`, installs `requirements.txt`, runs `uvicorn app.main:app --reload` |
| Root `docker-compose.yml` (backend + OpenSearch) | Implemented — `docker compose up --build`, see `deployment.md` |

## 2. CloudLens (`cloud/`)

An independently built and already-functional application, using a different stack from the SafeSOC backend:

### 2.1 Backend (`cloud/AWS-IAM-backend/requirements.txt`)

| Package | Role |
|---|---|
| `django>=5.0` | Web framework |
| `djangorestframework` | REST API layer |
| `django-cors-headers` | CORS |
| `python-dotenv` | Env loading |
| `boto3`, `botocore` | AWS SDK — IAM scanning |
| `networkx` | Graph analysis — attack path / privilege escalation detection |
| `scipy` | Supports NetworkX's layout/graph algorithms |
| `requests` | Telegram notifications, HTTP calls |
| `tzdata` | Timezone data |

Database: SQLite for dev, PostgreSQL for prod (per `cloud/AWS-IAM-backend/README.md`) — this is a **separate** database from the SafeSOC backend's planned PostgreSQL instance; the two are not currently shared or federated.

### 2.2 Frontend (`cloud/AWS-IAM-frontend`)

React + TypeScript + Vite, with Tailwind CSS (`tailwind.config.js`, `postcss.config.js`) and a force-directed graph library for the IAM relationship map. See `package.json` for exact versions.

## 3. SafeSOC Frontend

`frontend/` contains only a `.gitkeep` — **no stack has been chosen or implemented yet.** The report's Phase 1 SRS (§3.5) doesn't specify a frontend framework for the main SafeSOC dashboard either; this is an open decision for Phase 2.

## 4. Summary — Target vs. Actual (SafeSOC backend only)

| Layer | Report target | Actually installed |
|---|---|---|
| API framework | FastAPI | ✅ FastAPI |
| Schema validation | Pydantic | ✅ Pydantic |
| Log storage | OpenSearch | ✅ OpenSearch |
| Relational storage | PostgreSQL | ❌ not installed |
| Real-time/cache state | Redis | ❌ not installed |
| LLM inference | Ollama (local) / Groq (cloud) | ❌ neither installed |
| Endpoint detection | Wazuh | ❌ no integration code |
| Deployment | Docker Compose (single command) | ✅ `docker compose up --build` |
