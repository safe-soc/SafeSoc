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
| `requests` | `>=2.31.0` | Used by `injector/injector.py`, `clients/telegram.py`, TI/LLM HTTP clients |
| `sqlalchemy[asyncio]` | `>=2.0.0` | ORM — Postgres models (SS-007-009) |
| `asyncpg` | `>=0.29.0` | Async PostgreSQL driver |
| `alembic` | `>=1.13.0` | Postgres migrations |
| `redis` | `>=5.0.0` | Correlation windows, session context, pub/sub, rate limits (SS-010) |
| `celery` | `>=5.3.0` | Background task queue — enrichment, correlation, scoring, reporting, notifications (SS-011) |
| `bcrypt` | `>=4.0.0` | Password hashing (SS-012) |
| `pyjwt` | `>=2.8.0` | JWT issuance/verification (SS-013) |
| `scikit-learn` | `>=1.4.0` | Isolation Forest anomaly detection (SS-049-050) |
| `weasyprint` | `>=61.0` | PDF report generation (SS-052) |
| `pytest`, `pytest-asyncio`, `httpx` | — | Test suite (545 tests, SS-002) |

This is the full dependency set for every implemented feature — nothing in `core/config.py` currently lacks a corresponding installed package.

### 1.2 Deployment/runtime

| Component | Status |
|---|---|
| `backend/Dockerfile` | Implemented — `python:3.12-slim`, installs `requirements.txt`, runs `uvicorn app.main:app --reload` |
| Root `docker-compose.yml` (OpenSearch, PostgreSQL, Redis, backend, Celery worker, Celery beat) | Implemented — `docker compose up --build`, see `deployment.md` |

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

**Stack chosen and scaffolded (SS-057):** React 18 + TypeScript + Vite + Tailwind CSS — matching CloudLens's frontend (§2.2 above) for stack consistency and shared team familiarity, as the SRS itself doesn't mandate a framework (Phase 1 §3.5 left this open for Phase 2).

| Layer | Choice |
|---|---|
| Framework | React 18 (`react`, `react-dom`) |
| Language | TypeScript, strict mode |
| Build tool | Vite |
| Routing | `react-router-dom` (client-side, `BrowserRouter`) |
| Styling | Tailwind CSS |
| HTTP client | `axios` — single shared instance (`src/lib/api.ts`) with a request interceptor injecting the stored JWT and a response interceptor bouncing to `/login` on `401` |
| Auth state | React Context (`src/context/AuthContext.tsx`) backed by `localStorage` (`src/lib/auth-storage.ts`) |
| Lint | ESLint 9 (flat config), `typescript-eslint` |

Unlike CloudLens, no graph-visualization library is included — SafeSOC's dashboard doesn't have an equivalent relationship-graph view.

Run locally: `cd frontend && npm install && npm run dev` (serves on `http://localhost:5173`, configured via `VITE_API_BASE_URL` — see `.env.example`). Production build: `npm run build`.

## 4. Summary — Target vs. Actual (SafeSOC backend only)

| Layer | Report target | Actually installed |
|---|---|---|
| API framework | FastAPI | ✅ FastAPI |
| Schema validation | Pydantic | ✅ Pydantic |
| Log storage | OpenSearch | ✅ OpenSearch |
| Relational storage | PostgreSQL | ✅ PostgreSQL (SQLAlchemy async + Alembic) |
| Real-time/cache state | Redis | ✅ Redis |
| Task queue | — | ✅ Celery |
| Auth | JWT + RBAC | ✅ PyJWT + bcrypt |
| LLM inference | Ollama (local) / Groq (cloud) | ✅ both, provider-switchable via `LLM_PROVIDER` |
| Anomaly detection | Isolation Forest | ✅ scikit-learn |
| PDF reporting | — | ✅ WeasyPrint |
| Endpoint detection | Wazuh | ✅ adapter implemented (`adapters/wazuh.py`) |
| Deployment | Docker Compose (single command) | ✅ `docker compose up --build` |
