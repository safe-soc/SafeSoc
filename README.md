# SafeSOC

**AI-Assisted Multi-Tenant Security Operations Platform for SMBs**

Major Project (Phase 1) — Dept. of Computer Science and Engineering, SJB Institute of Technology, VTU, 2025–26.

## What this is

Enterprise SIEMs (Splunk, Sentinel, QRadar) cost more than most small/medium businesses can justify. Open-source alternatives (Wazuh, ELK) remove the licensing cost but not the expertise barrier — their output is raw and technical, and SMBs rarely have a dedicated analyst to interpret it.

SafeSOC doesn't try to replace detection engines — it builds an intelligent operations layer on top of them: log normalization across sources, threat intelligence enrichment, attack-chain correlation, a natural-language investigation assistant, endpoint risk scoring, and automated reporting, all as a multi-tenant, containerized platform.

> **Status: Full roadmap (Milestones 1-14, SS-001 through SS-067) implemented.** Ingestion, auth/RBAC, threat-intel enrichment, attack-chain correlation, risk scoring, incident management, the NL investigation assistant, anomaly detection, automated reporting/notifications, the React frontend, real-time updates, and a security-hardening pass are all built and tested. See [Current Status](#current-status) below for the handful of items still open.

## Repository Structure

```
backend/          SafeSOC FastAPI backend — fully implemented
frontend/         SafeSOC React dashboard — implemented
injector/         Synthetic log generator (6 attack scenarios) + one-command demo mode
ml/               Isolation Forest anomaly model — training data, training script, trained model
scripts/          Utility scripts — not started yet
cloud/            CloudLens — standalone AWS IAM risk & attack-path analyzer, bridged into SafeSOC's ingestion pipeline
docs/             Project documentation (architecture, API, requirements, roadmap, ...)
infrastructure/   Infra-as-code — not started yet
assets/           Architecture and ER diagrams
```

## Current Status

| Area | State |
|---|---|
| Log ingestion & normalization (`POST /api/v1/ingest`) | ✅ Implemented |
| Alert search (`GET /api/v1/alerts`) | ✅ Implemented |
| OpenSearch storage, monthly index partitioning | ✅ Implemented |
| Authentication / RBAC / enforced multi-tenancy | ✅ Implemented (JWT, bcrypt, admin/analyst/viewer roles) |
| Synthetic log injector | ✅ Implemented (6 named attack scenarios + one-command demo mode) |
| CloudLens (AWS IAM risk analyzer) | ✅ Implemented, standalone |
| CloudLens ↔ SafeSOC integration | ✅ Implemented (`POST /api/v1/cloud/findings`) |
| Threat intelligence enrichment | ✅ Implemented (VirusTotal, AbuseIPDB) |
| Attack chain correlation | ✅ Implemented (6 patterns, Redis sliding windows, MITRE mapping) |
| Endpoint risk scoring | ✅ Implemented |
| Incident management | ✅ Implemented (lifecycle, notes, alert linking) |
| Natural language investigation assistant | ✅ Implemented (8 intents, MCP tools, Ollama/Groq) |
| Anomaly detection (Isolation Forest) | ✅ Implemented |
| Automated PDF reporting | ✅ Implemented (weekly digest) |
| Telegram notifications | ✅ Implemented |
| Real-time dashboard updates (WebSocket) | ✅ Implemented |
| React frontend | ✅ Implemented |
| Load/performance benchmark harness | ✅ Implemented |
| Security hardening (rate limiting, JWT guard, timing-safe comparisons) | ✅ Implemented — see [`docs/security-review.md`](docs/security-review.md) |
| Single-command Docker Compose deployment | ✅ Implemented (`docker compose up --build`) |

Full detail, file-by-file, is in [`docs/architecture.md`](docs/architecture.md), [`docs/requirements.md`](docs/requirements.md), and [`docs/project-roadmap.md`](docs/project-roadmap.md).

## Running the Backend

```bash
docker compose up --build
```

That's it — no `.env` required. This starts OpenSearch and the SafeSOC backend together, with the backend waiting for OpenSearch to report healthy before it starts. If ports `9200`/`8000` are already in use on your machine, override them: `OPENSEARCH_PORT=9201 BACKEND_PORT=8001 docker compose up --build`.

Confirm it's healthy:
```
curl http://localhost:8000/health
```

Every API endpoint except `/health` requires a JWT (`Authorization: Bearer <token>`) — the fastest way to get a working demo tenant, a logged-in user, realistic alert history, and both an active and a resolved incident in one step:
```
python injector/demo.py
```
This prints the demo tenant's login (`demo@safesoc.example` / `SafeSOC-Demo-2026!`) at the end. From there, generate additional ad-hoc test data against that same tenant:
```
python injector/injector.py --scenario brute_force
```
`injector.py` logs in automatically (defaulting to the demo tenant above); pass `--tenant-id`/`--email`/`--password` to target a different user, or `--no-auth` to send the legacy unauthenticated payload shape against a backend with auth disabled. Run `python injector/injector.py --help` for the full scenario list and options.

See [`docs/deployment.md`](docs/deployment.md) for the non-Docker/manual alternative, useful for local debugging.

### Example: ingest a log directly

```bash
# Get a token first (see above), then:
curl -X POST http://localhost:8000/api/v1/ingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "logs": [{
      "source": "synthetic",
      "log_type": "authentication",
      "timestamp": "2026-08-05T02:47:11Z",
      "host_id": "DESKTOP-042",
      "host_ip": "192.168.1.42",
      "action": "failed_login",
      "description": "Failed SSH authentication attempt",
      "severity": "high"
    }]
  }'
```

`tenant_id` is derived from the token, not the payload, once authenticated — see `docs/api-design.md`.

Interactive API docs (Swagger UI) are available at `http://localhost:8000/docs` while the backend is running in debug mode.

## CloudLens

CloudLens (`cloud/`) is a separate, fully working AWS IAM risk and attack-path analyzer — Django + DRF backend, React + TypeScript frontend, with its own [`docker-compose.yml`](cloud/docker-compose.yml). It scans IAM users/roles/policies, visualizes privilege-escalation paths, and sends Telegram notifications. Its findings are bridged into SafeSOC's unified alert stream via `POST /api/v1/cloud/findings` (service-token authenticated). See [`cloud/README.md`](cloud/README.md).

## Documentation

| Doc | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Layer-by-layer implementation status |
| [`docs/requirements.md`](docs/requirements.md) | SRS requirements vs. actual implementation |
| [`docs/api-design.md`](docs/api-design.md) | Endpoint contracts, all implemented |
| [`docs/database-schema.md`](docs/database-schema.md) | OpenSearch mapping, Postgres/Redis schemas |
| [`docs/tech-stack.md`](docs/tech-stack.md) | Actual dependencies in use |
| [`docs/deployment.md`](docs/deployment.md) | How to actually run this today |
| [`docs/testing.md`](docs/testing.md) | Current test coverage (545 tests, CI-enforced) |
| [`docs/security-review.md`](docs/security-review.md) | OWASP-oriented security review (SS-067) |
| [`docs/decisions.md`](docs/decisions.md) | Architecture decision log |
| [`docs/project-roadmap.md`](docs/project-roadmap.md) | Milestone-by-milestone status |
| [`docs/roadmap-issues.md`](docs/roadmap-issues.md) | Full issue backlog with completion status |
| [`docs/coding-standards.md`](docs/coding-standards.md) | Conventions observed in the implemented code |
| [`docs/meeting-notes.md`](docs/meeting-notes.md) | Meeting log template |

## Team

| Name | USN |
|---|---|
| Shreyas Satish | 1JB23CS146 |
| Sohan Kanna D. | 1JB23CS152 |
| Tanush Somani | 1JB23CS167 |
| Vishwas Adhikari | 1JB23CS187 |

**Guide:** Dr. Krishna A N, Professor & Head, Dept. of CSE, SJB Institute of Technology

## License

See [`LICENSE`](LICENSE). *(Not yet finalized — the file is currently a placeholder.)*
