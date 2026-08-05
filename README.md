# SafeSOC

**AI-Assisted Multi-Tenant Security Operations Platform for SMBs**

Major Project (Phase 1) — Dept. of Computer Science and Engineering, SJB Institute of Technology, VTU, 2025–26.

## What this is

Enterprise SIEMs (Splunk, Sentinel, QRadar) cost more than most small/medium businesses can justify. Open-source alternatives (Wazuh, ELK) remove the licensing cost but not the expertise barrier — their output is raw and technical, and SMBs rarely have a dedicated analyst to interpret it.

SafeSOC doesn't try to replace detection engines — it builds an intelligent operations layer on top of them: log normalization across sources, threat intelligence enrichment, attack-chain correlation, a natural-language investigation assistant, endpoint risk scoring, and automated reporting, all as a multi-tenant, containerized platform.

> **Status: Phase 1 complete.** The core log ingestion pipeline is implemented and working. The intelligence layer described above (enrichment, correlation, NL assistant, risk scoring, reporting) is designed and scaffolded but **not yet built** — see [Current Status](#current-status) below before assuming a feature works.

## Repository Structure

```
backend/          SafeSOC FastAPI backend (the real Phase 1 implementation)
frontend/         SafeSOC React dashboard (not started)
injector/         Synthetic log generator, used for testing/demo
ml/               Anomaly detection model artifacts (Phase 2)
scripts/          Utility scripts (Phase 2)
cloud/            CloudLens — standalone AWS IAM risk & attack-path analyzer
docs/             Project documentation (architecture, API, requirements, roadmap, ...)
infrastructure/   Infra-as-code (Phase 2)
assets/           Architecture and ER diagrams
```

## Current Status

| Area | State |
|---|---|
| Log ingestion & normalization (`POST /api/v1/ingest`) | ✅ Implemented |
| Alert search (`GET /api/v1/alerts`) | ✅ Implemented |
| OpenSearch storage, monthly index partitioning | ✅ Implemented |
| Synthetic log injector | ✅ Implemented (basic — single log type, no attack scenarios yet) |
| CloudLens (AWS IAM risk analyzer) | ✅ Implemented, standalone |
| Threat intelligence enrichment | ⏳ Planned |
| Attack chain correlation | ⏳ Planned |
| Natural language investigation assistant | ⏳ Planned |
| Endpoint risk scoring | ⏳ Planned |
| Incident management | ⏳ Planned |
| Anomaly detection (Isolation Forest) | ⏳ Planned |
| Automated PDF reporting | ⏳ Planned |
| Authentication / RBAC / enforced multi-tenancy | ⏳ Planned |
| CloudLens ↔ SafeSOC integration | ⏳ Planned |
| React frontend | ⏳ Planned |
| Single-command Docker Compose deployment | ⏳ Planned (no root `docker-compose.yml` yet) |

Full detail, file-by-file, is in [`docs/architecture.md`](docs/architecture.md), [`docs/requirements.md`](docs/requirements.md), and [`docs/project-roadmap.md`](docs/project-roadmap.md).

## Running the Backend (Today)

There is no single-command deployment yet (see [`docs/deployment.md`](docs/deployment.md)). To run the implemented ingestion pipeline locally:

1. Start an OpenSearch instance reachable from your machine (security plugin disabled for local dev), e.g.:
   ```
   docker run -p 9200:9200 -e "discovery.type=single-node" -e "DISABLE_SECURITY_PLUGIN=true" opensearchproject/opensearch:2
   ```
2. Copy `.env.example` to `backend/.env` and adjust `OPENSEARCH_*` values if needed.
3. Install and run the backend:
   ```
   cd backend
   pip install -r requirements.txt
   uvicorn app.main:app --reload
   ```
4. Confirm it's healthy:
   ```
   curl http://localhost:8000/health
   ```
5. Generate some test data:
   ```
   python injector/injector.py http://localhost:8000/api/v1/ingest 20
   ```

### Example: ingest a log directly

```bash
curl -X POST http://localhost:8000/api/v1/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acme-corp",
    "logs": [{
      "tenant_id": "acme-corp",
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

Interactive API docs (Swagger UI) are available at `http://localhost:8000/docs` while the backend is running in debug mode.

## CloudLens

CloudLens (`cloud/`) is a separate, fully working AWS IAM risk and attack-path analyzer — Django + DRF backend, React + TypeScript frontend, with its own [`docker-compose.yml`](cloud/docker-compose.yml). It scans IAM users/roles/policies, visualizes privilege-escalation paths, and sends Telegram notifications. It is not yet integrated into SafeSOC's unified alert stream. See [`cloud/README.md`](cloud/README.md).

## Documentation

| Doc | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Layer-by-layer implementation status |
| [`docs/requirements.md`](docs/requirements.md) | SRS requirements vs. actual implementation |
| [`docs/api-design.md`](docs/api-design.md) | Endpoint contracts (implemented + planned) |
| [`docs/database-schema.md`](docs/database-schema.md) | OpenSearch mapping, planned Postgres/Redis schemas |
| [`docs/tech-stack.md`](docs/tech-stack.md) | Actual vs. target dependencies |
| [`docs/deployment.md`](docs/deployment.md) | How to actually run this today |
| [`docs/testing.md`](docs/testing.md) | Current test coverage (none yet) and what's planned |
| [`docs/decisions.md`](docs/decisions.md) | Architecture decision log |
| [`docs/project-roadmap.md`](docs/project-roadmap.md) | Phase 1 (done) vs. Phase 2 (planned) |
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
