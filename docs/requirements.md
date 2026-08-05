# SafeSOC — Requirements Status

Source: Software Requirements Specification, Phase 1 Report (Chapter 3). Every requirement below is tagged against the current state of this repository.

Status legend: **Implemented** · **Partial** (some part works, rest missing) · **Planned** (spec'd, no code yet).

## 1. Product Perspective

SafeSOC is intended to sit between expensive enterprise SIEMs and unmanaged open-source tools (Wazuh/ELK), providing an operations layer — enrichment, correlation, investigation, reporting — on top of open-source detection. **Planned as a whole**: the operations layer (enrichment, correlation, NL investigation, reporting) does not exist yet. What exists today is the ingestion/normalization foundation those features will sit on.

## 2. User Classes & Access Control

| User class | Status |
|---|---|
| SMB IT Administrator, Business Owner, Security Consultant, Platform Administrator (defined roles) | **Planned** — no user model, no login, no role distinction anywhere in the codebase. |
| Role-based access (Admin / Analyst / Viewer) | **Planned** — `UserRole` enum exists (`backend/app/core/enums.py`) but nothing enforces it; `core/security.py` and `core/dependencies.py` are empty stubs. |

## 3. Core Functional Requirements

| Requirement | Status | Evidence |
|---|---|---|
| **Log ingestion & normalization** — REST endpoint, single + batch (up to 1,000/request), universal `NormalizedLog` schema, per-batch partial failure handling, UUID `alert_id` + dual timestamps | **Implemented** | `routers/v1/ingest.py`, `schemas/log.py`, `services/ingestion.py`. Note: the report specifies a 1,000-log batch cap; no such limit is enforced in code today — batches of any size are accepted. |
| Source-specific adapters (Wazuh, CloudTrail, GuardDuty, synthetic) | **Partial** | Only the synthetic path is exercised. `adapters/` is an empty package; Wazuh/AWS log formats are never parsed or transformed. |
| Monthly OpenSearch index partitioning | **Implemented** | `db/opensearch.py` (`_build_index_name`), mapping in `db/mappings/alert_mapping.py`. |
| Index Lifecycle Management (auto-delete after 90 days) | **Planned** | No ILM policy is defined or applied anywhere in the code. |
| **Threat intelligence enrichment** (AbuseIPDB, VirusTotal, PostgreSQL cache, rate limiting, async) | **Planned** | `clients/abuseipdb.py`, `clients/virustotal.py`, `services/enrichment.py` are all empty stubs. Cache TTL settings exist in config but are unused. |
| **Natural language investigation assistant** (8 intents, MCP orchestration, conversation context) | **Planned** | `services/investigation.py`, `mcp/__init__.py`, `routers/v1/investigate.py` are empty. `clients/ollama.py` and `clients/groq.py` are empty stubs. |
| **Attack chain correlation engine** (6 patterns, Redis sliding windows, MITRE mapping) | **Planned** | `services/correlation.py`, `workers/correlation_worker.py` are empty. Redis client (`db/redis.py`) is unimplemented, so no sliding-window state can be kept. |
| **Endpoint risk scoring** (0–100, decay, four risk levels) | **Planned** | `services/risk_scoring.py`, `tasks/scoring.py` are empty. Scoring weight constants exist in `core/config.py` but are unused. |
| **Incident management** (lifecycle, linked alerts, notes, reports) | **Planned** | `routers/v1/incidents.py` is empty. No incident model exists. |
| **Cloud security monitoring** (CloudTrail/GuardDuty ingestion, unified queue) | **Planned** | `routers/v1/cloud.py` is empty. CloudLens (see `architecture.md`) implements equivalent detections independently but is not connected to this pipeline. |
| **Anomaly detection** (Isolation Forest, Z-score) | **Planned** | `services/anomaly.py` is empty. `ml/` directory contains only `.gitkeep` — no trained model, no training data. |
| **Automated reporting** (weekly PDF digest via WeasyPrint) | **Planned** | `services/reporting.py`, `tasks/reporting.py` are empty. WeasyPrint is not in `backend/requirements.txt`. |
| **Multi-tenant architecture** (query-layer isolation, JWT, bcrypt, 3 roles) | **Partial** | `tenant_id` is a required, filtered field in ingestion and search (data-model level isolation). JWT auth, bcrypt hashing, and role enforcement are **not implemented** — `tenant_id` is currently caller-supplied and unauthenticated. |
| **Synthetic data generation** (multiple attack scenarios, demo mode) | **Partial** | `injector/injector.py` generates randomized normal-looking logs of one type (`authentication`) by default. It does **not** implement the "multiple attack scenarios" or "comprehensive demo mode with active attack chains" described in the report. |

## 4. Non-Functional Requirements

| Requirement | Status | Notes |
|---|---|---|
| ≥100 log events/sec ingestion | **Unverified** | No load test exists in the repo (see `testing.md`). The report cites ~50ms for 10-log batches as an informal observation, not an automated benchmark. |
| Alert queries < 500ms | **Unverified** | Same as above — no automated performance test. |
| NL assistant responds within 15s | **Not applicable yet** | Feature not implemented. |
| Docker services restart automatically on failure | **Implemented** | `docker-compose.yml` sets `restart: unless-stopped` on both services (see `deployment.md`). |
| Single-command startup (`docker compose up`) | **Implemented** | `docker compose up --build` from repo root; verified end-to-end — OpenSearch reaches healthy, backend starts after it, all four implemented endpoints respond correctly. |
| Cross-platform (Ubuntu/macOS/Windows + Docker) | **Partially verified** | Verified working on Windows + Docker Desktop. Not yet tested on Ubuntu/macOS. |
| No vendor-specific cloud services required | **Implemented** (by design) | Stack is OpenSearch/FastAPI/Docker; no cloud-managed services are referenced in code. |
| Graceful handling of external API failures (cached fallback) | **Planned** | No external API integrations are implemented yet to exhibit this behavior. |

## 5. Technology Stack Requirements

See `tech-stack.md` for the full comparison between the report's target stack and what's actually declared in `backend/requirements.txt`.

## 6. Summary

Of the ~13 core functional requirements in the SRS, **1 is fully implemented** (log ingestion & normalization), **3 are partial** (adapters, multi-tenancy, synthetic data generation), and **9 are planned with no implementation**. This matches the Phase 1 report's own scope statement (§5.1): Phase 1 targeted the core data pipeline plus the standalone CloudLens module, deferring the intelligence and user-facing layers to Phase 2.
