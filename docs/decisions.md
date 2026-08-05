# SafeSOC — Architecture Decision Log

Format: each entry records a decision, its rationale, and its current implementation status. Sourced from the Phase 1 report (§7.2 "Design Decisions Validated") and cross-checked against the code.

---

### ADR-001: Universal `NormalizedLog` schema as the data contract

**Decision:** Every log source, regardless of origin, is converted to a single Pydantic schema (`NormalizedLog`) before any downstream processing.
**Rationale:** Eliminates format-specific handling in every consumer (enrichment, correlation, investigation, reporting); Pydantic enforces the contract at the type level.
**Status: Implemented.** `backend/app/schemas/log.py`. All ingestion, storage mapping, and query code operates on this shape.

---

### ADR-002: Adapter pattern for source-specific ingestion

**Decision:** Source-specific parsing/transformation logic (Wazuh, AWS CloudTrail, AWS GuardDuty, synthetic) is isolated in an `adapters/` layer, separate from the universal ingestion pipeline.
**Rationale:** New sources can be added without touching validation, storage, or downstream processing logic.
**Status: Partially implemented.** The `adapters/` package exists and the ingestion pipeline is structured to accommodate it, but it currently contains no adapter code — `backend/app/adapters/__init__.py` is empty. Only the synthetic source is exercised, and even that isn't routed through a real adapter; the ingest endpoint just defaults `source` to `"synthetic"`. The pattern is validated architecturally, not yet proven with a second source.

---

### ADR-003: Monthly OpenSearch index partitioning

**Decision:** Logs are stored in indices named `safesoc-alerts-{YYYY}.{MM}`, auto-created on first write to a new month.
**Rationale:** Bounds per-index size, allows time-range queries to skip irrelevant indices, and simplifies retention (deleting old indices vs. deleting documents).
**Status: Implemented** for index creation and querying (`backend/app/db/opensearch.py`). **Not implemented:** the retention half of the rationale — no Index Lifecycle Management policy exists to actually delete indices older than 90 days, so the stated storage-bounding benefit isn't realized yet.

---

### ADR-004: Containerization via Docker, portable across environments

**Decision:** The platform should run identically on dev laptops and cloud VMs via containerization, with no vendor-specific cloud services required.
**Rationale:** SMB target customers and academic reviewers need zero-friction, single-command deployment.
**Status: Implemented.** `backend/Dockerfile` builds correctly, and a root `docker-compose.yml` (SS-001) now provides the single-command startup the report describes — `docker compose up --build` runs `opensearch` and `backend` together, with the backend gated on OpenSearch's healthcheck. Verified end-to-end: both containers build, OpenSearch reports healthy before the backend starts, and all four implemented endpoints (`/`, `/health`, `/api/v1/ingest`, `/api/v1/alerts`) respond correctly through the compose-managed stack.

---

### ADR-005: Ingestion never blocks on downstream processing

**Decision:** The ingest endpoint validates and writes to OpenSearch synchronously, but defers all enrichment/correlation/scoring to later, asynchronous stages so a slow or failing external dependency can't stall ingestion.
**Rationale:** Keeps ingestion latency low and resilient to threat-intel API outages.
**Status: Implemented by omission.** The ingest endpoint genuinely doesn't call any enrichment/correlation code today — because that code doesn't exist yet, not because an async task queue is deferring it. The non-blocking property currently holds trivially. Once enrichment/correlation are built (Phase 2), this decision will need to be re-validated with real async infrastructure (Celery/Redis, per `tech-stack.md`), which is not yet wired up (`tasks/celery_app.py` is an empty stub).

---

### ADR-006: Config defined ahead of implementation

**Decision (implicit, observed in code, not stated in the report):** `backend/app/core/config.py` defines settings for nearly every Phase 2 feature (Postgres, Redis, JWT, LLM providers, TI APIs, correlation, risk scoring, anomaly detection, reporting) before the corresponding code exists.
**Rationale (inferred):** Establishes the configuration surface/contract early so Phase 2 work can proceed against a stable settings object rather than renegotiating env var names per feature.
**Status: Implemented for config; not yet consumed.** Useful as a forward-looking scaffold, but it means `core/config.py` currently overstates what the running application actually does — a reader of that file alone would assume more is built than actually is. Worth keeping in mind when onboarding new contributors.

---

### ADR-007: CloudLens kept as a separate application pending integration

**Decision:** Rather than rewriting the existing CloudLens AWS IAM analyzer into the SafeSOC backend, it's retained as-is (Django + React, own Docker Compose) and will be integrated later by adapting its findings to the `NormalizedLog` schema and pushing them through the shared ingestion pipeline.
**Rationale:** CloudLens is already validated against a live AWS environment; a rewrite would risk regressing a working tool for architectural purity.
**Status: Decision made, integration not started.** CloudLens remains fully separate; `routers/v1/cloud.py` in the SafeSOC backend (the intended integration point) is an empty stub.

---

### ADR-008: Multi-tenancy enforced at the query layer via `tenant_id`

**Decision:** Rather than separate databases/schemas per tenant, all tenants share one OpenSearch cluster/index set, with `tenant_id` as a mandatory filter on every read and write.
**Rationale:** Most cost-effective way to serve many small tenants on shared infrastructure (report §1.5).
**Status: Partially implemented.** The filtering mechanism is real (`search_alerts()` always requires and applies `tenant_id`). What's missing is *trust* in that value — there is no authentication layer deriving `tenant_id` from a verified identity, so today it's caller-supplied and unenforced. The isolation model is sound; the enforcement is not yet in place.
