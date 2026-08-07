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
**Status: Implemented.** `adapters/{wazuh,cloudtrail,guardduty,cloudlens}.py` (SS-018–020, SS-038) each implement `transform(raw) -> dict`; `services/ingestion.py::ADAPTER_REGISTRY` dispatches a batch to the matching adapter by its `source` field (SS-021). The pattern is now proven with four real sources, not just architecturally validated.

---

### ADR-003: Monthly OpenSearch index partitioning

**Decision:** Logs are stored in indices named `safesoc-alerts-{YYYY}.{MM}`, auto-created on first write to a new month.
**Rationale:** Bounds per-index size, allows time-range queries to skip irrelevant indices, and simplifies retention (deleting old indices vs. deleting documents).
**Status: Implemented**, including retention (SS-006): index creation and querying in `backend/app/db/opensearch.py`, plus an idempotent ISM policy (`ensure_ilm_policy()`) that auto-deletes indices older than `settings.OPENSEARCH_ILM_RETENTION_DAYS` (90 by default), applied via an `ism_template` so it covers new indices automatically without per-index wiring. The storage-bounding benefit the rationale describes is now realized, not just designed for.

---

### ADR-004: Containerization via Docker, portable across environments

**Decision:** The platform should run identically on dev laptops and cloud VMs via containerization, with no vendor-specific cloud services required.
**Rationale:** SMB target customers and academic reviewers need zero-friction, single-command deployment.
**Status: Implemented.** `backend/Dockerfile` builds correctly, and a root `docker-compose.yml` (SS-001) now provides the single-command startup the report describes — `docker compose up --build` runs `opensearch` and `backend` together, with the backend gated on OpenSearch's healthcheck. Verified end-to-end: both containers build, OpenSearch reports healthy before the backend starts, and all four implemented endpoints (`/`, `/health`, `/api/v1/ingest`, `/api/v1/alerts`) respond correctly through the compose-managed stack.

---

### ADR-005: Ingestion never blocks on downstream processing

**Decision:** The ingest endpoint validates and writes to OpenSearch synchronously, but defers all enrichment/correlation/scoring to later, asynchronous stages so a slow or failing external dependency can't stall ingestion.
**Rationale:** Keeps ingestion latency low and resilient to threat-intel API outages.
**Status: Implemented — real async deferral, as of SS-026.** `POST /api/v1/ingest` queues `app.tasks.enrichment.enrich_alert` (Celery, `tasks/celery_app.py`, SS-011) for every accepted log's `alert_id` after the OpenSearch write, then returns immediately — `.delay()` is a fast broker publish, not the enrichment work itself. The worker later fetches the document by ID (`db/opensearch.py::get_alert_by_id`), runs the actual threat-intel enrichment (SS-025, including any VirusTotal/AbuseIPDB latency or rate-limit waits), and updates the document in place (`update_alert_ti_fields`, update-by-id). Verified live: ingest response time was measured with enrichment queued behind it and stayed low regardless of how long the background enrichment took, and the OpenSearch document was confirmed updated only after the fact, not before the response was sent. This decision no longer holds "by omission" — the async infrastructure is real and load-bearing.

---

### ADR-006: Config defined ahead of implementation

**Decision (implicit, observed in code, not stated in the report):** `backend/app/core/config.py` defines settings for nearly every Phase 2 feature (Postgres, Redis, JWT, LLM providers, TI APIs, correlation, risk scoring, anomaly detection, reporting) before the corresponding code exists.
**Rationale (inferred):** Establishes the configuration surface/contract early so Phase 2 work can proceed against a stable settings object rather than renegotiating env var names per feature.
**Status: Implemented for config, and now fully consumed.** As of Milestone 14 (SS-001–067), every settings section `core/config.py` defines is read by the feature it configures — the scaffold-ahead-of-code gap this ADR originally described has closed. The one remaining exception is `SECRET_KEY` (line 31), which is genuinely unused anywhere in `backend/app` — worth removing or wiring up in a future cleanup pass (flagged in `docs/security-review.md` finding #10). New settings should still be added ahead of their consuming feature per this ADR's original pattern.

---

### ADR-007: CloudLens kept as a separate application pending integration

**Decision:** Rather than rewriting the existing CloudLens AWS IAM analyzer into the SafeSOC backend, it's retained as-is (Django + React, own Docker Compose) and will be integrated later by adapting its findings to the `NormalizedLog` schema and pushing them through the shared ingestion pipeline.
**Rationale:** CloudLens is already validated against a live AWS environment; a rewrite would risk regressing a working tool for architectural purity.
**Status: Implemented (SS-038–040).** `cloud/AWS-IAM-backend/engine/safesoc_bridge.py` pushes each scan's findings to `POST /api/v1/cloud/findings` (service-token authenticated) after a scan completes; `backend/app/adapters/cloudlens.py` converts them to `NormalizedLog` shape and routes them through the same ingestion pipeline as every other source. CloudLens itself remains a separate application (Django + React, own Docker Compose) — only its findings flow into SafeSOC, not the application itself.

---

### ADR-008: Multi-tenancy enforced at the query layer via `tenant_id`

**Decision:** Rather than separate databases/schemas per tenant, all tenants share one OpenSearch cluster/index set, with `tenant_id` as a mandatory filter on every read and write.
**Rationale:** Most cost-effective way to serve many small tenants on shared infrastructure (report §1.5).
**Status: Implemented.** The filtering mechanism is real (`search_alerts()` always requires and applies `tenant_id`), and as of SS-016, `tenant_id` is now derived from a verified JWT rather than caller-supplied — every endpoint except `GET /health` requires authentication, and a mismatched `tenant_id` anywhere in a request is rejected with `403` rather than trusted. Role-based access within a tenant (SS-017) and auth rate limiting (SS-067) are layered on top. See `docs/security-review.md` for what's still deliberately deferred (e.g. no admin-invite flow gating who can register against a given tenant).

---

### ADR-009: CloudLens's account-level risk score is not imported into SafeSOC's endpoint risk scoring (SS-041)

**Decision:** SafeSOC does not fetch, store, or reconcile CloudLens's own `Scan.risk_score` (a separate 0–100 AWS-account-posture score computed entirely inside CloudLens's own Django app). Instead, harmonization happens one level down: CloudLens *findings* already flow into SafeSOC as regular alerts (`source="cloudlens"`, SS-038/SS-039), each carrying a normal `severity`. `services/risk_scoring.py:calculate_risk_score()` treats these exactly like any other alert — same severity weights, same MITRE/TI/anomaly/after-hours bonuses, no CloudLens-specific branch — scored per "host" using `affected_resource` as the `host_id` (already how the SS-038 adapter maps it).
**Rationale:** SafeSOC currently has no channel to pull CloudLens's scan-level score at all — SS-039's sync is one-directional (findings only, not the scan's aggregate number), and adding one would mean re-opening SS-039's already-shipped, tested integration contract for a `Low` priority issue. The findings-level channel already exists and already carries severity, which is the raw material CloudLens's own score is computed from — so unifying at that layer, through the one scoring formula every other alert already uses, avoids maintaining two parallel risk models or inventing a synthetic conversion between CloudLens's *account*-level number and SafeSOC's *host*-level one. CloudLens's own 0–100 score remains visible in CloudLens's own dashboard; SafeSOC doesn't attempt to duplicate or reconcile that specific number.
**Status: Implemented.** No code change was required — `calculate_risk_score()` was already source-agnostic (it only reads `severity`/`mitre_technique`/`ti_result`/`anomaly_score`/`timestamp`, never `source`), so cloud-sourced alerts already contribute exactly as designed. `tests/test_risk_scoring.py` adds an explicit test proving this rather than leaving it as an unverified emergent property of the pipeline.
