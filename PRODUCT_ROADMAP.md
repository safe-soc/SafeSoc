# SafeSOC — Product Roadmap

**Audience:** contributors, reviewers, and (eventually) adopters.
**Status:** planning document — no code has been written against this roadmap yet.

This document reframes SafeSOC's 68-issue Phase 2 engineering backlog ([`docs/roadmap-issues.md`](docs/roadmap-issues.md)) as a **release plan**, and extends it with the issues a real open-source SOC platform needs but a college-project backlog doesn't naturally produce (plugin architecture, security policy, release automation, observability, and so on).

## How the three roadmap documents relate

| Document | Altitude | Use it for |
|---|---|---|
| [`docs/project-roadmap.md`](docs/project-roadmap.md) | Narrative, Phase-1-report-anchored | Historical context on what the report promised vs. what Phase 1 shipped. Superseded by this document for forward planning. |
| [`docs/roadmap-issues.md`](docs/roadmap-issues.md) | Engineering backlog | The source of truth for individual issue detail — title, description, acceptance criteria, files likely to change. This document references issues by ID (`SS-XXX`) rather than repeating that detail. |
| **`PRODUCT_ROADMAP.md`** (this file) | Product / release | Which issues ship together, why, in what order, and what's deliberately excluded from the version that actually gets submitted. |

---

## Vision

SafeSOC started as a final-year project brief: an AI-assisted, multi-tenant SOC platform for SMBs who can't afford Splunk and can't operate Wazuh unassisted. That brief doesn't change. What changes is the bar: this roadmap plans SafeSOC as software that should **still make sense to maintain, extend, and run six months after the defense** — which means treating v1.0.0 as a real 1.0, not just "whatever's done by the deadline," while being explicit about what's deliberately *not* in it.

Four things this roadmap optimizes for, in tension with each other by design:

1. **A successful, defensible final-year submission** (v1.0.0 has a hard deadline the rest of this list doesn't).
2. **Long-term maintainability** — the codebase should stay legible to a stranger, not just to the four people who wrote it.
3. **Open-source friendliness** — the parts of a repository that make people trust and adopt it (docs, security policy, contribution path) aren't afterthoughts, they're releases.
4. **A plausible path to commercialization** — nothing in v1.0 should have to be re-architected to eventually charge money for it (multi-tenancy, plugin boundaries, and API stability are treated as first-class from v0.2.0 onward, not bolted on later).

## Versioning Philosophy

Semantic versioning, applied loosely before 1.0 and strictly after:

- **v0.x.0** — pre-1.0. Breaking changes to internal APIs/schemas are expected and fine; each `v0.x.0` bump represents a release-worthy chunk of the Phase 2 backlog landing, not a promise of stability.
- **v1.0.0** — the first version where "stable" means something: the documented `/api/v1` surface, the `NormalizedLog` schema, and the multi-tenant data model are treated as load-bearing from here on. This is also the college submission target.
- **v1.1+** — backward-compatible additions and open-source polish. No breaking changes without a `v2.0` bump.
- **v2.0** — the version allowed to break things, for the research-grade bets that might genuinely require it (plugin marketplace, multi-cloud, SOAR-style automation).

## Feature Classification Legend

Every feature below carries one of four tags:

| Tag | Meaning |
|---|---|
| **MVP** | Required for v1.0.0. Without it, SafeSOC isn't a credible "AI-assisted SOC operations layer" — it's a log pipeline with some stubs. |
| **Product Enhancement** | Real value, but v1.0.0 is coherent without it. Ships in v1.0 only if time allows without displacing an MVP item. |
| **Research Feature** | Unproven ROI, high effort/uncertainty, or needs validated demand before committing engineering time. v2.0 territory. |
| **Nice to Have** | Low cost, non-essential polish. Fine to pick up opportunistically; never worth delaying an MVP item for. |

---

## Release Plan at a Glance

| Release | Focus | Issues | MVP items | Est. effort | Status |
|---|---|---|---|---|---|
| [v0.1.0](#v010--repository-foundation) | Repository Foundation | SS-001–006 | 3 of 6 | ~1.5–2 wks | Planned |
| [v0.2.0](#v020--authentication--multi-tenancy) | Auth & Multi-Tenancy | SS-007–017, SS-070 | 10 of 11 | ~4 wks | Planned |
| [v0.3.0](#v030--core-ingestion-platform) | Core Ingestion Platform | SS-018–021, SS-064 | 4 of 5 | ~2 wks | Planned |
| [v0.4.0](#v040--threat-intelligence) | Threat Intelligence | SS-022–026 | 5 of 5 | ~2 wks | Planned |
| [v0.5.0](#v050--cloud-security-integration) | Cloud Security Integration | SS-038–041 | 2 of 4 | ~1.5–2 wks | Planned |
| [v0.6.0](#v060--incident-management) | Incident Management | SS-027–037 | 10 of 11 | ~4–5 wks | Planned |
| [v0.7.0](#v070--dashboard--user-experience) | Dashboard & UX | SS-057–063 | 5 of 7 | ~4 wks | Planned |
| [v0.8.0](#v080--ai-investigation-assistant) | AI Investigation Assistant | SS-042–047 | 4 of 6 | ~3 wks | Planned |
| [v0.9.0](#v090--detection--analytics) | Detection & Analytics | SS-048–051 | 3 of 4 | ~2 wks | Planned |
| [v1.0.0](#v100--production-ready-college-submission) | Production Ready | SS-065–068, SS-071–072, SS-052–056 | 6 of 8 | ~2–3 wks + reporting | **Submission target** |
| [v1.1+](#v11--open-source-improvements) | Open Source Improvements | SS-069, SS-073–079 | 0 (by definition) | open-ended | Post-submission |
| [v2.0](#v20--advanced-ai-soc-platform) | Advanced AI SOC Platform | SS-080–082 | 0 (by definition) | unscheduled | Speculative |

**82 total issues** (68 from the original backlog + 14 new, listed in full under [Missing Issues](#missing-issues-for-a-professional-open-source-project) below).

---

## v0.1.0 — Repository Foundation

**Goal:** Make the repo trivially runnable and give it a real safety net before any Phase 2 feature work starts. Everything after this release assumes both exist.
**Prerequisites:** none — this is the starting point.
**Estimated effort:** ~1.5–2 weeks
**Expected deliverable:** `docker compose up` boots a working backend against real OpenSearch; a real (if small) pytest suite runs in CI on every push.

| Feature | Classification | Issues |
|---|---|---|
| One-command local deployment (root `docker-compose.yml`) | **MVP** | SS-001 |
| Automated backend test suite bootstrap | **MVP** | SS-002 |
| CI test execution | **MVP** | SS-003 |
| Exception-handling consolidation | Product Enhancement | SS-004 |
| Ingestion batch-size cap enforcement | Product Enhancement | SS-005 |
| OpenSearch Index Lifecycle Management (90-day retention) | Nice to Have | SS-006 |

*Why ILM is "Nice to Have" here:* a demo/submission dataset never gets old enough for 90-day retention to matter. It becomes an MVP concern the moment SafeSOC runs unattended for months — i.e., post-v1.0.

---

## v0.2.0 — Authentication & Multi-Tenancy

**Goal:** Close the single highest-severity gap between the report's design and the current code: `tenant_id` is presently caller-supplied and unauthenticated (see `docs/architecture.md` §4). This release makes tenant isolation real.
**Prerequisites:** v0.1.0
**Estimated effort:** ~4 weeks — the largest infrastructure release before feature build-out starts, because it stands up the entire storage/task-queue tier the rest of the product depends on.
**Expected deliverable:** Real login, real JWTs, real per-tenant data isolation, roles enforced. SafeSOC stops being a single-tenant toy.

| Feature | Classification | Issues |
|---|---|---|
| PostgreSQL integration (driver, async engine, Alembic) | **MVP** | SS-007, SS-008 |
| Core tenant/user data model | **MVP** | SS-009 |
| Redis integration | **MVP** | SS-010 |
| Celery task queue | **MVP** | SS-011 |
| Password hashing & registration | **MVP** | SS-012 |
| JWT issuance/validation | **MVP** | SS-013 |
| Auth endpoints (register/login/refresh) | **MVP** | SS-014 |
| Auth dependency injection | **MVP** | SS-015 |
| Enforced tenant isolation on ingest/alerts | **MVP** | SS-016 |
| RBAC (admin/analyst/viewer) | **MVP** | SS-017 |
| API versioning & stability policy | Product Enhancement | SS-070 *(new)* |

*Note:* PostgreSQL and Redis land here rather than as their own release because infrastructure with no consumer is unreviewable — auth is the first real consumer, and everything from v0.4.0 onward needs Postgres/Redis too, so this is the natural place to pay that cost once.

---

## v0.3.0 — Core Ingestion Platform

**Goal:** Ingest real security telemetry, not just synthetic logs — the moment SafeSOC's "normalize anything" promise becomes true instead of theoretical.
**Prerequisites:** v0.2.0 (adapters should write through the now-authenticated ingest path)
**Estimated effort:** ~2 weeks
**Expected deliverable:** SafeSOC ingests real Wazuh alerts and AWS CloudTrail activity end-to-end, plus a synthetic injector capable of realistic attack scenarios (needed to demo/test every release from here on).

| Feature | Classification | Issues |
|---|---|---|
| Wazuh adapter | **MVP** | SS-018 |
| AWS CloudTrail adapter | **MVP** | SS-019 |
| AWS GuardDuty adapter | Product Enhancement | SS-020 |
| Adapter dispatch/registry | **MVP** | SS-021 |
| Multi-scenario synthetic injector | **MVP** | SS-064 |

*Why GuardDuty is not MVP:* CloudTrail alone already proves the "real cloud source" story; GuardDuty is additive breadth, not a different capability.

---

## v0.4.0 — Threat Intelligence

**Goal:** Auto-enrich alerts so an analyst never manually looks up an IP or file hash — one of the report's headline claims, currently 100% unimplemented.
**Prerequisites:** v0.2.0 (Postgres for the cache table), v0.3.0 (real data worth enriching)
**Estimated effort:** ~2 weeks
**Expected deliverable:** Every alert carrying a network indicator is automatically enriched, cache-first, rate-limited, and non-blocking.

| Feature | Classification | Issues |
|---|---|---|
| VirusTotal client | **MVP** | SS-022 |
| AbuseIPDB client | **MVP** | SS-023 |
| Threat-intel cache table | **MVP** | SS-024 |
| Enrichment service | **MVP** | SS-025 |
| Async enrichment wiring (non-blocking ingestion) | **MVP** | SS-026 |

---

## v0.5.0 — Cloud Security Integration

**Goal:** Merge CloudLens's already-working AWS IAM findings into SafeSOC's unified alert queue — one of the two "existing implementations" this project inherited becomes part of the single platform story instead of a second, disconnected app.
**Prerequisites:** v0.2.0 (auth for the bridge call), v0.3.0 (adapter pattern already established)
**Estimated effort:** ~1.5–2 weeks
**Expected deliverable:** A completed CloudLens scan's findings appear in the same alert queue as endpoint/cloud-log events.

| Feature | Classification | Issues |
|---|---|---|
| CloudLens `Finding` → `NormalizedLog` adapter | **MVP** | SS-038 |
| CloudLens → SafeSOC sync bridge | **MVP** | SS-039 |
| Cloud-specific query surface (`routers/v1/cloud.py`) | Nice to Have | SS-040 |
| Risk-score harmonization (CloudLens ↔ SafeSOC) | Product Enhancement | SS-041 |

*Why SS-040 is Nice to Have:* the existing `GET /api/v1/alerts?source=aws_cloudtrail` filter likely already covers this — building a dedicated router risks being redundant work; confirm the gap actually exists before spending effort here.

---

## v0.6.0 — Incident Management

**Goal:** The actual reason SafeSOC exists — turn a stream of enriched alerts into prioritized, explainable, trackable incidents automatically. This is the platform's core differentiator, not a supporting feature.
**Prerequisites:** v0.2.0, v0.4.0 (enrichment output feeds risk scoring)
**Estimated effort:** ~4–5 weeks — the single largest release in the plan. **Recommend treating this as two internal sprints** (correlation engine, then incidents/risk-scoring on top of it) even though it's one product release.
**Expected deliverable:** A detected multi-step attack becomes a scored, auto-created, trackable incident — live, for the first time.

| Feature | Classification | Issues |
|---|---|---|
| Redis sliding-window primitives | **MVP** | SS-027 |
| Attack chain correlation (6 patterns) | **MVP** | SS-028 |
| MITRE ATT&CK technique/tactic mapping | **MVP** | SS-029 |
| Real-time correlation worker | **MVP** | SS-030 |
| Auto-incident creation from detected chains | **MVP** | SS-031 |
| Endpoint risk scoring | **MVP** | SS-032 |
| Scheduled risk recalculation (time decay) | Product Enhancement | SS-033 |
| Endpoints listing API | **MVP** | SS-034 |
| Incident data model | **MVP** | SS-035 |
| Incident CRUD & lifecycle endpoints | **MVP** | SS-036 |
| Alert linking & investigation notes | **MVP** | SS-037 |

---

## v0.7.0 — Dashboard & User Experience

**Goal:** Give humans a way to use everything built so far without curl or Swagger UI.
**Prerequisites:** v0.2.0 through v0.6.0 (the frontend has nothing to render without them)
**Estimated effort:** ~4 weeks
**Expected deliverable:** A working web UI — SafeSOC stops being API-only.

| Feature | Classification | Issues |
|---|---|---|
| Frontend framework scaffold | **MVP** | SS-057 |
| Auth/login UI | **MVP** | SS-058 |
| Alert queue view | **MVP** | SS-059 |
| Endpoint risk view | **MVP** | SS-060 |
| Incident management UI | **MVP** | SS-061 |
| Investigation chat UI | Product Enhancement | SS-062 |
| Real-time WebSocket updates | Nice to Have | SS-063 |

*Why chat UI isn't MVP here:* it depends on v0.8.0's backend shipping first; the UI can be built once that lands and doesn't block v0.7.0's own release value (alert/incident views are independently useful).

---

## v0.8.0 — AI Investigation Assistant

**Goal:** The natural-language analyst experience that differentiates SafeSOC from "just another dashboard."
**Prerequisites:** v0.6.0 (needs real incident/risk data to query); the chat UI (SS-062) needs v0.7.0
**Estimated effort:** ~3 weeks
**Expected deliverable:** An analyst can ask "show me failed logins from the last 6 hours" in plain English and get a real, data-backed answer.

| Feature | Classification | Issues |
|---|---|---|
| Ollama (local LLM) client | **MVP** | SS-042 |
| Groq (cloud LLM) fallback client | Nice to Have | SS-043 |
| Intent classification (8 intents) | **MVP** | SS-044 |
| MCP tool definitions | **MVP** | SS-045 |
| Multi-turn conversation context | Product Enhancement | SS-046 |
| Investigation endpoint | **MVP** | SS-047 |

*Scope-flex note:* if this release is under time pressure, ship with a reduced intent set (e.g. 4 of 8) rather than cutting the feature entirely — a smaller, reliable assistant demos better than a broad, flaky one.

---

## v0.9.0 — Detection & Analytics

**Goal:** Add the statistical/ML detection layer on top of the rule-based correlation shipped in v0.6.0 — closes the SRS's "hybrid detection" design goal.
**Prerequisites:** v0.6.0 (extends, doesn't replace, rule-based correlation), v0.3.0 (needs a realistic data stream to train/score against)
**Estimated effort:** ~2 weeks
**Expected deliverable:** Alerts get a genuine Isolation Forest anomaly score, not just rule matches.

| Feature | Classification | Issues |
|---|---|---|
| Synthetic normal-behavior training data generator | **MVP** | SS-048 |
| Isolation Forest training pipeline | **MVP** | SS-049 |
| Anomaly scoring service | **MVP** | SS-050 |
| Z-score network volume spike detection | Product Enhancement | SS-051 |

---

## v1.0.0 — Production Ready (College Submission)

**Goal:** Everything above, hardened, documented, and demoable in one command — the version that actually gets submitted and defended.
**Prerequisites:** the MVP items from v0.1.0 through v0.9.0 (see [What Not to Build Before v1.0](#what-not-to-build-before-v10) for the explicit exclusion list)
**Estimated effort:** ~2–3 weeks of hardening, **plus a scope decision on automated reporting** (see below)
**Expected deliverable:** A tagged `v1.0.0` that a reviewer can clone, run with one command, see a populated demo tenant with active attack chains, and inspect working documentation for.

| Feature | Classification | Issues |
|---|---|---|
| Demo mode (pre-loaded historical data + live attack chains) | **MVP** | SS-065 |
| Performance verification against SRS targets | **MVP** | SS-066 |
| Security review pass (OWASP Top 10) | **MVP** | SS-067 |
| Full `docs/` accuracy sync | **MVP** | SS-068 |
| System-wide audit log | **MVP** | SS-071 *(new)* |
| One-command installer/quickstart | **MVP** | SS-072 *(new)* |
| Automated PDF reporting | Product Enhancement — **timeline risk, see below** | SS-052, SS-053, SS-054 |
| Notifications (Telegram) | Nice to Have | SS-055, SS-056 |

**Reporting scope-risk callout:** SS-052 (PDF generation) is the one v1.0 candidate feature that aggregates *everything else* (risk, incidents, TI, cloud posture) and is therefore the easiest place to lose a week right before a deadline. If v1.0.0 is behind schedule when this release is reached, **descope to a simpler HTML or JSON summary** rather than cutting reporting entirely, and defer the polished WeasyPrint PDF to v1.1.

---

## v1.1+ — Open Source Improvements

**Goal:** Make SafeSOC legible and adoptable by people who aren't the four people who built it.
**Prerequisites:** v1.0.0
**Estimated effort:** open-ended — prioritize by actual adopter/contributor friction, not this list's order
**Expected deliverable:** A repository a stranger could clone, understand, deploy, and contribute to without opening a DM to the team.

| Feature | Classification | Issues |
|---|---|---|
| Plugin/adapter SDK (formalized, documented, third-party-implementable) | Product Enhancement | SS-069 *(new)* |
| Documentation website (generated from `docs/`) | Product Enhancement | SS-073 *(new)* |
| Contribution guide + community templates | Product Enhancement | SS-074 *(new)* |
| Security policy (vulnerability disclosure) | Product Enhancement | SS-075 *(new)* |
| Release automation (semver, changelog, versioned images) | Product Enhancement | SS-076 *(new)* |
| Observability for the platform itself (metrics, tracing) | Product Enhancement | SS-077 *(new)* |
| Published, reproducible performance benchmark suite | Product Enhancement | SS-078 *(new)* |
| Kubernetes/Helm deployment path | Product Enhancement | SS-079 *(new)* |

*Note on SS-069 vs. v0.3.0's adapters:* v0.3.0 ships Wazuh/CloudTrail/GuardDuty as internal, hardcoded adapter modules — that's sufficient for v1.0. SS-069 is the later step of turning that internal pattern into a documented, versioned interface a third party could implement without forking the repo — genuinely a different (larger) piece of work, not a duplicate.

---

## v2.0 — Advanced AI SOC Platform

**Goal:** Speculative, high-effort, high-uncertainty bets. Pursue only with validated demand from real v1.x usage — building these before v1.0 has any users would be planning in a vacuum.
**Prerequisites:** v1.1+, plus actual user/community feedback
**Estimated effort:** unscheduled
**Expected deliverable:** Not a deliverable — a set of bets to revisit once there's evidence worth acting on.

| Feature | Classification | Issues |
|---|---|---|
| Multi-cloud adapter framework (Azure Sentinel, GCP) | Research Feature | SS-080 *(new)* |
| SOAR-style automated response playbooks | Research Feature | SS-081 *(new)* |
| Community plugin / detection-rule marketplace | Research Feature | SS-082 *(new)* |

**Parking lot (ideas, not yet issues — don't spec these until v1.x usage justifies it):** AI-driven autonomous remediation suggestions, graph-based attack-path prediction (extending CloudLens's existing NetworkX work to endpoint/network data), automated compliance reporting (SOC 2 / ISO 27001), a SaaS billing/control-plane layer for commercial multi-tenant hosting.

---

## What Not to Build Before v1.0

Explicitly deferred, with rationale — these would consume schedule without moving the v1.0 story forward:

| Item | Why it can wait |
|---|---|
| **Everything in v1.1+ and v2.0**, by construction | Open-source polish and speculative research features don't help a defense demo; they help adoption *after* there's something to adopt. |
| Groq LLM fallback client (SS-043) | Ollama alone proves the NL assistant works. A second provider is redundancy, not capability. |
| Real-time WebSocket dashboard updates (SS-063) | Polling is an entirely acceptable substitute for a demo audience; the real-time channel is an experience upgrade, not a new capability. |
| OpenSearch ILM / 90-day retention (SS-006) | A submission dataset never lives long enough for this to matter. |
| Scheduled risk-score recalculation (SS-033) | On-demand computation at query/ingest time is sufficient for a demo; the scheduled job is a production-scale optimization. |
| Multi-turn conversation context in the NL assistant (SS-046) | Single-turn Q&A is a defensible, honest cut — better than a flaky multi-turn implementation. |
| Cloud-specific query router (SS-040) | Likely redundant with the existing `source` filter on `/api/v1/alerts` — verify before building. |
| SafeSOC-native Telegram notifications (SS-055, SS-056) | CloudLens already demonstrates this exact pattern once; duplicating it in SafeSOC before v1.0 is low marginal value. |
| GuardDuty adapter (SS-020) | CloudTrail alone already proves "real AWS source" works; GuardDuty is breadth, not a new capability. |
| Full WeasyPrint PDF report polish (SS-052–054, if behind schedule) | See the explicit scope-risk callout under v1.0.0 — a plain HTML/JSON summary is an acceptable fallback. |

---

## Missing Issues for a Professional Open-Source Project

The original 68-issue backlog was derived from the Phase 1 SRS and the code — it's thorough on *features* but, reasonably, silent on the things that make a repository trustworthy to outside contributors and operators. These 14 new issues close that gap. IDs continue the existing `SS-XXX` sequence.

| ID | Title | Addresses | Release | Classification |
|---|---|---|---|---|
| SS-069 | Plugin/Adapter SDK & formal architecture | *Plugin architecture* | v1.1+ | Product Enhancement |
| SS-070 | Public REST API stabilization & versioning policy | *Public REST API, API versioning* | v0.2.0 | Product Enhancement |
| SS-071 | System-wide audit log (auth events, data access, config changes) | *Audit logs* | v1.0.0 | MVP |
| SS-072 | One-command installer / quickstart script | *Installer* | v1.0.0 | MVP |
| SS-073 | Documentation website (MkDocs/Docusaurus + GitHub Pages, generated from `docs/`) | *Documentation website* | v1.1+ | Product Enhancement |
| SS-074 | `CONTRIBUTING.md` + issue/PR templates + `CODE_OF_CONDUCT.md` | *Contribution guide* | v1.1+ | Product Enhancement |
| SS-075 | `SECURITY.md` — vulnerability disclosure policy | *Security policy* | v1.1+ | Product Enhancement |
| SS-076 | Release automation (semver tagging, changelog generation, GitHub Releases, versioned Docker images) | *Release workflow* | v1.1+ | Product Enhancement |
| SS-077 | Platform observability (Prometheus metrics, structured tracing, error/uptime dashboards for SafeSOC itself) | *Observability* | v1.1+ | Product Enhancement |
| SS-078 | Published, reproducible performance benchmark suite | *Performance benchmarks* | v1.1+ | Product Enhancement |
| SS-079 | Kubernetes/Helm deployment path | (extends *Installer*) | v1.1+ | Product Enhancement |
| SS-080 | Multi-cloud adapter framework (Azure Sentinel, GCP) | — | v2.0 | Research Feature |
| SS-081 | SOAR-style automated response playbooks | — | v2.0 | Research Feature |
| SS-082 | Community plugin / detection-rule marketplace | — | v2.0 | Research Feature |

**Already covered by the existing backlog** (listed here so the mapping from the requirements-prompt's example list is explicit, not because anything new is needed):

- **RBAC** → SS-017 (v0.2.0)
- **Performance benchmarks** (internal verification, as opposed to SS-078's public/reproducible version) → SS-066 (v1.0.0)

---

## Effort Summary

| Release | Issues (existing + new) | Est. effort |
|---|---|---|
| v0.1.0 | 6 | ~1.5–2 wks |
| v0.2.0 | 11 + 1 new | ~4 wks |
| v0.3.0 | 4 + 1 (SS-064) | ~2 wks |
| v0.4.0 | 5 | ~2 wks |
| v0.5.0 | 4 | ~1.5–2 wks |
| v0.6.0 | 11 | ~4–5 wks |
| v0.7.0 | 7 | ~4 wks |
| v0.8.0 | 6 | ~3 wks |
| v0.9.0 | 4 | ~2 wks |
| v1.0.0 | 4 + 2 new + 5 (reporting/notify) | ~2–3 wks + reporting risk |
| v1.1+ | 8 new | open-ended |
| v2.0 | 3 new | unscheduled |
| **Total to v1.0.0** | **62 issues** | **~26–29 weeks** (~6–7 months at this pace for a 4-person part-time team) |

The gap between "~26–29 weeks to v1.0.0" and a single academic term is real — this roadmap is written as the honest long-term plan, not a deadline-fitted one. If the college submission deadline is tighter than that, the right response is to **cut scope by release** (the exclusion list above already identifies the lowest-cost cuts), not to compress every release proportionally, which tends to produce a v1.0 where nothing works well instead of one where fewer things work completely.
