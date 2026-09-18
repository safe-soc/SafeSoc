# SafeSOC — Compliance Center

Scope: an evidence-mapping view (`/compliance`, `GET /api/v1/compliance/requirements[/{id}]`) connecting SafeSOC's existing security telemetry to applicable Indian cybersecurity/data-protection requirements. This document explains what it covers, how each requirement's status is computed, and — most importantly — what it deliberately does **not** claim.

## The one rule everything else follows

**SafeSOC evidence is not a legal-compliance determination.** The presence of logs, alerts, or incidents in SafeSOC tells you SafeSOC observed *something* — it never tells you an organization has satisfied a legal obligation, because most obligations (notification actually sent, contracts actually signed, backups actually configured, jurisdiction of physical storage) have no technical telemetry signature at all, or have one only SafeSOC can't see. Every requirement's assessment is written to make that distinction explicit rather than implied.

Concretely, this means:
- Only four status phrasings ever reach a user: **Evidence available**, **Control appears supported**, **Evidence gap**, **Not assessable from SafeSOC telemetry**. "Compliant" / "non-compliant" / "legally compliant" never appear anywhere in the UI or API.
- Every requirement detail page shows five things side by side and never blends them: the **regulatory requirement** (what the law says), **what SafeSOC can observe**, the **evidence currently available**, **what SafeSOC cannot verify**, and a **recommended organizational action**.
- Where no SafeSOC evidence exists for a requirement (e.g. encryption configuration, physical storage jurisdiction), the requirement says so — it is never inferred from unrelated logs.

## Frameworks covered

### Digital Personal Data Protection Act, 2023 (+ DPDP Rules, 2025)

Primary source: [MeitY's official Act text](https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf), cross-referenced against [Section 8 on Indian Kanoon](https://indiankanoon.org/doc/186118625/). The Rules (which give Section 8(5)'s "reasonable security safeguards" concrete technical content) are sourced from [dpdpa.com's Rule 6 text](https://www.dpdpa.com/dpdparules/rule6.html) — a secondary aggregator, not MeitY's own Rules PDF directly; treat clause wording as indicative, not a verbatim quote, until cross-checked against the Gazette notification.

Five requirements: access control (DPDP-R1), logging/monitoring (DPDP-R2), encryption/tokenisation/backups (DPDP-R3), Data Processor contractual safeguards (DPDP-R4), and breach notification (DPDP-R5).

### CERT-In Directions dated 28.04.2022

Issued under Section 70B(6) of the IT Act, 2000. Primary source: [CERT-In's own PDF](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf). **Sourcing caveat**: this PDF's text could not be reliably extracted for direct quotation during implementation (compressed content stream). The specific figures used here — 6-hour incident reporting, 180-day log retention within Indian jurisdiction, NTP synchronization to NIC/NPL servers, a designated CERT-In point of contact — are corroborated by multiple independent secondary summaries ([Internet Society](https://www.internetsociety.org/resources/doc/2022/internet-impact-brief-india-cert-in-cybersecurity-directions-2022/), [Lexology](https://www.lexology.com/library/detail.aspx?g=899f3b94-c31f-4983-868f-5ee5abbf78c8), [Medianama](https://www.medianama.com/2022/05/223-cybersecurity-directive-time-sync/)) that all cite the same Direction, but none of them is the primary legal text itself. Treat exact paragraph numbers as approximate until verified against the primary PDF directly.

Four requirements: 6-hour incident reporting (CERTIN-R1), 180-day log retention (CERTIN-R2), clock synchronization (CERTIN-R3), and designated point of contact (CERTIN-R4).

### DPIIT / Other Applicable Requirements

Research finding, not an assumption: DPIIT (Department for Promotion of Industry and Internal Trade, Ministry of Commerce and Industry) is India's industrial-policy and startup-recognition body — [its own mandate document](https://www.dpiit.gov.in/static/uploads/2025/06/65688c315685d1869f6cf98c12e6c468.pdf) covers investment promotion, Make in India, Startup India recognition, logistics policy, and IP rights. It does **not** issue cybersecurity technical directions; that domain belongs to MeitY/CERT-In and the DPDP Act's own rules, both already covered above.

Rather than silently omitting DPIIT or inventing a control to fill the "third framework card" the UI spec asked for, DPIIT-R1 exists as a single explanatory (non-technical) entry stating this explicitly: *"No directly applicable DPIIT cybersecurity technical control was identified for this assessment. DPIIT is not being treated as a cybersecurity control framework."* Its status is `NOT_ASSESSABLE` by design, not because evidence happened to be missing.

## Architecture: static mapping + live assessment, zero migrations

`ComplianceFramework`/`ComplianceRequirement` (the legal text — title, reference, source, requirement summary, what SafeSOC can/cannot observe) live as a **static Python module**, `backend/app/core/compliance_mapping.py`, following the same pattern as `core/mitre_mapping.py`. This is deliberate: the law doesn't change per tenant, and a migration is the wrong tool for updating legal text — editing a Python list is.

**There is no `ComplianceAssessment` or `ComplianceEvidence` database table, and no migration was added for this feature.** Every requirement's status, evidence count, and related-incident list is computed fresh on every request by `backend/app/services/compliance.py`, reading directly from data that already exists:

| Requirement | Live evidence source |
|---|---|
| DPDP-R1 (access control) | `User.role` counts, tenant-scoped |
| DPDP-R2 (logging/monitoring) | `services/audit.py` (audit trail), `services/incidents.py` (incidents), `db/opensearch.py` (alerts), and a new tenant-wide rollup over the Investigation Session models (SS-098) — confirmed findings, completed actions |
| DPDP-R5 / CERTIN-R1 (notification / reporting timeliness) | `services/incidents.py` incident count + lifecycle |
| CERTIN-R2 (log retention) | Live read of `settings.OPENSEARCH_ILM_RETENTION_DAYS`, compared against the 180-day requirement |
| DPDP-R3, DPDP-R4, CERTIN-R3, CERTIN-R4, DPIIT-R1 | None — explicitly `NOT_ASSESSABLE`, no query at all |

This mirrors the "live evidence, never a stored snapshot" principle already established for Investigation Sessions: nothing here can drift from what SafeSOC's other pages show, because it's the same underlying queries.

## Status semantics

Internal enum (`core/enums.py::ComplianceStatus`) → user-facing phrasing:

| Internal | User-facing | Meaning |
|---|---|---|
| `EVIDENCE_AVAILABLE` | "Evidence available" | SafeSOC found meaningful evidence consistent with the control |
| `PARTIALLY_SUPPORTED` | "Control appears supported" | SafeSOC evidences part of the requirement (e.g. detection) but a structurally-unobservable part remains (e.g. the actual filing/notification) |
| `GAP` | "Evidence gap" | SafeSOC could look, and found nothing (or a config value below a stated legal threshold) |
| `NOT_ASSESSABLE` | "Not assessable from SafeSOC telemetry" | This requirement has no SafeSOC-observable technical signature at all |

`GAP` is never rendered as "non-compliant" — a zero-evidence tenant (e.g. freshly onboarded, nothing detected yet) is exactly what `GAP` describes; it says nothing about whether the organization's actual security posture is adequate.

## Worked example: CERTIN-R2

This is the one requirement with a genuinely precise, config-driven check, worth calling out: it reads the real `OPENSEARCH_ILM_RETENTION_DAYS` setting (default `90`, `db/mappings/ilm_policy.py`) and compares it against CERT-In's 180-day minimum. A configured value below 180 is `GAP`, with the exact configured/required numbers surfaced. A value at or above 180 is `PARTIALLY_SUPPORTED`, **not** `EVIDENCE_AVAILABLE` — because retention *duration* being long enough says nothing about whether the underlying OpenSearch storage is physically/legally within Indian jurisdiction, which the Direction also requires and which SafeSOC has no way to check.

## Integration with the investigation system

A requirement's evidence links directly into the existing investigation architecture — Compliance Requirement → related Incident → the incident's persistent Investigation Session (confirmed findings, actions) — reusing `IncidentDetail.tsx`'s existing routes and the Arc 5 Investigation Session panel exactly as they are. No new incident/investigation view was built; the Compliance detail page only links out to the real one. Its anti-fabrication guarantees (a finding is `confirmed` only via an explicit analyst action, never automatically) are untouched.

## What was intentionally not implemented

- **No `ComplianceAssessment`/evidence persistence** — by design (see Architecture above).
- **No AI on the Compliance page** — no chatbot, no AI-generated legal conclusions. If AI summarization is added later, it may only restate existing evidence/findings/hypotheses/recommendations, each clearly labeled, never issue a legal conclusion.
- **No "Generate Compliance Evidence Report"** — the existing PDF report generator (`services/investigation_report.py`, Arc 1) was not modified or extended. The data model here is additive-compatible with a future report that reuses that infrastructure, but building it was out of scope for this pass.
- **No write endpoints** — the Compliance Center is entirely read-only. There is no way for a client to set or override a requirement's status; every value is recomputed server-side from tenant-scoped data on every request.

## Future framework expansion

Adding a new framework or requirement means adding entries to `COMPLIANCE_REQUIREMENTS` in `core/compliance_mapping.py` and, if it needs evidence no existing assessor covers, one new function in `services/compliance.py` dispatched by `evidence_type` — no migration, no schema change. The same "identify an authoritative source before writing a requirement; state explicitly when no applicable control exists" discipline used for DPDP/CERT-In/DPIIT here should apply to any future addition (e.g. RBI cybersecurity frameworks for regulated entities, sector-specific CERT-In sub-directions) — never invent a requirement's text or a fabricated evidence mapping to fill a gap.
