# SafeSOC — Autonomous SOC Benchmark

Generated 2026-09-07T17:10:53.373095+00:00 from a live run against `http://localhost:8000`.

This report contains measurements, not claims. Every figure was produced by injecting
telemetry into the running platform and reading back what the pipeline actually did.
Nothing here was hand-written into a database. Where something was not measured, it
says so.

**Reproduce it:** `python -m benchmarks` from the repository root, against a running stack.

---

## 1. System under test

Telemetry travels one path, and the benchmark exercises all of it:

```
injector telemetry -> POST /api/v1/ingest -> normalization -> OpenSearch
   -> Celery correlation worker -> sliding window (Redis) -> pattern detectors
   -> incident create/merge (Postgres, advisory-locked)
   -> SOAR trigger evaluation -> playbook match -> action parameter resolution
   -> autonomy classification -> Celery SOAR worker -> simulated adapter
   -> verification -> audit log -> incident timeline
```

Investigation runs alongside it: incident evidence is re-derived live per question,
formatted into a grounded prompt, answered by the configured LLM, and persisted as an
investigation turn. Confirmed findings count as established fact; hypotheses explicitly
do not.

- **Isolation model:** SOAR and investigation tables carry no `tenant_id`. Every query
  reaches them through an already tenant-verified incident, so an id from another tenant
  is indistinguishable from one that does not exist (404).
- **Benchmark tenants:** `00000000-0be0-0000-0000-00000000000a` and `00000000-0be0-0000-0000-00000000000b` —
  dedicated, never the demo tenant. No benchmark result is persisted as an application model.

## 2. Test environment

| Component | Role in this run |
|---|---|
| FastAPI backend (Docker) | API under test |
| PostgreSQL | incidents, SOAR runs/actions, investigation state, audit log |
| OpenSearch | normalized alert storage; evidence retrieval |
| Redis | correlation sliding windows; Celery broker |
| Celery worker | correlation evaluation and SOAR action execution |
| Ollama (local LLM) | investigation answers; deterministic fallback when unavailable |
| Simulated SOAR adapters | EDR / identity / firewall — no external system is contacted |

## 3. Scenario matrix

| Scenario | Detection | Incident | SOAR runs | Automatic | Awaiting approval | Skipped | Result |
|---|---|---|---|---|---|---|---|
| A. Credential Brute Force | credential_brute_force (0.60) | yes | 1 | 2/2 executed | 0/0 | 0 | **PASS** |
| B. Successful Compromise | successful_compromise (0.64) | yes | 2 | 4/4 executed | 2/2 | 0 | **PASS** |
| C. Privilege Escalation | privilege_escalation (0.95) | yes | 1 | 2/2 executed | 1/1 | 0 | **PASS** |
| D. Lateral Movement | lateral_movement (0.70) | yes | 1 | 2/2 executed | 1/1 | 0 | **PASS** |
| E. Data Exfiltration | data_exfiltration (0.64) | yes | 1 | 2/2 executed | 1/1 | 0 | **PASS** |
| F. Incomplete Evidence (Phase 3.5 regression) | successful_compromise (0.64) | yes | 2 | 2/2 executed | 2/2 | 2 | **PASS** |
| G. Benign Activity (restraint) | none | no | 0 | 0/0 executed | 0/0 | 0 | **PASS** |
| H. Tenant Isolation | successful_compromise (0.64) | yes | 2 | 4/4 executed | 2/2 | 0 | **PASS** |

**8/8 scenarios passed.**

### Failures and errors

_No scenario check failed._

## 4. Performance

Sample size is 7 scenario run(s). That is far too small for statistical claims — these are single-run observations on one developer machine, reported to show order of magnitude and to catch regressions, not as performance characteristics.

Two clocks are reported separately, because mixing them would manufacture precision:

- **Observed** — measured on the benchmark host from the moment `POST /ingest` returned
  until the artifact was first visible over the API. Includes poll granularity
  (~1.5s), so it is an upper bound.
- **Server-side** — differences between timestamps the backend itself wrote. One clock,
  so these are the trustworthy durations.

| Metric | Median | Clock |
|---|---|---|
| Time to incident (observed) | 1.58s | host |
| Time to fully settled (observed) | 3.23s | host |
| Incident -> SOAR run created | 0.22s | server |
| Incident -> last automatic action executed | 1.30s | server |
| Incident -> last verification completed | 2.32s | server |

Sample size: 7.

## 5. SOAR autonomy scorecard

Definitions are explicit, and a rate with an empty denominator is reported **N/A**
rather than silently rendered as 0% or 100%.

| Metric | Value | Definition |
|---|---|---|
| Playbooks triggered | 10 | runs created across all scenarios |
| Actions created | 27 | action records instantiated |
| Automatic actions | 18 | classified AUTOMATIC by policy |
| Approval-required actions | 9 | classified APPROVAL_REQUIRED |
| Awaiting approval | 9 | parked, never executed |
| Succeeded / Failed | 17 / 1 | terminal execution outcomes |
| Skipped | 2 | never instantiated (evidence unavailable / invalid parameters) |
| **automatic_execution_rate** | **100%** | automatic actions that reached a terminal execution state / all automatic actions |
| **approval_gate_enforcement_rate** | **100%** | approval-required actions that never executed without approval / all approval-required actions |
| **skipped_action_rate** | **7%** | skipped / (created + skipped) |
| **verification_success_rate** | **100%** | verified / actions reaching SUCCEEDED |

Skipped actions by reason: {'required_evidence_unavailable': 2}

## 6. AI investigation results

0/0 probes passed.

**These are screens, not proofs.** A keyword check cannot demonstrate the absence of
hallucination. Probes are recorded INCONCLUSIVE — not passed — when the LLM was
unavailable and the platform served its deterministic fallback, because a templated
sentence says nothing about grounding.

_AI probes not run._

### What the model actually said

_No answers captured._

**Read the hypothesis-boundary result with care.** A model that ignores the
findings sections of the prompt entirely would pass the hypothesis probe for the wrong
reason — by never mentioning any finding. Where the confirmed-findings probe also fails,
that is the more likely explanation, and the boundary result should be treated as
unproven rather than as evidence the model reasons about the confirmed/unconfirmed
distinction. The platform's part (supplying findings under labelled headings, and never
letting AI output create a confirmed finding) is structural and holds regardless.

## 7. Human-approval security

10/10 probes passed.

| Category | Check | Verdict | Detail |
|---|---|---|---|
| Approval bypass | no HTTP execute route exists | **PASS** | execution is reachable only through the Celery worker |
| Approval bypass | direct execute call is not routed | **PASS** | HTTP 404 |
| Authorization | viewer cannot approve | **PASS** | HTTP 403 |
| Tenant isolation | cross-tenant approval is refused | **PASS** | HTTP 404 (404 keeps existence indistinguishable) |
| Relationship scoping | action under the wrong incident is refused | **PASS** | HTTP 404 |
| Relationship scoping | action under the wrong run is refused | **PASS** | HTTP 404 |
| Relationship scoping | unknown action id is refused | **PASS** | HTTP 404 |
| Idempotency | duplicate approval does not re-decide | **PASS** | approved_at unchanged on the second call |
| State machine | approve after reject is refused | **PASS** | reject HTTP 200, then approve HTTP 409 |
| State machine | rejected action never executes | **PASS** | status=rejected executed_at=None result=null |

## 8. Tenant isolation

| Category | Check | Verdict | Detail |
|---|---|---|---|
| Tenant isolation | incident sets are disjoint | **PASS** | A=182 B=5 shared=0 |
| Tenant isolation | tenant A cannot read tenant B's incident | **PASS** | HTTP 404 |
| Tenant isolation | tenant A cannot read tenant B's evidence | **PASS** | HTTP 404 |
| Tenant isolation | tenant A cannot read tenant B's timeline | **PASS** | HTTP 404 |
| Tenant isolation | tenant A's SOAR runs reference only tenant A incidents | **PASS** | 89 runs, 0 pointing at tenant B |
| Tenant isolation | identical attacks produced separate incidents | **PASS** | A=7e2886ce B=1d583cdb |

## 9. Concurrency and idempotency

Looking specifically for the failure modes this architecture can actually produce:
duplicate playbook runs for one incident (advisory-lock failure), runs with more actions
than their playbook has steps (double instantiation), and actions still mid-flight after
the pipeline settled (a lost state transition — the signature of the shared-engine race
found in Phase 2).

| Simultaneous scenarios | Incidents | SOAR runs | Duplicate runs | Over-instantiated | Stuck actions | Wall time | Result |
|---|---|---|---|---|---|---|---|
| 10 | 7 | 7 | 0 | 0 | 14 | 61.6s | **FAIL** |

- At 10 scenarios — actions still mid-flight after settling: ['14586460-8bbc-4107-abe6-b4c8762834e4/enrich_indicator=pending', '14586460-8bbc-4107-abe6-b4c8762834e4/create_investigation_action=pending', 'e61087c8-e3ff-41a3-b97d-33e5eb1db09f/enrich_indicator=pending', 'e61087c8-e3ff-41a3-b97d-33e5eb1db09f/create_investigation_action=pending', '5ed2b927-e0da-44f6-b178-4d7761eb52a3/enrich_indicator=pending', '5ed2b927-e0da-44f6-b178-4d7761eb52a3/create_investigation_action=pending', 'd11ec729-50d4-4be6-9c5a-4d83a64a413f/enrich_indicator=pending', 'd11ec729-50d4-4be6-9c5a-4d83a64a413f/create_investigation_action=pending', '6108b95a-d291-4f56-a641-0b12abd44f35/enrich_indicator=pending', '6108b95a-d291-4f56-a641-0b12abd44f35/create_investigation_action=pending']

## 10. Resource management

Whether the pipeline returns its database connections after a burst of work. A count
that climbs and stays up means transactions are being abandoned, which ends in
`sorry, too many clients already` and a stalled platform.

| Category | Check | Verdict | Detail |
|---|---|---|---|
| Resource management | no Postgres connections leaked | **PASS** | idle-in-transaction 0 -> 0 after 4 SOAR-triggering scenarios (delta +0; total connections 2) |

## 11. Reliability

Celery task outcomes read from the worker's own log over the run window:

| Task | Succeeded | Failed |
|---|---|---|
| `evaluate_correlation` | 184 | 0 |
| `execute_soar_action` | 56 | 0 |

## 12. Autonomy classification

Judged strictly against what this run measured, not against ambition.

**SafeSOC reaches Level 4 — autonomous response with human gates — for the narrow class
of attacks its six static playbooks cover, against simulated response infrastructure.**
It is not Level 5, and the gap is deliberate rather than unfinished.

| | What it covers |
|---|---|
| **Autonomous (no human)** | Correlation and detection; incident creation and merging; playbook matching; action parameter resolution from live evidence; evidence collection; indicator enrichment; automated incident notes; investigation-action creation; execution verification; audit logging |
| **Requires a human** | Endpoint isolation, process termination, account disabling, credential revocation, indicator blocking — all five park in an approval queue and, as measured above, never executed unapproved |
| **Deterministic, not AI** | Every one of the above. Detection is threshold rules over a sliding window. Playbook selection is a static pattern-to-playbook table. Autonomy classification is a fixed policy dictionary. None of it involves a model |
| **Actually AI-driven** | Only the investigation narrative and the Q&A turns. The LLM reads evidence and answers questions. It cannot create a confirmed finding, trigger a playbook, approve an action, or change an incident's state |

The distinction that matters most: **the AI does not drive the response.** A reader who
sees "AI-assisted SOC" and assumes the model decides what to contain would be wrong. The
model's output is advisory text attached to an investigation; every state change in the
response pipeline comes from deterministic code or a human clicking approve.

## 13. Known limitations

- **Postgres connections leak on the SOAR execution path (open, unfixed).** Roughly one
  connection per executed SOAR action is left `idle in transaction` and never reclaimed
  until the worker process restarts. Correlation-only load leaks none, so it is specific
  to SOAR execution rather than the shared-engine pattern generally. It reaches Postgres'
  100-connection ceiling after a few hundred actions, at which point execution fails with
  `TooManyConnectionsError` and actions strand in PENDING. This is the cause of the stuck
  actions in the concurrency table, and it is the most serious finding in this report.
  Restarting the worker container reclaims the connections.
- **A failed action execution is reported to Celery as a successful task.**
  `workers/soar_worker.py` catches every exception and logs it, so the task returns
  normally. Celery's own task accounting therefore shows success for executions that did
  not happen, and the reliability table below understates failures for that reason.
- **Sample size.** Every timing figure is a single-run observation on one developer
  machine. Nothing here supports a statistical claim.
- **`increase_incident_priority` has no handler.** It is classified AUTOMATIC and
  instantiated by the privilege-escalation playbook, but `services/soar_execution.py`
  registers no handler for it, so it always fails — and because any failed action fails
  its run, that playbook's run always ends FAILED. Counted honestly here rather than
  excluded.
- **Adapters are simulated.** The EDR, identity, and firewall adapters mutate SafeSOC's
  own in-memory state. A passing verification means the simulation is consistent, not
  that a real endpoint was isolated.
- **Data exfiltration is approximated by connection count.** `NormalizedLog` has no
  bytes-transferred field, so the detector counts outbound connections.
- **Correlation window ordering is processing-order, not event-order.** The sliding
  window is scored by the time the worker processes an alert, not the alert's own
  timestamp. Order-dependent detectors (successful compromise, privilege escalation,
  lateral movement) therefore depend on Celery scheduling order.
- **Hallucination screening is keyword- and identifier-based.** It catches invented
  host/IP identifiers, not a fabricated claim written in fluent prose.
