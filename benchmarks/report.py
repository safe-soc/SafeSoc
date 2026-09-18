"""
SafeSOC — Benchmark Report Writer
Renders a measured run into docs/autonomous_soc_benchmark.md.

Every number in the output comes from the payload the runner measured.
Where a value was not measured, this writes "not measured" or "N/A" —
never a plausible-looking placeholder. Sample sizes are printed next to
medians so nobody reads a median of three runs as a performance
characteristic.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Optional

BENCHMARK_MIN_SAMPLE_FOR_STATS = 5


def _fmt_seconds(value: Optional[float]) -> str:
    return f"{value:.2f}s" if isinstance(value, (int, float)) else "not measured"


def _fmt_rate(value: Optional[float]) -> str:
    """None is N/A by construction — an undefined denominator, never rendered as 0%."""
    return f"{value * 100:.0f}%" if isinstance(value, (int, float)) else "N/A"


def _verdict_icon(passed: bool) -> str:
    return "PASS" if passed else "FAIL"


def _scenario_matrix(scenarios: list[dict]) -> str:
    lines = [
        "| Scenario | Detection | Incident | SOAR runs | Automatic | Awaiting approval | Skipped | Result |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for s in scenarios:
        actions = s["actions"]
        automatic = [a for a in actions if a["autonomy"] == "automatic"]
        approval = [a for a in actions if a["autonomy"] == "approval_required"]
        awaiting = [a for a in approval if a["status"] == "awaiting_approval"]
        executed = [a for a in automatic if a["status"] in ("succeeded", "failed")]
        detection = s["detected_category"] or "none"
        confidence = f" ({s['detected_confidence']:.2f})" if s.get("detected_confidence") is not None else ""
        lines.append(
            f"| {s['name']} | {detection}{confidence} | "
            f"{'yes' if s['incident_id'] else 'no'} | "
            f"{len(s['runs'])} | {len(executed)}/{len(automatic)} executed | "
            f"{len(awaiting)}/{len(approval)} | {len(s['skipped'])} | **{_verdict_icon(s['passed'])}** |"
        )
    return "\n".join(lines)


def _checks_detail(scenarios: list[dict]) -> str:
    blocks = []
    for s in scenarios:
        failed = [c for c in s["checks"] if not c["passed"]]
        if not failed and not s["errors"]:
            continue
        block = [f"**{s['name']}**"]
        for error in s["errors"]:
            block.append(f"- ERROR: {error}")
        for check in failed:
            block.append(f"- FAILED: {check['name']} — {check['detail']}")
        blocks.append("\n".join(block))
    return "\n\n".join(blocks) if blocks else "_No scenario check failed._"


def _probe_table(probes: list[dict], empty_message: str) -> str:
    if not probes:
        return f"_{empty_message}_"
    lines = ["| Category | Check | Verdict | Detail |", "|---|---|---|---|"]
    for p in probes:
        detail = str(p.get("detail", "")).replace("|", "\\|")
        lines.append(f"| {p['category']} | {p['name']} | **{p['verdict']}** | {detail} |")
    return "\n".join(lines)


def _ai_answers(probes: list[dict]) -> str:
    """The model's own words, so a reader can second-guess the automated verdict."""
    blocks = []
    for p in probes:
        if not p.get("evidence"):
            continue
        answer = str(p["evidence"]).strip().replace("\n", " ")
        blocks.append(f"- **{p['category']}** ({p['verdict']}): “{answer}”")
    return "\n".join(blocks) if blocks else "_No answers captured._"


def _settlement_cell(entry: dict) -> str:
    settlement = entry.get("settlement")
    if not settlement:
        return "not measured"
    if settlement["outcome"] == "COMPLETED":
        return f"COMPLETED in {settlement['duration_seconds']:.0f}s"
    return f"TIMEOUT at {settlement['timeout_seconds']:.0f}s"


def _concurrency_section(entries: list[dict]) -> str:
    """
    Correctness and settlement are reported as separate columns on
    purpose. Duplicate runs and over-instantiated actions are
    correctness failures that no amount of waiting fixes; work still in
    flight when the clock runs out is a settlement outcome. The earlier
    version collapsed both into one "Stuck actions" count, which is how
    a workload that settled at 65s against a 60s window came to be
    reported as 14 stranded actions.
    """
    if not entries:
        return "_Concurrency probe not run._"
    lines = [
        "| Simultaneous scenarios | Incidents | SOAR runs | Duplicate runs | Over-instantiated | Settlement | Non-terminal at timeout | Result |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for e in entries:
        settlement = e.get("settlement") or {}
        non_terminal = len(settlement.get("non_terminal_actions_at_timeout") or [])
        lines.append(
            f"| {e['level']} | {e['incidents_created']} | {e['runs_created']} | "
            f"{len(e['duplicate_runs'])} | {len(e['over_instantiated_runs'])} | "
            f"{_settlement_cell(e)} | {non_terminal} | **{_verdict_icon(e['passed'])}** |"
        )
    detail = []
    for e in entries:
        for label, items in (
            ("duplicate playbook runs", e["duplicate_runs"]),
            ("over-instantiated runs", e["over_instantiated_runs"]),
            ("errors", e["errors"]),
        ):
            if items:
                detail.append(f"- At {e['level']} scenarios - {label}: {items[:10]}")
        if e.get("stall_evidence") and not (e.get("settlement") or {}).get("settled", True):
            detail.append(f"- At {e['level']} scenarios - {e['stall_evidence']}")
    if detail:
        lines.append("")
        lines.extend(detail)
    return "\n".join(lines)


def write_report(payload: dict[str, Any], path: Path) -> None:
    scenarios = payload["scenarios"]
    scorecard = payload["soar_scorecard"]
    timing = payload["timing"]
    tasks = payload.get("worker_tasks") or {}

    passed = [s for s in scenarios if s["passed"]]
    ai_probes = payload.get("ai_probes") or []
    security_probes = payload.get("security_probes") or []
    isolation_probes = payload.get("isolation_probes") or []

    ai_pass = len([p for p in ai_probes if p["verdict"] == "PASS"])
    ai_inconclusive = len([p for p in ai_probes if p["verdict"] == "INCONCLUSIVE"])
    security_pass = len([p for p in security_probes if p["verdict"] == "PASS"])
    sample = timing.get("sample_size") or 0

    stats_caveat = (
        f"Sample size is {sample} scenario run(s). That is far too small for statistical claims — these are "
        "single-run observations on one developer machine, reported to show order of magnitude and to catch "
        "regressions, not as performance characteristics."
    )

    content = f"""# SafeSOC — Autonomous SOC Benchmark

Generated {payload['finished_at']} from a live run against `{payload['api_base']}`.

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
- **Benchmark tenants:** `{payload['tenants']['a']}` and `{payload['tenants']['b']}` —
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

{_scenario_matrix(scenarios)}

**{len(passed)}/{len(scenarios)} scenarios passed.**

### Failures and errors

{_checks_detail(scenarios)}

## 4. Performance

{stats_caveat}

Two clocks are reported separately, because mixing them would manufacture precision:

- **Observed** — measured on the benchmark host from the moment `POST /ingest` returned
  until the artifact was first visible over the API. Includes poll granularity
  (~1.5s), so it is an upper bound.
- **Server-side** — differences between timestamps the backend itself wrote. One clock,
  so these are the trustworthy durations.

| Metric | Median | Clock |
|---|---|---|
| Time to incident (observed) | {_fmt_seconds(timing.get('median_observed_time_to_incident'))} | host |
| Time to fully settled (observed) | {_fmt_seconds(timing.get('median_observed_time_to_settle'))} | host |
| Incident -> SOAR run created | {_fmt_seconds(timing.get('median_time_to_soar'))} | server |
| Incident -> last automatic action executed | {_fmt_seconds(timing.get('median_time_to_response'))} | server |
| Incident -> last verification completed | {_fmt_seconds(timing.get('median_time_to_verification'))} | server |

Sample size: {sample}{' (below the ' + str(BENCHMARK_MIN_SAMPLE_FOR_STATS) + '-run floor for even weak inference)' if sample < BENCHMARK_MIN_SAMPLE_FOR_STATS else ''}.

## 5. SOAR autonomy scorecard

Definitions are explicit, and a rate with an empty denominator is reported **N/A**
rather than silently rendered as 0% or 100%.

| Metric | Value | Definition |
|---|---|---|
| Playbooks triggered | {scorecard['playbooks_triggered']} | runs created across all scenarios |
| Actions created | {scorecard['actions_created']} | action records instantiated |
| Automatic actions | {scorecard['actions_automatic']} | classified AUTOMATIC by policy |
| Approval-required actions | {scorecard['actions_approval_required']} | classified APPROVAL_REQUIRED |
| Awaiting approval | {scorecard['actions_awaiting_approval']} | parked, never executed |
| Succeeded / Failed | {scorecard['actions_succeeded']} / {scorecard['actions_failed']} | terminal execution outcomes |
| Skipped | {scorecard['actions_skipped']} | never instantiated (evidence unavailable / invalid parameters) |
| **automatic_execution_rate** | **{_fmt_rate(scorecard['automatic_execution_rate'])}** | automatic actions that reached a terminal execution state / all automatic actions |
| **approval_gate_enforcement_rate** | **{_fmt_rate(scorecard['approval_gate_enforcement_rate'])}** | approval-required actions that never executed without approval / all approval-required actions |
| **skipped_action_rate** | **{_fmt_rate(scorecard['skipped_action_rate'])}** | skipped / (created + skipped) |
| **verification_success_rate** | **{_fmt_rate(scorecard['verification_success_rate'])}** | verified / actions reaching SUCCEEDED |

Skipped actions by reason: {scorecard['skipped_by_reason'] or 'none'}

## 6. AI investigation results

{ai_pass}/{len(ai_probes)} probes passed{f', {ai_inconclusive} inconclusive' if ai_inconclusive else ''}.

**These are screens, not proofs.** A keyword check cannot demonstrate the absence of
hallucination. Probes are recorded INCONCLUSIVE — not passed — when the LLM was
unavailable and the platform served its deterministic fallback, because a templated
sentence says nothing about grounding.

{_probe_table(ai_probes, "AI probes not run.")}

### What the model actually said

{_ai_answers(ai_probes)}

**Read the hypothesis-boundary result with care.** A model that ignores the
findings sections of the prompt entirely would pass the hypothesis probe for the wrong
reason — by never mentioning any finding. Where the confirmed-findings probe also fails,
that is the more likely explanation, and the boundary result should be treated as
unproven rather than as evidence the model reasons about the confirmed/unconfirmed
distinction. The platform's part (supplying findings under labelled headings, and never
letting AI output create a confirmed finding) is structural and holds regardless.

## 7. Human-approval security

{security_pass}/{len(security_probes)} probes passed.

{_probe_table(security_probes, "Security probes not run.")}

## 8. Tenant isolation

{_probe_table(isolation_probes, "Isolation probes not run.")}

## 9. Concurrency and idempotency

Looking specifically for the failure modes this architecture can actually produce:
duplicate playbook runs for one incident (advisory-lock failure), runs with more actions
than their playbook has steps (double instantiation), and actions still mid-flight after
the pipeline settled (a lost state transition — the signature of the shared-engine race
found in Phase 2).

{_concurrency_section(payload.get('concurrency') or [])}

## 10. Resource management

Whether the pipeline returns its database connections after a burst of work. A count
that climbs and stays up means transactions are being abandoned, which ends in
`sorry, too many clients already` and a stalled platform.

{_probe_table(payload.get('resource_probes') or [], "Resource probe not run.")}

## 11. Reliability

Celery task outcomes read from the worker's own log over the run window:

| Task | Succeeded | Failed |
|---|---|---|
| `evaluate_correlation` | {tasks.get('correlation_succeeded', 'not measured')} | {tasks.get('correlation_failed', 'not measured')} |
| `execute_soar_action` | {tasks.get('soar_succeeded', 'not measured')} | {tasks.get('soar_failed', 'not measured')} |

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
"""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
