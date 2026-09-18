"""
SafeSOC — Autonomous SOC Benchmark
Entry point: `python -m benchmarks` from the repository root, against a
running stack (see docs/deployment.md).

Everything it measures is produced by the live pipeline. Benchmark
telemetry goes into dedicated benchmark tenants, never the demo tenant,
so results never become production-looking data — and no benchmark
result is persisted as an application model. The output is a report
artifact (docs/autonomous_soc_benchmark.md) plus a JSON dump.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
for path in (REPO_ROOT, REPO_ROOT / "backend"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from app.core.benchmark_scenarios import BENCHMARK_SCENARIOS, get_scenario  # noqa: E402

from benchmarks.client import (  # noqa: E402
    DEFAULT_API_BASE,
    SafeSocClient,
    TenantCredentials,
    provision_tenant,
    worker_task_counts,
)
from benchmarks.probes import (  # noqa: E402
    ConcurrencyResult,
    ProbeResult,
    run_ai_grounding_probes,
    run_approval_security_probes,
    run_concurrency_probe,
    run_connection_leak_probe,
    verify_rejected_never_executes,
)
from benchmarks.report import write_report  # noqa: E402
from benchmarks.settlement import stall_evidence  # noqa: E402
from benchmarks.runner import evaluate, run_scenario, soar_scorecard, timing_summary  # noqa: E402

# Fixed ids so re-running is idempotent rather than piling up tenants.
TENANT_A = TenantCredentials(
    tenant_id=uuid.UUID("00000000-0be0-0000-0000-00000000000a"),
    email="bench-analyst-a@safesoc.invalid",
    password="Benchmark-Tenant-A-2026!",
    name="SafeSOC Benchmark Tenant A",
)
TENANT_B = TenantCredentials(
    tenant_id=uuid.UUID("00000000-0be0-0000-0000-00000000000b"),
    email="bench-analyst-b@safesoc.invalid",
    password="Benchmark-Tenant-B-2026!",
    name="SafeSOC Benchmark Tenant B",
)
VIEWER_A = TenantCredentials(
    tenant_id=TENANT_A.tenant_id,
    email="bench-viewer-a@safesoc.invalid",
    password="Benchmark-Viewer-A-2026!",
    name="SafeSOC Benchmark Tenant A",
)


def _settlement_payload(settlement) -> dict | None:
    """Flatten a SettlementResult for the JSON artifact — None when it was never measured."""
    if settlement is None:
        return None
    return {
        "outcome": settlement.outcome,
        "settled": settlement.settled,
        "duration_seconds": round(settlement.duration_seconds, 2),
        "timeout_seconds": settlement.timeout_seconds,
        "runs_observed": settlement.runs_observed,
        "actions_observed": settlement.actions_observed,
        "terminal_actions": settlement.terminal_actions,
        "parked_actions": settlement.parked_actions,
        "non_terminal_actions_at_timeout": settlement.non_terminal_actions_at_timeout,
        "action_statuses": settlement.action_statuses,
        "run_statuses": settlement.run_statuses,
        "seconds_without_progress": round(settlement.seconds_without_progress, 1),
        "worker_active_tasks_at_end": settlement.worker_active_tasks_at_end,
        "polls": settlement.polls,
    }


def log(message: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}", flush=True)


def _clients(api_base: str, container: str) -> tuple[SafeSocClient, SafeSocClient, SafeSocClient]:
    log("Provisioning isolated benchmark tenants...")
    provision_tenant(TENANT_A, api_base=api_base, container=container, role="analyst")
    provision_tenant(TENANT_B, api_base=api_base, container=container, role="analyst")
    provision_tenant(VIEWER_A, api_base=api_base, container=container, role="viewer")

    client_a = SafeSocClient(api_base)
    client_a.login(TENANT_A)
    client_b = SafeSocClient(api_base)
    client_b.login(TENANT_B)
    viewer = SafeSocClient(api_base)
    viewer.login(VIEWER_A)
    log(f"Tenant A={TENANT_A.tenant_id}  Tenant B={TENANT_B.tenant_id}  (+viewer)")
    return client_a, client_b, viewer


def _tenant_isolation_checks(client_a: SafeSocClient, client_b: SafeSocClient, result_a, result_b) -> list[ProbeResult]:
    """Cross-check that two tenants running the same attack share nothing."""
    checks: list[ProbeResult] = []

    a_incidents = {i["id"] for i in client_a.list_incidents(size=200)}
    b_incidents = {i["id"] for i in client_b.list_incidents(size=200)}
    checks.append(ProbeResult(
        "Tenant isolation", "incident sets are disjoint",
        "PASS" if not (a_incidents & b_incidents) else "FAIL",
        f"A={len(a_incidents)} B={len(b_incidents)} shared={len(a_incidents & b_incidents)}",
    ))

    if result_b.incident_id:
        response = client_a.get(f"/api/v1/incidents/{result_b.incident_id}")
        checks.append(ProbeResult(
            "Tenant isolation", "tenant A cannot read tenant B's incident",
            "PASS" if response.status_code == 404 else "FAIL", f"HTTP {response.status_code}",
        ))
        response = client_a.get(f"/api/v1/incidents/{result_b.incident_id}/evidence")
        checks.append(ProbeResult(
            "Tenant isolation", "tenant A cannot read tenant B's evidence",
            "PASS" if response.status_code == 404 else "FAIL", f"HTTP {response.status_code}",
        ))
        response = client_a.get(f"/api/v1/incidents/{result_b.incident_id}/timeline")
        checks.append(ProbeResult(
            "Tenant isolation", "tenant A cannot read tenant B's timeline",
            "PASS" if response.status_code == 404 else "FAIL", f"HTTP {response.status_code}",
        ))

    a_run_incidents = {run["incident_id"] for run in client_a.all_soar_runs()}
    checks.append(ProbeResult(
        "Tenant isolation", "tenant A's SOAR runs reference only tenant A incidents",
        "PASS" if not (a_run_incidents & b_incidents) else "FAIL",
        f"{len(a_run_incidents)} runs, {len(a_run_incidents & b_incidents)} pointing at tenant B",
    ))

    if result_a.incident_id and result_b.incident_id:
        checks.append(ProbeResult(
            "Tenant isolation", "identical attacks produced separate incidents",
            "PASS" if result_a.incident_id != result_b.incident_id else "FAIL",
            f"A={result_a.incident_id[:8]} B={result_b.incident_id[:8]}",
        ))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="SafeSOC autonomous SOC benchmark")
    parser.add_argument("--api-base", default=DEFAULT_API_BASE)
    parser.add_argument("--backend-container", default="safe-soc-backend-1")
    parser.add_argument("--worker-container", default="safe-soc-worker-1")
    parser.add_argument("--skip-ai", action="store_true", help="Skip the AI grounding probes (they need the LLM)")
    parser.add_argument("--skip-concurrency", action="store_true")
    parser.add_argument("--concurrency-levels", default="10,25", help="Comma-separated scenario counts")
    parser.add_argument("--out", default=str(REPO_ROOT / "docs" / "autonomous_soc_benchmark.md"))
    parser.add_argument("--json-out", default=str(REPO_ROOT / "docs" / "autonomous_soc_benchmark.json"))
    args = parser.parse_args()

    started_at = datetime.now(timezone.utc)
    run_tag = uuid.uuid4().hex[:6]
    client_a, client_b, viewer = _clients(args.api_base, args.backend_container)

    # ── Scenarios ───────────────────────────────────────────────────
    results = []
    isolation_checks: list[ProbeResult] = []
    for scenario in BENCHMARK_SCENARIOS:
        log(f"Running {scenario.id} ...")
        if scenario.tenant_isolation_check:
            result_a = evaluate(run_scenario(client_a, scenario, TENANT_A, f"{run_tag}A"), scenario)
            result_b = evaluate(run_scenario(client_b, scenario, TENANT_B, f"{run_tag}B"), scenario)
            isolation_checks = _tenant_isolation_checks(client_a, client_b, result_a, result_b)
            result_a.checks.extend((f"[isolation] {c.name}", c.passed, c.detail) for c in isolation_checks)
            results.append(result_a)
        else:
            results.append(evaluate(run_scenario(client_a, scenario, TENANT_A, run_tag), scenario))
        status = "PASS" if results[-1].passed else "FAIL"
        log(f"  {scenario.id}: {status}")

    # ── AI grounding ────────────────────────────────────────────────
    ai_results: list[ProbeResult] = []
    if not args.skip_ai:
        target = next((r for r in results if r.incident_id and r.scenario_id == "bm-b-successful-compromise"), None)
        target = target or next((r for r in results if r.incident_id), None)
        if target:
            log(f"Running AI grounding probes against incident {target.incident_id[:8]} ...")
            ai_results = run_ai_grounding_probes(client_a, target.incident_id)
            for probe in ai_results:
                log(f"  [{probe.verdict}] {probe.category} — {probe.name}")

    # ── Approval security ───────────────────────────────────────────
    log("Running approval-security probes against a dedicated scenario instance ...")
    security_results: list[ProbeResult] = []
    rejection_probe: ProbeResult | None = None
    sec_scenario = get_scenario("bm-b-successful-compromise")
    sec_result = run_scenario(client_a, sec_scenario, TENANT_A, f"{run_tag}SEC")
    approval_actions = [
        (run["id"], action["id"])
        for run in sec_result.runs
        for action in run["actions"]
        if action["autonomy_class"] == "approval_required" and action["status"] == "awaiting_approval"
    ]
    if sec_result.incident_id and len(approval_actions) >= 2:
        run_id, first_action = approval_actions[0]
        _, second_action = approval_actions[1]
        security_results = run_approval_security_probes(
            client_a, sec_result.incident_id, run_id, first_action, second_action, viewer, client_b
        )
        rejection_probe = verify_rejected_never_executes(client_a, sec_result.incident_id, run_id, second_action)
        security_results.append(rejection_probe)
        for probe in security_results:
            log(f"  [{probe.verdict}] {probe.category} — {probe.name}: {probe.detail}")
    else:
        log(f"  SKIPPED: needed 2 awaiting-approval actions, found {len(approval_actions)}")

    # ── Resource management ─────────────────────────────────────────
    log("Running connection-leak probe ...")
    leak_probe = run_connection_leak_probe(client_a, get_scenario("bm-a-credential-brute-force"))
    log(f"  [{leak_probe.verdict}] {leak_probe.detail}")

    # ── Concurrency ─────────────────────────────────────────────────
    concurrency_results: list[tuple[int, ConcurrencyResult]] = []
    if not args.skip_concurrency:
        for level in [int(x) for x in args.concurrency_levels.split(",") if x.strip()]:
            log(f"Running concurrency probe at {level} simultaneous scenarios ...")
            outcome = run_concurrency_probe(client_a, TENANT_A, get_scenario("bm-a-credential-brute-force"), level)
            concurrency_results.append((level, outcome))
            settlement = outcome.settlement
            log(
                f"  {level}: incidents={outcome.incidents_created} runs={outcome.runs_created} "
                f"duplicates={len(outcome.duplicate_runs)} over_instantiated={len(outcome.over_instantiated_runs)} "
                f"settlement={settlement.summary() if settlement else 'not measured'}"
            )
            if outcome.correctness_failures:
                log(f"  CORRECTNESS FAILURE: {outcome.correctness_failures}")
            elif not outcome.settled and settlement is not None:
                log(f"  SETTLEMENT TIMEOUT: {stall_evidence(settlement)}")

    # ── Reliability ─────────────────────────────────────────────────
    tasks = worker_task_counts(args.worker_container, since="30m")

    payload = {
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "api_base": args.api_base,
        "tenants": {"a": str(TENANT_A.tenant_id), "b": str(TENANT_B.tenant_id)},
        "scenarios": [
            {
                "id": r.scenario_id, "name": r.name, "passed": r.passed, "incident_id": r.incident_id,
                "detected_category": r.detected_category, "detected_confidence": r.detected_confidence,
                "events_injected": r.events_injected, "events_accepted": r.events_accepted,
                "runs": [run["playbook_id"] for run in r.runs],
                "actions": [
                    {"type": a.action_type, "autonomy": a.autonomy_class, "status": a.status,
                     "verification": a.verification_status}
                    for a in r.actions
                ],
                "skipped": r.skipped,
                "timeline_soar_events": r.timeline_soar_events,
                "settlement": _settlement_payload(r.settlement),
                "observed_time_to_incident": r.observed_time_to_incident,
                "observed_time_to_settle": r.observed_time_to_settle,
                "time_to_soar": r.time_to_soar, "time_to_response": r.time_to_response,
                "time_to_verification": r.time_to_verification,
                "checks": [{"name": n, "passed": ok, "detail": d} for n, ok, d in r.checks],
                "errors": r.errors,
            }
            for r in results
        ],
        "soar_scorecard": soar_scorecard(results),
        "timing": timing_summary(results),
        "ai_probes": [p.__dict__ for p in ai_results],
        "security_probes": [p.__dict__ for p in security_results],
        "isolation_probes": [p.__dict__ for p in isolation_checks],
        "resource_probes": [leak_probe.__dict__],
        "concurrency": [
            {
                "level": level, "incidents_created": o.incidents_created, "runs_created": o.runs_created,
                "duplicate_runs": o.duplicate_runs, "over_instantiated_runs": o.over_instantiated_runs,
                "errors": o.errors, "wall_seconds": o.wall_seconds, "passed": o.passed,
                "settlement": _settlement_payload(o.settlement),
                "stall_evidence": stall_evidence(o.settlement) if o.settlement else None,
            }
            for level, o in concurrency_results
        ],
        "worker_tasks": tasks,
    }

    Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json_out).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    write_report(payload, Path(args.out))
    log(f"Report written to {args.out}")
    log(f"Raw results written to {args.json_out}")

    failed = [r for r in results if not r.passed]
    log(f"DONE: {len(results) - len(failed)}/{len(results)} scenarios passed")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
