"""
SafeSOC — Autonomous SOC Benchmark Runner
Executes core/benchmark_scenarios.py against a live stack and measures
what actually happened.

Two things this deliberately does NOT do:

  * It never inserts an incident, run, or action directly. Every
    artifact it measures was produced by the real pipeline from real
    telemetry, or it is recorded as a miss.
  * It never invents a duration. Timings come from server-side
    timestamps that share one clock (incident.created_at ->
    run.created_at -> action.executed_at -> verified_at), reported
    separately from host-observed latency, because the host and the
    container clocks are not the same clock and pretending otherwise
    would manufacture precision that doesn't exist.

Telemetry generation is the injector's (injector/injector.py), reused
by name rather than reimplemented; the only transformation applied
here is the scenario's declared degradation.
"""

from __future__ import annotations

import statistics
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "backend"))

from injector.injector import SCENARIOS, generate_log  # noqa: E402

from app.core.benchmark_scenarios import BenchmarkScenario, TelemetryDegradation  # noqa: E402

from benchmarks.client import SafeSocClient, TenantCredentials, parse_ts  # noqa: E402
from benchmarks.settlement import (  # noqa: E402
    TERMINAL_ACTION_STATUSES,
    SettlementResult,
    wait_for_settlement,
)

# How long to wait for the asynchronous pipeline (Celery correlation ->
# incident -> SOAR trigger -> action execution) to settle before
# recording what it produced. A scenario that needs longer than this is
# reported as a timeout, never silently retried into looking fast.
# A single scenario settles in ~2.4s measured. 90s is generous headroom
# for provider latency without being so large that a genuine stall would
# go unreported; the runner exits the moment the workload settles, so a
# high ceiling costs nothing on healthy runs.
SETTLE_TIMEOUT_SECONDS = 90
POLL_INTERVAL_SECONDS = 1.5



def build_events(scenario: BenchmarkScenario, host: str) -> list[dict]:
    """
    The injector's own generator, plus the scenario's declared
    degradation. Kept in step with tests/test_benchmark_scenarios.py's
    _scenario_events() — if these diverge, the suite grades something
    other than what it validated.
    """
    if scenario.injector_scenario == "benign_single_failed_login":
        # The injector has no entry for this (its SCENARIOS registry
        # holds exactly one attack per correlation pattern, an
        # invariant its own tests enforce), so the benign case is built
        # from the same generate_log() primitive the scenarios use.
        event = generate_log(log_type="authentication", severity="low", host_id=host)
        event["action"] = "failed_login"
        event["description"] = f"Benign single failed login on {host}"
        events = [event]
    else:
        events = SCENARIOS[scenario.injector_scenario](host)

    if scenario.degradation == TelemetryDegradation.STRIP_IP_ADDRESSES:
        events = [{k: v for k, v in e.items() if k not in ("source_ip", "destination_ip")} for e in events]
    return events


@dataclass
class ActionOutcome:
    action_type: str
    autonomy_class: str
    status: str
    verification_status: str
    executed_at: Optional[datetime]
    verified_at: Optional[datetime]
    approved_at: Optional[datetime]
    result_success: Optional[bool]


@dataclass
class ScenarioResult:
    scenario_id: str
    name: str
    tenant_id: str
    host: str

    events_injected: int = 0
    events_accepted: int = 0
    events_rejected: int = 0

    incident_id: Optional[str] = None
    incidents_created: int = 0
    detected_category: Optional[str] = None
    detected_confidence: Optional[float] = None

    runs: list[dict] = field(default_factory=list)
    actions: list[ActionOutcome] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)

    # Host-observed: from the moment ingest returned to the moment the
    # benchmark could first SEE the artifact over the API. Includes poll
    # granularity, so it is an upper bound, not a precise latency.
    observed_time_to_incident: Optional[float] = None
    observed_time_to_settle: Optional[float] = None

    # Server-side: differences between timestamps the backend wrote,
    # all from the same clock. These are the trustworthy durations.
    time_to_soar: Optional[float] = None
    time_to_response: Optional[float] = None
    time_to_verification: Optional[float] = None

    timeline_soar_events: int = 0
    settled: bool = False
    settlement: Optional[SettlementResult] = None
    errors: list[str] = field(default_factory=list)

    # Filled in by evaluate()
    checks: list[tuple[str, bool, str]] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.errors and all(ok for _, ok, _ in self.checks)

    @property
    def automatic_actions(self) -> list[ActionOutcome]:
        return [a for a in self.actions if a.autonomy_class == "automatic"]

    @property
    def approval_actions(self) -> list[ActionOutcome]:
        return [a for a in self.actions if a.autonomy_class == "approval_required"]


def _collect_actions(runs: list[dict]) -> list[ActionOutcome]:
    outcomes = []
    for run in runs:
        for action in run["actions"]:
            result = action.get("result") or {}
            outcomes.append(
                ActionOutcome(
                    action_type=action["action_type"],
                    autonomy_class=action["autonomy_class"],
                    status=action["status"],
                    verification_status=action["verification_status"],
                    executed_at=parse_ts(action.get("executed_at")),
                    verified_at=parse_ts(action.get("verified_at")),
                    approved_at=parse_ts(action.get("approved_at")),
                    result_success=result.get("success") if isinstance(result, dict) else None,
                )
            )
    return outcomes


def extract_skips(soar_timeline_entries: list[dict]) -> list[dict]:
    """
    Pull the skip records out of the incident timeline.

    A timeline entry's payload is {action, actor_user_id, details}, and
    a skip's own fields (action_type, reason, detail) live one level
    down in `details` — reading the outer dict yields entries with no
    action_type at all, which silently grades every skip as missing.
    """
    return [
        entry["data"].get("details") or {}
        for entry in soar_timeline_entries
        if entry.get("data", {}).get("action") == "soar.action.skipped"
    ]


def run_scenario(
    client: SafeSocClient,
    scenario: BenchmarkScenario,
    credentials: TenantCredentials,
    host_suffix: str,
    settle_timeout: int = SETTLE_TIMEOUT_SECONDS,
) -> ScenarioResult:
    """Inject one scenario's telemetry and observe what the real pipeline does with it."""
    host = f"BM-{scenario.id.replace('bm-', '').upper()[:18]}-{host_suffix}"
    result = ScenarioResult(
        scenario_id=scenario.id, name=scenario.name, tenant_id=str(credentials.tenant_id), host=host
    )

    events = build_events(scenario, host)
    result.events_injected = len(events)

    try:
        ingest_response = client.ingest(events)
    except Exception as e:  # noqa: BLE001 - recorded, never swallowed
        result.errors.append(f"ingest failed: {e}")
        return result

    injected_at = time.monotonic()
    result.events_accepted = ingest_response.get("accepted", 0)
    result.events_rejected = ingest_response.get("rejected", 0)
    alert_ids = set(ingest_response.get("alert_ids") or [])

    # Wait for the workload to actually settle rather than sleeping a
    # fixed window and judging whatever state that happened to catch —
    # see benchmarks/settlement.py for why the old approach produced
    # false "stuck" verdicts.
    settlement = wait_for_settlement(
        client,
        alert_ids,
        expected_incidents=scenario.expected_incidents if scenario.expects_detection else None,
        expects_soar=bool(scenario.expected_playbooks),
        timeout_seconds=settle_timeout,
        poll_interval_seconds=POLL_INTERVAL_SECONDS,
    )
    result.settlement = settlement
    result.settled = settlement.settled
    result.observed_time_to_settle = settlement.duration_seconds
    result.errors.extend(settlement.errors)

    incidents = [i for i in client.list_incidents() if alert_ids & set(i.get("alert_ids") or [])]
    result.incidents_created = len(incidents)
    incident: Optional[dict] = incidents[0] if incidents else None

    if incident is None:
        # For a restraint scenario this is the CORRECT outcome, not a failure.
        result.settled = not scenario.expects_detection
        return result

    result.observed_time_to_incident = settlement.duration_seconds
    result.runs = client.soar_runs_with_actions(incident["id"])

    result.incident_id = incident["id"]
    result.detected_category = incident.get("category")
    result.detected_confidence = incident.get("confidence")
    if not result.runs:
        result.runs = client.soar_runs_with_actions(incident["id"])
    result.actions = _collect_actions(result.runs)

    incident_created = parse_ts(incident.get("created_at"))
    entries = client.incident_timeline(incident["id"])
    soar_entries = [e for e in entries if str(e["data"].get("action", "")).startswith("soar.")]
    result.timeline_soar_events = len(soar_entries)
    result.skipped = extract_skips(soar_entries)

    # Server-side timings: one clock, so these subtractions are sound.
    run_created = min((parse_ts(r.get("created_at")) for r in result.runs if r.get("created_at")), default=None)
    if incident_created and run_created:
        result.time_to_soar = (run_created - incident_created).total_seconds()

    executions = [a.executed_at for a in result.actions if a.executed_at]
    if incident_created and executions:
        result.time_to_response = (max(executions) - incident_created).total_seconds()

    verifications = [a.verified_at for a in result.actions if a.verified_at]
    if incident_created and verifications:
        result.time_to_verification = (max(verifications) - incident_created).total_seconds()

    return result


def evaluate(result: ScenarioResult, scenario: BenchmarkScenario) -> ScenarioResult:
    """Grade an observed result against the scenario's declared ground truth."""
    check = result.checks.append

    check(("all events accepted", result.events_rejected == 0, f"{result.events_accepted}/{result.events_injected} accepted"))

    if scenario.expects_detection:
        check(("incident created", result.incident_id is not None, result.incident_id or "none"))
        check((
            "detected category is one of the expected patterns",
            result.detected_category in {p.value for p in scenario.expected_patterns},
            f"{result.detected_category}",
        ))
    else:
        check(("no incident created (restraint)", result.incident_id is None, result.incident_id or "none"))
        return result

    if result.incident_id is None:
        return result

    triggered = {run["playbook_id"] for run in result.runs}
    check((
        "expected playbooks triggered",
        triggered == set(scenario.expected_playbooks),
        f"got {sorted(triggered)} expected {sorted(scenario.expected_playbooks)}",
    ))

    created_types = {a.action_type for a in result.actions}
    expected_created = {a.value for a in scenario.all_expected_actions}
    check((
        "expected actions instantiated",
        created_types == expected_created,
        f"got {sorted(created_types)} expected {sorted(expected_created)}",
    ))

    expected_skipped = {a.value for a in scenario.expected_skipped_actions}
    skipped_types = {s.get("action_type") for s in result.skipped}
    check((
        "expected actions skipped for unavailable evidence",
        skipped_types == expected_skipped,
        f"got {sorted(t for t in skipped_types if t)} expected {sorted(expected_skipped)}",
    ))
    check((
        "no skipped action left an executable record",
        not (skipped_types & created_types),
        f"overlap {sorted(skipped_types & created_types)}",
    ))

    # The core autonomy guarantee.
    unapproved_executions = [
        a for a in result.approval_actions if a.status in ("executing", "succeeded") and a.approved_at is None
    ]
    check((
        "no approval-required action executed without approval",
        not unapproved_executions,
        f"{len(unapproved_executions)} violation(s)",
    ))
    check((
        "approval-required actions are parked awaiting approval",
        all(a.status == "awaiting_approval" for a in result.approval_actions),
        f"{[a.status for a in result.approval_actions]}",
    ))

    # Automatic actions should have run unattended. A failed automatic
    # action is reported rather than counted as a failure of the gate.
    ran = [a for a in result.automatic_actions if a.status in ("succeeded", "failed")]
    check((
        "automatic actions executed unattended",
        len(ran) == len(result.automatic_actions),
        f"{len(ran)}/{len(result.automatic_actions)} executed",
    ))

    check(("SOAR lifecycle events reached the incident timeline", result.timeline_soar_events > 0, f"{result.timeline_soar_events} events"))
    settlement_detail = result.settlement.summary() if result.settlement else "not measured"
    check(("workload settled within the timeout", result.settled, settlement_detail))
    return result


# ── Aggregate metrics ───────────────────────────────────────────────


def _median(values: list[float]) -> Optional[float]:
    return statistics.median(values) if values else None


def _rate(numerator: int, denominator: int) -> Optional[float]:
    """None means N/A — a rate with an empty denominator is undefined, never silently 0.0 or 1.0."""
    return (numerator / denominator) if denominator else None


def soar_scorecard(results: list[ScenarioResult]) -> dict:
    """
    The autonomy scorecard. Every rate is explicit about its
    denominator, and returns None (rendered "N/A") when that denominator
    is zero rather than dividing by it.
    """
    actions = [a for r in results for a in r.actions]
    automatic = [a for a in actions if a.autonomy_class == "automatic"]
    approval = [a for a in actions if a.autonomy_class == "approval_required"]
    skipped = [s for r in results for s in r.skipped]

    automatic_executed = [a for a in automatic if a.status in ("succeeded", "failed")]
    approval_gated = [a for a in approval if not (a.status in ("executing", "succeeded") and a.approved_at is None)]
    verified = [a for a in actions if a.verification_status == "verified"]
    verifiable = [a for a in actions if a.status == "succeeded"]

    skipped_by_reason: dict[str, int] = {}
    for entry in skipped:
        reason = entry.get("reason", "unknown")
        skipped_by_reason[reason] = skipped_by_reason.get(reason, 0) + 1

    return {
        "playbooks_triggered": sum(len(r.runs) for r in results),
        "actions_created": len(actions),
        "actions_automatic": len(automatic),
        "actions_approval_required": len(approval),
        "actions_executed_automatically": len(automatic_executed),
        "actions_awaiting_approval": len([a for a in approval if a.status == "awaiting_approval"]),
        "actions_succeeded": len([a for a in actions if a.status == "succeeded"]),
        "actions_failed": len([a for a in actions if a.status == "failed"]),
        "actions_skipped": len(skipped),
        "skipped_by_reason": skipped_by_reason,
        "automatic_execution_rate": _rate(len(automatic_executed), len(automatic)),
        "approval_gate_enforcement_rate": _rate(len(approval_gated), len(approval)),
        "skipped_action_rate": _rate(len(skipped), len(actions) + len(skipped)),
        "verification_success_rate": _rate(len(verified), len(verifiable)),
    }


def timing_summary(results: list[ScenarioResult]) -> dict:
    detected = [r for r in results if r.incident_id]
    return {
        "sample_size": len(detected),
        "median_observed_time_to_incident": _median([r.observed_time_to_incident for r in detected if r.observed_time_to_incident]),
        "median_observed_time_to_settle": _median([r.observed_time_to_settle for r in detected if r.observed_time_to_settle]),
        "median_time_to_soar": _median([r.time_to_soar for r in detected if r.time_to_soar is not None]),
        "median_time_to_response": _median([r.time_to_response for r in detected if r.time_to_response is not None]),
        "median_time_to_verification": _median([r.time_to_verification for r in detected if r.time_to_verification is not None]),
    }
