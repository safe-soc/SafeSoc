"""
SafeSOC — Benchmark Settlement Detection
Answers one question honestly: has the pipeline finished with this
workload, or did we merely stop looking?

The previous methodology slept for a fixed window and then labelled any
non-terminal action "stuck". That conflated three different things, and
was measurably wrong: at 10-25 concurrent scenarios the benchmark
reported 14-26 "stuck" actions, and every one of them later reached a
terminal state on its own with no duplicate runs and no lost
transitions. The pipeline was slower than the window, not broken.

So this module separates:

  COMPLETED — every action in the workload reached a quiescent state
              before the timeout. Quiescent is not the same as
              successful: it includes FAILED and REJECTED, and it
              includes AWAITING_APPROVAL, because an action parked on a
              human is the pipeline having finished its part.

  TIMEOUT   — the timeout elapsed with work still in flight. This says
              "we did not observe completion in the time allowed". It
              says nothing about whether the work would have finished a
              second later, and it must never be reported as though it
              did.

There is deliberately no STRANDED verdict. Proving an action is
permanently abandoned would require showing that no execution path
remains capable of progressing it, and nothing in this architecture can
establish that from the outside: a worker restart or a manual dispatch
would still pick it up. What this module does instead is record
*evidence of a stall* — how long the workload went without any state
change, and whether the worker reported active tasks at the time — and
leave the interpretation to a reader. A false claim of permanent
stranding would damage the benchmark's credibility far more than an
honest "unresolved at timeout".

Terminal statuses are read from the product's own state machine
(services/soar.py), never re-declared here, so they cannot drift.
"""

from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
for path in (REPO_ROOT, REPO_ROOT / "backend"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from app.core.enums import SoarActionStatus  # noqa: E402
from app.services.soar import _TERMINAL_ACTION_STATUSES  # noqa: E402

# The product's own definition of "this action is finished", taken from
# its state machine rather than restated: the statuses with no outgoing
# transition in _ALLOWED_ACTION_TRANSITIONS.
TERMINAL_ACTION_STATUSES: frozenset[str] = frozenset(s.value for s in _TERMINAL_ACTION_STATUSES)

# Parked on a human decision. Not terminal — an analyst can still
# approve or reject it — but the pipeline has done everything it will do
# unattended, so a workload waiting here has settled as far as an
# unattended benchmark is concerned.
PARKED_ACTION_STATUSES: frozenset[str] = frozenset({SoarActionStatus.AWAITING_APPROVAL.value})

QUIESCENT_ACTION_STATUSES: frozenset[str] = TERMINAL_ACTION_STATUSES | PARKED_ACTION_STATUSES

# Still moving under the pipeline's own power.
IN_FLIGHT_ACTION_STATUSES: frozenset[str] = frozenset(
    s.value for s in SoarActionStatus
) - QUIESCENT_ACTION_STATUSES

COMPLETED = "COMPLETED"
TIMEOUT = "TIMEOUT"

# Chosen from measured behaviour, not to make results pass — see
# docs/autonomous_soc_benchmark.md's methodology section. A single
# scenario settles in ~2-4s; the justification for the concurrent
# default lives with the concurrency probe, which passes its own value.
DEFAULT_SETTLE_TIMEOUT_SECONDS = 90
DEFAULT_POLL_INTERVAL_SECONDS = 2.0

# How long the workload must show no state change at all before that is
# worth recording as stall evidence. Long enough not to fire during
# normal provider latency (blocking TI calls run several seconds each).
DEFAULT_STABILITY_WINDOW_SECONDS = 30.0


def concurrency_settle_timeout(scenario_count: int) -> float:
    """
    How long a concurrent workload is allowed before it is called a
    timeout, scaled to the work being asked of the pipeline.

    Grounded in measurement, not chosen to make the probe pass: on this
    hardware one scenario settles in ~2.4s, and ten launched together
    settle in ~65s (each scenario is 6 alerts, and every alert becomes
    its own correlation task, so cost grows with the batch). The old
    fixed 60s window sat just below that 65s figure, which is exactly
    why it reported healthy workloads as stuck.

    60s of base plus 12s per scenario gives roughly 1.8x headroom over
    the measured figure at level 10 (180s) while still scaling with the
    level rather than being a single number that is too tight for large
    batches and uselessly loose for small ones. A workload that needs
    longer than this is reported as a TIMEOUT — that is a legitimate
    finding about performance, and the budget is deliberately not
    inflated to hide it.
    """
    return 60.0 + 12.0 * max(scenario_count, 0)


@dataclass
class SettlementResult:
    outcome: str
    settled: bool
    duration_seconds: float
    timeout_seconds: float

    incidents: list[str] = field(default_factory=list)
    runs_observed: int = 0
    actions_observed: int = 0
    terminal_actions: int = 0
    parked_actions: int = 0
    non_terminal_actions_at_timeout: list[str] = field(default_factory=list)
    run_statuses: dict[str, int] = field(default_factory=dict)
    action_statuses: dict[str, int] = field(default_factory=dict)

    # Stall evidence — recorded, never interpreted as proof of permanent
    # abandonment. See the module docstring.
    seconds_without_progress: float = 0.0
    worker_active_tasks_at_end: Optional[int] = None

    polls: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def non_terminal_count(self) -> int:
        return len(self.non_terminal_actions_at_timeout)

    def summary(self) -> str:
        if self.outcome == COMPLETED:
            return f"COMPLETED in {self.duration_seconds:.1f}s (max {self.timeout_seconds:.0f}s)"
        return (
            f"TIMEOUT after {self.duration_seconds:.1f}s (max {self.timeout_seconds:.0f}s); "
            f"{self.non_terminal_count} action(s) still in flight"
        )


def worker_active_task_count(container: str = "safe-soc-worker-1") -> Optional[int]:
    """
    How many tasks the worker says it is running.

    Corroborating evidence only. Note what this is NOT based on: the
    Celery broker queue depth, which was measured reading 0 while three
    tasks were actively executing, because Celery prefetches work off
    the queue into the worker. Treating an empty queue as "idle" would
    have manufactured exactly the false stranding verdict this module
    exists to avoid. Returns None when the worker cannot be asked, so an
    unmeasurable environment is reported as unknown rather than zero.
    """
    try:
        result = subprocess.run(
            ["docker", "exec", container, "celery", "-A", "app.tasks.celery_app", "inspect", "active"],
            capture_output=True, text=True, timeout=45,
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    return sum(1 for line in result.stdout.splitlines() if line.strip().startswith("*"))


def _snapshot(client, alert_ids: set[str], size: int = 200) -> tuple[list[dict], list[dict]]:
    """
    The workload, reached causally: the alerts this benchmark injected ->
    the incidents referencing them -> those incidents' runs and actions.

    Scoped this way rather than by querying globally so the detector can
    never wait on (or be confused by) the demo tenant, another
    benchmark's leftovers, or historical runs. The client is already
    authenticated as one benchmark tenant, so tenant isolation is
    enforced server-side on top of this.
    """
    incidents = [i for i in client.list_incidents(size=size) if alert_ids & set(i.get("alert_ids") or [])]
    runs = [run for incident in incidents for run in client.soar_runs_with_actions(incident["id"])]
    return incidents, runs


def _state_fingerprint(runs: list[dict]) -> tuple:
    """Everything that changes as the pipeline works, so 'no progress' is detectable."""
    return tuple(sorted((a["id"], a["status"]) for run in runs for a in run["actions"]))


def wait_for_settlement(
    client,
    alert_ids: set[str],
    *,
    expected_incidents: Optional[int] = None,
    expects_soar: bool = True,
    timeout_seconds: float = DEFAULT_SETTLE_TIMEOUT_SECONDS,
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
    stability_window_seconds: float = DEFAULT_STABILITY_WINDOW_SECONDS,
    worker_container: str = "safe-soc-worker-1",
) -> SettlementResult:
    """
    Poll the workload's durable state until it settles or the timeout
    elapses.

    Settlement is judged on ACTION state, not run state: a run legitimately
    stays RUNNING while one of its actions waits on an analyst, so requiring
    terminal runs would time out on a correctly-behaving pipeline.

    `expected_incidents` guards against declaring victory early — with
    nothing detected yet, zero actions are trivially "all quiescent". When
    given, that many incidents must exist before settlement can be
    declared.
    """
    started = time.monotonic()
    deadline = started + timeout_seconds

    incidents: list[dict] = []
    runs: list[dict] = []
    result = SettlementResult(
        outcome=TIMEOUT, settled=False, duration_seconds=0.0, timeout_seconds=timeout_seconds
    )

    last_fingerprint: Optional[tuple] = None
    last_change_at = started

    while True:
        try:
            incidents, runs = _snapshot(client, alert_ids)
            result.polls += 1
        except Exception as e:  # noqa: BLE001
            result.errors.append(f"poll failed: {e}")
            time.sleep(poll_interval_seconds)
            if time.monotonic() >= deadline:
                break
            continue

        fingerprint = _state_fingerprint(runs)
        if fingerprint != last_fingerprint:
            last_fingerprint = fingerprint
            last_change_at = time.monotonic()

        actions = [a for run in runs for a in run["actions"]]
        in_flight = [a for a in actions if a["status"] in IN_FLIGHT_ACTION_STATUSES]

        incidents_ready = expected_incidents is None or len(incidents) >= expected_incidents
        # A workload that triggers no SOAR at all settles as soon as its
        # incidents exist; requiring actions would never be satisfied.
        work_present = bool(runs) if expects_soar else True

        if incidents_ready and work_present and not in_flight:
            result.outcome = COMPLETED
            result.settled = True
            break

        if time.monotonic() >= deadline:
            break

        time.sleep(poll_interval_seconds)

    result.duration_seconds = time.monotonic() - started
    result.seconds_without_progress = time.monotonic() - last_change_at
    result.incidents = [i["id"] for i in incidents]
    result.runs_observed = len(runs)

    actions = [a for run in runs for a in run["actions"]]
    result.actions_observed = len(actions)
    result.terminal_actions = sum(1 for a in actions if a["status"] in TERMINAL_ACTION_STATUSES)
    result.parked_actions = sum(1 for a in actions if a["status"] in PARKED_ACTION_STATUSES)
    result.non_terminal_actions_at_timeout = [
        f"{a['action_type']}={a['status']}" for a in actions if a["status"] in IN_FLIGHT_ACTION_STATUSES
    ]

    for run in runs:
        result.run_statuses[run["status"]] = result.run_statuses.get(run["status"], 0) + 1
    for action in actions:
        result.action_statuses[action["status"]] = result.action_statuses.get(action["status"], 0) + 1

    # Only worth the subprocess cost when something is unresolved, and
    # only ever as evidence a reader can weigh.
    if not result.settled:
        result.worker_active_tasks_at_end = worker_active_task_count(worker_container)

    return result


def stall_evidence(result: SettlementResult, stability_window_seconds: float = DEFAULT_STABILITY_WINDOW_SECONDS) -> str:
    """
    A sentence describing what was actually observed at timeout — never
    a verdict of permanent stranding, which this architecture cannot
    prove from the outside.
    """
    if result.settled:
        return "workload settled; no unresolved actions"
    if not result.non_terminal_actions_at_timeout:
        return "timed out before the expected workload appeared; no actions were left in flight"

    parts = [
        f"{result.non_terminal_count} action(s) still in flight when the {result.timeout_seconds:.0f}s limit elapsed"
    ]
    if result.seconds_without_progress >= stability_window_seconds:
        parts.append(f"no state change for {result.seconds_without_progress:.0f}s")
    else:
        parts.append(f"state last changed {result.seconds_without_progress:.0f}s ago, so the pipeline was still progressing")
    if result.worker_active_tasks_at_end is None:
        parts.append("worker activity could not be sampled")
    else:
        parts.append(f"worker reported {result.worker_active_tasks_at_end} active task(s)")
    return "; ".join(parts) + ". Not evidence of permanent stranding."
