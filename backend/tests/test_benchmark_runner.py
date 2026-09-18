"""
SafeSOC — Benchmark Runner Logic Tests (Phase 4)
The runner's pure parts: how telemetry is degraded, when the pipeline
counts as settled, how a scenario is graded, and — the part most
capable of quietly lying — how rates are computed. A scorecard that
renders an undefined rate as 0% or 100% would misreport the autonomy
guarantee, so that behaviour is pinned here.

The benchmarks package lives at the repository root, outside the
backend image. These tests skip rather than fail where it isn't
importable (e.g. the Docker test overlay, which mounts injector/ and
ml/ but not benchmarks/).
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

runner = pytest.importorskip("benchmarks.runner", reason="benchmarks package not mounted in this environment")

from app.core.benchmark_scenarios import BENCHMARK_SCENARIOS, TelemetryDegradation, get_scenario  # noqa: E402


# ── Rates: N/A, never a fabricated 0% or 100% ───────────────────────

def test_rate_with_an_empty_denominator_is_none_not_zero():
    """
    The distinction that matters: "no approval-required actions existed"
    must not render as "0% of them were gated", which would read as a
    total failure of the gate.
    """
    assert runner._rate(0, 0) is None
    assert runner._rate(5, 0) is None


@pytest.mark.parametrize(
    "numerator,denominator,expected",
    [(0, 4, 0.0), (2, 4, 0.5), (4, 4, 1.0)],
)
def test_rate_computes_normally_with_a_real_denominator(numerator, denominator, expected):
    assert runner._rate(numerator, denominator) == expected


def test_median_of_nothing_is_none():
    assert runner._median([]) is None
    assert runner._median([2.0, 4.0, 6.0]) == 4.0


def test_scorecard_on_an_empty_run_reports_na_rather_than_perfect_scores():
    """An empty benchmark must not look like a flawless one."""
    scorecard = runner.soar_scorecard([])

    assert scorecard["actions_created"] == 0
    for rate in ("automatic_execution_rate", "approval_gate_enforcement_rate", "verification_success_rate"):
        assert scorecard[rate] is None, f"{rate} should be N/A with no data"


def _action(action_type="isolate_endpoint", autonomy="approval_required", status="awaiting_approval",
            verification="not_verified", approved_at=None, executed_at=None, verified_at=None):
    return runner.ActionOutcome(
        action_type=action_type, autonomy_class=autonomy, status=status, verification_status=verification,
        executed_at=executed_at, verified_at=verified_at, approved_at=approved_at, result_success=None,
    )


def _result(actions=(), skipped=(), runs=()):
    result = runner.ScenarioResult(scenario_id="x", name="x", tenant_id="t", host="h")
    result.actions = list(actions)
    result.skipped = list(skipped)
    result.runs = list(runs)
    return result


def test_scorecard_counts_a_gated_action_as_enforced():
    result = _result(actions=[_action(status="awaiting_approval")])

    scorecard = runner.soar_scorecard([result])

    assert scorecard["actions_approval_required"] == 1
    assert scorecard["approval_gate_enforcement_rate"] == 1.0


def test_scorecard_counts_an_unapproved_execution_as_a_gate_failure():
    """The scorecard must be capable of reporting a violation, or it proves nothing."""
    result = _result(actions=[_action(status="succeeded", approved_at=None)])

    scorecard = runner.soar_scorecard([result])

    assert scorecard["approval_gate_enforcement_rate"] == 0.0


def test_scorecard_treats_an_approved_execution_as_correctly_gated():
    from datetime import datetime, timezone

    approved = datetime.now(timezone.utc)
    result = _result(actions=[_action(status="succeeded", approved_at=approved)])

    assert runner.soar_scorecard([result])["approval_gate_enforcement_rate"] == 1.0


def test_scorecard_groups_skipped_actions_by_reason():
    result = _result(skipped=[
        {"action_type": "enrich_indicator", "reason": "required_evidence_unavailable"},
        {"action_type": "block_indicator", "reason": "required_evidence_unavailable"},
        {"action_type": "block_indicator", "reason": "parameter_validation_failed"},
    ])

    scorecard = runner.soar_scorecard([result])

    assert scorecard["actions_skipped"] == 3
    assert scorecard["skipped_by_reason"] == {
        "required_evidence_unavailable": 2,
        "parameter_validation_failed": 1,
    }


# ── Settling ────────────────────────────────────────────────────────
#
# Quiescence moved out of the runner into benchmarks/settlement.py,
# which derives the terminal statuses from the product's own state
# machine instead of restating them. These assert the same behaviour
# against its status sets.

settlement = pytest.importorskip("benchmarks.settlement", reason="benchmarks package not mounted in this environment")


@pytest.mark.parametrize("status", ["pending", "approved", "executing"])
def test_an_action_still_moving_is_not_quiescent(status):
    assert status in settlement.IN_FLIGHT_ACTION_STATUSES
    assert status not in settlement.QUIESCENT_ACTION_STATUSES


@pytest.mark.parametrize("status", ["succeeded", "failed", "rejected", "awaiting_approval"])
def test_terminal_or_parked_actions_count_as_quiescent(status):
    """Awaiting approval counts as settled: it is waiting on a human, not on the pipeline."""
    assert status in settlement.QUIESCENT_ACTION_STATUSES
    assert status not in settlement.IN_FLIGHT_ACTION_STATUSES


def test_terminal_statuses_come_from_the_products_own_state_machine():
    """
    Not restated in the benchmark: if the SOAR state machine ever gains
    or loses a terminal status, the settlement detector follows it
    rather than silently grading against a stale copy.
    """
    from app.services.soar import _TERMINAL_ACTION_STATUSES

    assert settlement.TERMINAL_ACTION_STATUSES == {s.value for s in _TERMINAL_ACTION_STATUSES}


def test_awaiting_approval_is_parked_but_not_terminal():
    """The distinction that makes the benchmark honest: parked is settled, but it is not an outcome."""
    assert "awaiting_approval" in settlement.PARKED_ACTION_STATUSES
    assert "awaiting_approval" not in settlement.TERMINAL_ACTION_STATUSES


# ── Telemetry degradation ───────────────────────────────────────────

def test_degradation_strips_both_ip_fields_and_leaves_the_rest_intact():
    scenario = next(s for s in BENCHMARK_SCENARIOS if s.degradation == TelemetryDegradation.STRIP_IP_ADDRESSES)

    events = runner.build_events(scenario, "BM-TEST-01")

    assert events
    for event in events:
        assert "source_ip" not in event and "destination_ip" not in event
        assert event["host_id"] == "BM-TEST-01"
        assert event["action"] and event["severity"]


def test_undegraded_scenarios_keep_their_ip_evidence():
    scenario = get_scenario("bm-b-successful-compromise")

    events = runner.build_events(scenario, "BM-TEST-02")

    assert any(e.get("source_ip") for e in events), "the un-degraded twin must carry the evidence F removes"


def test_the_benign_scenario_builds_exactly_one_failed_login():
    events = runner.build_events(get_scenario("bm-g-benign-activity"), "BM-TEST-03")

    assert len(events) == 1
    assert events[0]["action"] == "failed_login"


# ── Grading ─────────────────────────────────────────────────────────

def test_a_restraint_scenario_passes_only_when_no_incident_appeared():
    scenario = get_scenario("bm-g-benign-activity")

    clean = runner.evaluate(_result(), scenario)
    assert clean.passed

    noisy = _result()
    noisy.incident_id = "an-incident-that-should-not-exist"
    assert not runner.evaluate(noisy, scenario).passed


def test_grading_fails_when_an_approval_action_executed_without_approval():
    """The single most important thing this benchmark can detect."""
    scenario = get_scenario("bm-b-successful-compromise")
    result = _result(actions=[_action(status="succeeded", approved_at=None)])
    result.incident_id = "incident-1"
    result.detected_category = "successful_compromise"

    graded = runner.evaluate(result, scenario)

    failed = [name for name, ok, _ in graded.checks if not ok]
    assert "no approval-required action executed without approval" in failed
    assert not graded.passed


# ── Timeline skip parsing ───────────────────────────────────────────
#
# Regression: the first version of this read the timeline entry's outer
# payload instead of its `details`, so every skip arrived with no
# action_type and the degraded-telemetry scenario was graded as having
# skipped nothing — a benchmark bug that looked exactly like a product
# failure.

def _skip_entry(action_type="enrich_indicator", reason="required_evidence_unavailable"):
    return {
        "type": "audit",
        "timestamp": "2026-09-07T10:00:00Z",
        "data": {
            "action": "soar.action.skipped",
            "actor_user_id": None,
            "details": {"action_type": action_type, "reason": reason, "detail": "primary_ip"},
        },
    }


def test_skip_extraction_reads_the_nested_details_not_the_outer_payload():
    skips = runner.extract_skips([_skip_entry()])

    assert len(skips) == 1
    assert skips[0]["action_type"] == "enrich_indicator"
    assert skips[0]["reason"] == "required_evidence_unavailable"


def test_skip_extraction_ignores_other_soar_lifecycle_events():
    entries = [
        _skip_entry(),
        {"type": "audit", "timestamp": "t", "data": {"action": "soar.action.succeeded", "details": {}}},
        {"type": "audit", "timestamp": "t", "data": {"action": "soar.playbook.triggered", "details": {}}},
    ]

    assert len(runner.extract_skips(entries)) == 1


def test_skip_extraction_survives_an_entry_with_no_details():
    entries = [{"type": "audit", "timestamp": "t", "data": {"action": "soar.action.skipped"}}]

    assert runner.extract_skips(entries) == [{}]
