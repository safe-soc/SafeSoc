"""
SafeSOC — Benchmark Scenario Ground-Truth Tests (Phase 4)
A benchmark is only worth running if its expectations match the system
it grades. These tests re-derive every expectation in
core/benchmark_scenarios.py from the REAL detectors
(services/correlation.py), the REAL playbook catalog
(core/soar_playbooks.py), the REAL autonomy policy
(core/soar_policy.py) and the REAL MITRE mapping
(core/mitre_mapping.py) — so a scenario that quietly drifts from the
implementation fails here rather than producing a flattering
scorecard.

The strongest test in this file is
test_each_scenarios_injector_events_actually_trigger_its_expected_patterns:
it pushes the injector's own generated events through the actual
detector functions and the actual match_playbook(), which is the only
way to know an expectation is reachable rather than aspirational.
"""

import sys
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from injector.injector import SCENARIOS, generate_log  # noqa: E402

from app.core.benchmark_scenarios import (  # noqa: E402
    BENCHMARK_SCENARIOS,
    BenchmarkScenario,
    TelemetryDegradation,
    get_scenario,
    validate_scenarios,
)
from app.core.enums import AutonomyClass, CorrelationPattern, SoarActionType  # noqa: E402
from app.core.mitre_mapping import get_mitre_technique  # noqa: E402
from app.core.soar_playbooks import EvidenceField, get_playbook, match_playbook  # noqa: E402
from app.core.soar_policy import classify  # noqa: E402
from app.services import correlation  # noqa: E402

DETECTING_SCENARIOS = [s for s in BENCHMARK_SCENARIOS if s.expects_detection]


def _to_window_events(events: list[dict]) -> list[dict]:
    """The same shape workers/correlation_worker.py::add_event stores per alert — mirrors test_injector_scenarios.py's helper."""
    return [
        {
            "alert_id": str(uuid.uuid4()),
            "log_type": event["log_type"],
            "action": event["action"],
            "severity": event["severity"],
            "destination_ip": event.get("destination_ip"),
        }
        for event in events
    ]


def _scenario_events(scenario: BenchmarkScenario, host: str = "BENCH-HOST-01") -> list[dict]:
    """
    Build a scenario's telemetry exactly as the runner does: the
    injector's own generator, then the declared degradation. Kept in
    step with benchmarks/runner.py — see that module's build_events().
    """
    if scenario.injector_scenario == "benign_single_failed_login":
        event = generate_log(log_type="authentication", severity="low", host_id=host)
        event["action"] = "failed_login"
        events = [event]
    else:
        events = SCENARIOS[scenario.injector_scenario](host)

    if scenario.degradation == TelemetryDegradation.STRIP_IP_ADDRESSES:
        events = [{k: v for k, v in e.items() if k not in ("source_ip", "destination_ip")} for e in events]
    return events


# ── The definitions are internally coherent ─────────────────────────

def test_validate_scenarios_passes():
    validate_scenarios()  # also runs at import time; explicit here so a failure names this test


def test_scenario_ids_are_unique_and_addressable():
    ids = [s.id for s in BENCHMARK_SCENARIOS]
    assert len(ids) == len(set(ids))
    for scenario_id in ids:
        assert get_scenario(scenario_id) is not None
    assert get_scenario("bm-does-not-exist") is None


def test_the_suite_covers_at_least_six_scenarios():
    """Phase 4's own bar. Not a arbitrary number — below this the suite stops covering the platform."""
    assert len(BENCHMARK_SCENARIOS) >= 6


def test_the_suite_covers_detection_restraint_degradation_and_isolation():
    """Coverage of the four behaviours that actually distinguish a SOC agent from a log viewer."""
    assert any(s.expects_detection for s in BENCHMARK_SCENARIOS)
    assert any(not s.expects_detection for s in BENCHMARK_SCENARIOS), "no restraint scenario"
    assert any(s.degradation != TelemetryDegradation.NONE for s in BENCHMARK_SCENARIOS), "no degraded-telemetry scenario"
    assert any(s.tenant_isolation_check for s in BENCHMARK_SCENARIOS), "no tenant-isolation scenario"


# ── Expectations match the real catalog / policy / mapping ──────────

@pytest.mark.parametrize("scenario", BENCHMARK_SCENARIOS, ids=lambda s: s.id)
def test_every_expected_playbook_exists_in_the_real_catalog(scenario):
    for playbook_id in scenario.expected_playbooks:
        assert get_playbook(playbook_id) is not None, f"{scenario.id} expects unknown playbook {playbook_id}"


@pytest.mark.parametrize("scenario", BENCHMARK_SCENARIOS, ids=lambda s: s.id)
def test_expected_playbooks_are_triggered_by_the_expected_patterns(scenario):
    """Each expected playbook's own trigger pattern must be one this scenario claims to detect."""
    for playbook_id in scenario.expected_playbooks:
        playbook = get_playbook(playbook_id)
        assert playbook.trigger.pattern in scenario.expected_patterns, (
            f"{scenario.id} expects {playbook_id}, which triggers on {playbook.trigger.pattern.value}, "
            f"but that pattern isn't in expected_patterns"
        )


@pytest.mark.parametrize("scenario", BENCHMARK_SCENARIOS, ids=lambda s: s.id)
def test_declared_actions_are_exactly_the_steps_of_the_expected_playbooks(scenario):
    """
    No missing and no invented actions: the union of automatic +
    approval + skipped must equal the union of the expected playbooks'
    real steps.
    """
    catalog_actions = {
        step.action_type
        for playbook_id in scenario.expected_playbooks
        for step in get_playbook(playbook_id).steps
    }
    declared = set(scenario.all_expected_actions) | set(scenario.expected_skipped_actions)
    assert declared == catalog_actions, (
        f"{scenario.id}: declared {sorted(a.value for a in declared)} != catalog "
        f"{sorted(a.value for a in catalog_actions)}"
    )


@pytest.mark.parametrize("scenario", BENCHMARK_SCENARIOS, ids=lambda s: s.id)
def test_declared_autonomy_matches_the_real_policy(scenario):
    for action_type in scenario.expected_automatic_actions:
        assert classify(action_type) == AutonomyClass.AUTOMATIC
    for action_type in scenario.expected_approval_actions:
        assert classify(action_type) == AutonomyClass.APPROVAL_REQUIRED


@pytest.mark.parametrize("scenario", BENCHMARK_SCENARIOS, ids=lambda s: s.id)
def test_mitre_is_derived_from_the_product_mapping_not_authored(scenario):
    expected = []
    for pattern in scenario.expected_patterns:
        for technique_id in get_mitre_technique(pattern).technique_ids:
            if technique_id not in expected:
                expected.append(technique_id)
    assert list(scenario.mitre_techniques) == expected


def test_no_scenario_invents_a_mitre_technique():
    """Every technique the suite reports must exist in core/mitre_mapping.py — nothing hand-written."""
    known = {t for technique in get_mitre_technique.__globals__["MITRE_PATTERN_MAPPING"].values() for t in technique.technique_ids}
    for scenario in BENCHMARK_SCENARIOS:
        assert set(scenario.mitre_techniques) <= known


# ── Expectations are reachable through the REAL detectors ───────────

@pytest.mark.parametrize("scenario", DETECTING_SCENARIOS, ids=lambda s: s.id)
def test_each_scenarios_injector_events_actually_trigger_its_expected_patterns(scenario):
    """
    The load-bearing test: run the scenario's real generated telemetry
    through the real detectors and assert the patterns it claims are
    the patterns that actually come out. An expectation that can't be
    reached is a broken benchmark, not a system failure.
    """
    events = _to_window_events(_scenario_events(scenario))
    chains = [
        chain
        for chain in (detector(events, "bench-tenant", "BENCH-HOST-01") for detector in correlation.DETECTORS)
        if chain is not None
    ]
    detected = {chain.pattern for chain in chains}
    assert detected == set(scenario.expected_patterns), (
        f"{scenario.id}: detectors produced {sorted(p.value for p in detected)}, "
        f"expected {sorted(p.value for p in scenario.expected_patterns)}"
    )


@pytest.mark.parametrize("scenario", DETECTING_SCENARIOS, ids=lambda s: s.id)
def test_detected_confidence_actually_clears_each_expected_playbooks_trigger(scenario):
    """
    A pattern being detected isn't enough — the confidence has to clear
    that playbook's own min_confidence, or no run is ever created. This
    catches an expectation that is one threshold short of real.
    """
    events = _to_window_events(_scenario_events(scenario))
    chains = {
        chain.pattern: chain
        for chain in (detector(events, "bench-tenant", "BENCH-HOST-01") for detector in correlation.DETECTORS)
        if chain is not None
    }
    for playbook_id in scenario.expected_playbooks:
        playbook = get_playbook(playbook_id)
        chain = chains[playbook.trigger.pattern]
        matched = match_playbook(chain.pattern, chain.confidence)
        assert matched is not None and matched.id == playbook_id, (
            f"{scenario.id}: {chain.pattern.value} at confidence {chain.confidence:.2f} did not match {playbook_id} "
            f"(needs >= {playbook.trigger.min_confidence})"
        )


def test_the_benign_scenario_really_produces_no_detection():
    """
    Restraint, proven against the real detectors rather than asserted.
    If this ever fails, the thresholds changed — the fix is to discuss
    the threshold, never to loosen this expectation.
    """
    benign = next(s for s in BENCHMARK_SCENARIOS if not s.expects_detection)
    events = _to_window_events(_scenario_events(benign))
    chains = [d(events, "bench-tenant", "BENCH-HOST-01") for d in correlation.DETECTORS]
    assert all(chain is None for chain in chains)
    assert benign.expected_incidents == 0


# ── The degraded-telemetry scenario is degraded in the way it claims ─

def test_the_incomplete_evidence_scenario_really_has_no_ip_fields():
    scenario = next(s for s in BENCHMARK_SCENARIOS if s.degradation == TelemetryDegradation.STRIP_IP_ADDRESSES)
    for event in _scenario_events(scenario):
        assert "source_ip" not in event
        assert "destination_ip" not in event


def test_the_skipped_action_is_exactly_the_one_needing_the_stripped_evidence():
    """
    The skip expectation must follow from the playbook definition: the
    skipped steps are precisely those drawing on PRIMARY_IP, which is
    what the degradation removes.
    """
    scenario = next(s for s in BENCHMARK_SCENARIOS if s.degradation == TelemetryDegradation.STRIP_IP_ADDRESSES)
    ip_dependent = {
        step.action_type
        for playbook_id in scenario.expected_playbooks
        for step in get_playbook(playbook_id).steps
        if step.parameter_field == EvidenceField.PRIMARY_IP
    }
    assert set(scenario.expected_skipped_actions) == ip_dependent
    assert ip_dependent, "the degradation would prove nothing if no expected step used PRIMARY_IP"


def test_undegraded_scenarios_skip_nothing():
    for scenario in BENCHMARK_SCENARIOS:
        if scenario.degradation == TelemetryDegradation.NONE:
            assert scenario.expected_skipped_actions == ()


# ── Telemetry generation reuses the injector ────────────────────────

@pytest.mark.parametrize("scenario", BENCHMARK_SCENARIOS, ids=lambda s: s.id)
def test_every_scenario_resolves_to_real_generated_telemetry(scenario):
    events = _scenario_events(scenario)
    assert events, f"{scenario.id} generated no events"
    for event in events:
        # The fields the ingestion pipeline requires of every log.
        for required in ("log_type", "action", "severity", "host_id", "timestamp", "description"):
            assert required in event, f"{scenario.id} event missing {required}"


def test_named_injector_scenarios_come_from_the_injectors_own_registry():
    """Telemetry is generated by the injector, not reimplemented — except the one benign case it has no entry for."""
    for scenario in BENCHMARK_SCENARIOS:
        if scenario.injector_scenario and scenario.injector_scenario != "benign_single_failed_login":
            assert scenario.injector_scenario in SCENARIOS
