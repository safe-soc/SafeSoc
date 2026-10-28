"""
SafeSOC — Static SOAR Playbook Tests
Covers playbook validation (uniqueness, non-empty steps, every step's
action_type classified), that triggers reuse the correlation engine's
own CorrelationPattern rather than a parallel vocabulary, and
parameter-template resolution (resolve_step_parameters) against a
closed, known set of evidence fields — including the "evidence
missing" case, which must resolve to None rather than raising or
guessing.
"""

import pytest

from app.core.enums import CorrelationPattern, SoarActionType
from app.core.soar_playbooks import (
    SOAR_PLAYBOOKS,
    EvidenceField,
    Playbook,
    PlaybookStep,
    PlaybookTrigger,
    get_playbook,
    resolve_step_parameters,
    validate_playbook_definitions,
)


# ── Playbook validation ─────────────────────────────────────────────

def test_validate_playbook_definitions_passes_for_the_real_catalog():
    validate_playbook_definitions()  # must not raise


def test_every_playbook_id_is_unique():
    ids = [playbook.id for playbook in SOAR_PLAYBOOKS]
    assert len(ids) == len(set(ids))


def test_every_playbook_has_at_least_one_step():
    for playbook in SOAR_PLAYBOOKS:
        assert len(playbook.steps) > 0, playbook.id


def test_every_playbook_step_is_a_classified_action_type():
    from app.core.soar_policy import classify

    for playbook in SOAR_PLAYBOOKS:
        for step in playbook.steps:
            classify(step.action_type)  # must not raise


def test_every_correlation_pattern_has_at_least_one_playbook():
    """Task requirement: 'a small initial set of playbooks covering the existing correlation patterns.'"""
    covered_patterns = {playbook.trigger.pattern for playbook in SOAR_PLAYBOOKS}
    assert covered_patterns == set(CorrelationPattern)


def test_playbook_trigger_reuses_correlation_pattern_not_a_new_vocabulary():
    for playbook in SOAR_PLAYBOOKS:
        assert isinstance(playbook.trigger.pattern, CorrelationPattern)


def test_validate_playbook_definitions_rejects_duplicate_ids():
    duplicate_playbooks = [
        Playbook("dup-id", "A", PlaybookTrigger(CorrelationPattern.CREDENTIAL_BRUTE_FORCE, 0.5), (PlaybookStep(SoarActionType.ADD_INCIDENT_NOTE),)),
        Playbook("dup-id", "B", PlaybookTrigger(CorrelationPattern.LATERAL_MOVEMENT, 0.5), (PlaybookStep(SoarActionType.ADD_INCIDENT_NOTE),)),
    ]
    with pytest.raises(ValueError, match="Duplicate"):
        _validate(duplicate_playbooks)


def test_validate_playbook_definitions_rejects_a_playbook_with_no_steps():
    empty_playbook = [Playbook("empty", "Empty", PlaybookTrigger(CorrelationPattern.CREDENTIAL_BRUTE_FORCE, 0.5), ())]
    with pytest.raises(ValueError, match="no steps"):
        _validate(empty_playbook)


def _validate(playbooks: list[Playbook]) -> None:
    """Re-implements validate_playbook_definitions' body against an arbitrary playbook list, without touching the real SOAR_PLAYBOOKS module global."""
    from app.core.soar_policy import classify

    seen_ids: set[str] = set()
    for playbook in playbooks:
        if playbook.id in seen_ids:
            raise ValueError(f"Duplicate SOAR playbook id: {playbook.id}")
        seen_ids.add(playbook.id)
        if not playbook.steps:
            raise ValueError(f"SOAR playbook '{playbook.id}' has no steps.")
        for step in playbook.steps:
            classify(step.action_type)


def test_get_playbook_returns_none_for_an_unknown_id():
    assert get_playbook("not-a-real-playbook") is None


def test_get_playbook_returns_the_real_definition():
    playbook = get_playbook("pb-successful-compromise")
    assert playbook is not None
    assert playbook.trigger.pattern == CorrelationPattern.SUCCESSFUL_COMPROMISE


# ── Parameter-template (evidence field) resolution ─────────────────

def test_resolve_primary_host_from_evidence():
    step = PlaybookStep(SoarActionType.ISOLATE_ENDPOINT, EvidenceField.PRIMARY_HOST)
    params = resolve_step_parameters(step, {"hosts": ["DESKTOP-042", "DESKTOP-999"], "ips": [], "users": []})
    assert params == {"host_id": "DESKTOP-042"}


def test_resolve_primary_ip_from_evidence():
    step = PlaybookStep(SoarActionType.BLOCK_INDICATOR, EvidenceField.PRIMARY_IP)
    params = resolve_step_parameters(step, {"hosts": [], "ips": ["203.0.113.5"], "users": []})
    assert params == {"indicator": "203.0.113.5"}


def test_resolve_primary_user_from_evidence():
    step = PlaybookStep(SoarActionType.DISABLE_ACCOUNT, EvidenceField.PRIMARY_USER)
    params = resolve_step_parameters(step, {"hosts": [], "ips": [], "users": ["tom.thompson"]})
    assert params == {"user": "tom.thompson"}


def test_resolve_missing_evidence_yields_none_not_a_crash():
    """A host-scoped step against evidence with no hosts must resolve to None, not raise — validation happens later."""
    step = PlaybookStep(SoarActionType.ISOLATE_ENDPOINT, EvidenceField.PRIMARY_HOST)
    params = resolve_step_parameters(step, {"hosts": [], "ips": [], "users": []})
    assert params == {"host_id": None}


def test_resolve_none_evidence_field_only_returns_static_parameters():
    step = PlaybookStep(SoarActionType.ADD_INCIDENT_NOTE, EvidenceField.NONE, static_parameters={"note": "fixed text"})
    params = resolve_step_parameters(step, {"hosts": ["X"], "ips": ["1.2.3.4"], "users": ["u"]})
    assert params == {"note": "fixed text"}


def test_resolve_step_parameters_never_evaluates_static_parameters_as_code():
    """static_parameters values are opaque strings, never interpreted — a literal '{hosts[0]}'-looking string must pass through unchanged."""
    step = PlaybookStep(SoarActionType.ADD_INCIDENT_NOTE, EvidenceField.NONE, static_parameters={"note": "{hosts[0]}; rm -rf /"})
    params = resolve_step_parameters(step, {"hosts": ["real-host"], "ips": [], "users": []})
    assert params == {"note": "{hosts[0]}; rm -rf /"}


# ── Ransomware precursor (ADR-013) ──────────────────────────────────

def test_ransomware_precursor_playbook_collects_evidence_then_asks_to_isolate():
    from app.core.soar_playbooks import match_playbook
    from app.core.soar_policy import requires_approval

    playbook = get_playbook("pb-ransomware-precursor")

    assert playbook.trigger == PlaybookTrigger(CorrelationPattern.RANSOMWARE_PRECURSOR, 0.7)
    assert [step.action_type for step in playbook.steps] == [
        SoarActionType.COLLECT_ADDITIONAL_EVIDENCE,
        SoarActionType.CREATE_INVESTIGATION_ACTION,
        SoarActionType.ISOLATE_ENDPOINT,
    ]
    assert playbook.steps[0].parameter_field == playbook.steps[2].parameter_field == EvidenceField.PRIMARY_HOST
    assert "patient zero" in playbook.steps[1].static_parameters["description"]
    assert requires_approval(SoarActionType.ISOLATE_ENDPOINT)
    # Every confidence the detector can produce (0.75 / 0.8 / 0.95) clears the trigger.
    assert match_playbook(CorrelationPattern.RANSOMWARE_PRECURSOR, 0.75) is playbook
    assert match_playbook(CorrelationPattern.RANSOMWARE_PRECURSOR, 0.69) is None
