"""
SafeSOC — SOAR Autonomy Policy Tests
classify() is the sole authority for AUTOMATIC vs APPROVAL_REQUIRED —
these tests prove it's complete (every SoarActionType is classified),
correct against the approved taxonomy, and fails closed for anything
outside the closed enum.
"""

import pytest

from app.core.enums import AutonomyClass, SoarActionType
from app.core.soar_policy import ACTION_AUTONOMY, UnclassifiedSoarActionError, classify, is_automatic, requires_approval

_EXPECTED_AUTOMATIC = {
    SoarActionType.COLLECT_ADDITIONAL_EVIDENCE,
    SoarActionType.CREATE_INVESTIGATION_ACTION,
    SoarActionType.ENRICH_INDICATOR,
    SoarActionType.ADD_INCIDENT_NOTE,
    SoarActionType.INCREASE_INCIDENT_PRIORITY,
}

_EXPECTED_APPROVAL_REQUIRED = {
    SoarActionType.ISOLATE_ENDPOINT,
    SoarActionType.DISABLE_ACCOUNT,
    SoarActionType.BLOCK_INDICATOR,
    SoarActionType.TERMINATE_PROCESS,
    SoarActionType.REVOKE_CREDENTIALS,
}


def test_every_soar_action_type_is_classified():
    assert set(ACTION_AUTONOMY.keys()) == set(SoarActionType)


def test_automatic_actions_match_the_approved_taxonomy():
    automatic = {action for action, cls in ACTION_AUTONOMY.items() if cls == AutonomyClass.AUTOMATIC}
    assert automatic == _EXPECTED_AUTOMATIC


def test_approval_required_actions_match_the_approved_taxonomy():
    gated = {action for action, cls in ACTION_AUTONOMY.items() if cls == AutonomyClass.APPROVAL_REQUIRED}
    assert gated == _EXPECTED_APPROVAL_REQUIRED


def test_autonomy_class_has_no_never_autonomous_member():
    """The safety guarantee is structural: there is no third AutonomyClass value at all."""
    assert set(AutonomyClass) == {AutonomyClass.AUTOMATIC, AutonomyClass.APPROVAL_REQUIRED}


@pytest.mark.parametrize("action_type", sorted(_EXPECTED_AUTOMATIC, key=lambda a: a.value))
def test_classify_returns_automatic_for_each_automatic_action(action_type):
    assert classify(action_type) == AutonomyClass.AUTOMATIC
    assert is_automatic(action_type) is True
    assert requires_approval(action_type) is False


@pytest.mark.parametrize("action_type", sorted(_EXPECTED_APPROVAL_REQUIRED, key=lambda a: a.value))
def test_classify_returns_approval_required_for_each_gated_action(action_type):
    assert classify(action_type) == AutonomyClass.APPROVAL_REQUIRED
    assert is_automatic(action_type) is False
    assert requires_approval(action_type) is True


def test_classify_fails_closed_for_an_unclassified_value():
    """
    A raw string outside SoarActionType's own members can still reach
    classify() from a poorly-behaved caller (str, Enum equality/hash
    quirks aside) — it must raise, never silently default to either class.
    """
    with pytest.raises(UnclassifiedSoarActionError):
        classify("delete_evidence")  # not a SoarActionType member at all


def test_classify_is_pure_and_deterministic():
    results = {classify(SoarActionType.ISOLATE_ENDPOINT) for _ in range(5)}
    assert results == {AutonomyClass.APPROVAL_REQUIRED}
