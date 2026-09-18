"""
SafeSOC — SOAR Autonomy Policy
The single, deterministic authority for which SoarActionType values
may execute without a human in the loop (AUTOMATIC) and which require
an explicit analyst approval first (APPROVAL_REQUIRED). This is a
policy engine, not a model: no LLM call, no randomness, no I/O — the
same action_type always yields the same classification.

Deliberately excludes any "never autonomous" action entirely: delete-
evidence, delete-account, destructive-filesystem, and irreversible-
production-change actions are not SoarActionType members at all (see
core/enums.py), so there is no enum value for this policy, an AI
recommendation, or a malicious API caller to even target. The
guarantee is structural — nothing in the type system can construct a
SoarActionExecution for one of these — not a runtime denylist a future
bug could route around.

classify() fails closed: an action_type this module hasn't explicitly
classified raises rather than defaulting to either AUTOMATIC (unsafe)
or APPROVAL_REQUIRED (silently wrong, masks a real bug). Every member
of SoarActionType is classified below; the only way to hit the
failure path is adding a new SoarActionType without a matching policy
entry, which is exactly the mistake this should catch immediately
(core/soar_playbooks.py's validate_playbook_definitions() also calls
classify() on every step at import time, so a gap here breaks the
test suite at collection, not at request time).
"""

from app.core.enums import AutonomyClass, SoarActionType

ACTION_AUTONOMY: dict[SoarActionType, AutonomyClass] = {
    # AUTOMATIC — safe to execute without a human in the loop: reversible,
    # non-disruptive, or purely additive (evidence, notes, priority).
    SoarActionType.COLLECT_ADDITIONAL_EVIDENCE: AutonomyClass.AUTOMATIC,
    SoarActionType.CREATE_INVESTIGATION_ACTION: AutonomyClass.AUTOMATIC,
    SoarActionType.ENRICH_INDICATOR: AutonomyClass.AUTOMATIC,
    SoarActionType.ADD_INCIDENT_NOTE: AutonomyClass.AUTOMATIC,
    SoarActionType.INCREASE_INCIDENT_PRIORITY: AutonomyClass.AUTOMATIC,
    # APPROVAL_REQUIRED — has a real, potentially disruptive effect on a
    # user, endpoint, or network; an analyst must explicitly approve it
    # (services/soar.py's state machine) before it can execute.
    SoarActionType.ISOLATE_ENDPOINT: AutonomyClass.APPROVAL_REQUIRED,
    SoarActionType.DISABLE_ACCOUNT: AutonomyClass.APPROVAL_REQUIRED,
    SoarActionType.BLOCK_INDICATOR: AutonomyClass.APPROVAL_REQUIRED,
    SoarActionType.TERMINATE_PROCESS: AutonomyClass.APPROVAL_REQUIRED,
    SoarActionType.REVOKE_CREDENTIALS: AutonomyClass.APPROVAL_REQUIRED,
}


class UnclassifiedSoarActionError(Exception):
    """
    Raised by classify() for any action_type absent from
    ACTION_AUTONOMY — fail closed, never guess a default. action_type
    is typed as SoarActionType but this must stay robust even when a
    caller passes a raw, non-enum string (exactly the case this
    exception exists to reject) — getattr(..., "value", ...) avoids
    crashing on the very input it's meant to report clearly.
    """
    def __init__(self, action_type: SoarActionType):
        label = getattr(action_type, "value", action_type)
        super().__init__(f"No autonomy classification exists for SOAR action type '{label}'. Refusing to guess.")
        self.action_type = action_type


def classify(action_type: SoarActionType) -> AutonomyClass:
    """
    The ONLY function anything in SafeSOC may use to decide whether a
    SOAR action can run without analyst approval. Pure and
    deterministic.

    Raises:
        UnclassifiedSoarActionError: if action_type isn't a key in
        ACTION_AUTONOMY. This should never happen at runtime — every
        SoarActionType member is classified above — and exists purely
        as a fail-closed guard against a future action_type being
        added without a corresponding policy decision.
    """
    try:
        return ACTION_AUTONOMY[action_type]
    except KeyError:
        raise UnclassifiedSoarActionError(action_type) from None


def is_automatic(action_type: SoarActionType) -> bool:
    return classify(action_type) == AutonomyClass.AUTOMATIC


def requires_approval(action_type: SoarActionType) -> bool:
    return classify(action_type) == AutonomyClass.APPROVAL_REQUIRED
