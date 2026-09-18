"""
SafeSOC — Static SOAR Playbook Definitions
A playbook maps one detected correlation pattern (the correlation
engine's own CorrelationPattern, services/correlation.py — reused
here, not a second pattern vocabulary) to an ordered sequence of SOAR
actions. Static Python config, not a database table, following the
same reasoning core/mitre_mapping.py and core/compliance_mapping.py
already establish: this is code-reviewed, rarely-changing reference
data, the same for every tenant — a migration would be the wrong tool
for editing it.

Deliberately NOT a rule/expression engine. A trigger is only ever "one
CorrelationPattern at or above a confidence floor" (PlaybookTrigger) —
richer conditions, if ever needed, are new named fields on that
dataclass, never an embedded expression string. A step's parameters
are resolved by resolve_step_parameters() below, a plain dict lookup
keyed on the closed EvidenceField enum — there is no template string,
no eval()/exec(), no format-string interpolation, and therefore no
template-injection surface at all. Only a fixed, known set of incident-
evidence fields (primary host/IP/user) can ever feed a parameter.

Everything here is pure: match_playbook/resolve_step_parameters/
step_evidence_is_available do no I/O and hold no state. The live
wiring — evaluating these triggers against a detected correlation
chain and instantiating a run — lives in services/soar.py
(evaluate_triggers/create_playbook_run), called from
workers/correlation_worker.py.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from app.core.enums import CorrelationPattern, SoarActionType
from app.core.soar_policy import classify


class EvidenceField(str, Enum):
    """
    The closed set of incident-evidence fields a playbook step's
    parameters may draw from (services/incident_evidence.py's already-
    computed hosts/ips/users). Adding a new field here means adding a
    new branch to resolve_step_parameters() below — it can never grow
    into a free-form expression by itself.
    """
    PRIMARY_HOST = "primary_host"
    PRIMARY_IP = "primary_ip"
    PRIMARY_USER = "primary_user"
    NONE = "none"


@dataclass(frozen=True)
class PlaybookStep:
    action_type: SoarActionType
    parameter_field: EvidenceField = EvidenceField.NONE
    # Small, fixed, non-evidence-derived values (e.g. a canned note/
    # description) — never user input, never interpreted as code.
    static_parameters: dict = field(default_factory=dict)


@dataclass(frozen=True)
class PlaybookTrigger:
    pattern: CorrelationPattern
    min_confidence: float


@dataclass(frozen=True)
class Playbook:
    id: str
    title: str
    trigger: PlaybookTrigger
    steps: tuple[PlaybookStep, ...]


SOAR_PLAYBOOKS: list[Playbook] = [
    Playbook(
        id="pb-credential-brute-force",
        title="Credential Brute Force Response",
        trigger=PlaybookTrigger(CorrelationPattern.CREDENTIAL_BRUTE_FORCE, min_confidence=0.5),
        steps=(
            PlaybookStep(SoarActionType.ENRICH_INDICATOR, EvidenceField.PRIMARY_IP),
            PlaybookStep(
                SoarActionType.CREATE_INVESTIGATION_ACTION, EvidenceField.NONE,
                static_parameters={"description": "Review repeated failed login attempts against the affected host."},
            ),
        ),
    ),
    Playbook(
        id="pb-successful-compromise",
        title="Successful Compromise Response",
        trigger=PlaybookTrigger(CorrelationPattern.SUCCESSFUL_COMPROMISE, min_confidence=0.6),
        steps=(
            PlaybookStep(SoarActionType.ENRICH_INDICATOR, EvidenceField.PRIMARY_IP),
            PlaybookStep(
                SoarActionType.ADD_INCIDENT_NOTE, EvidenceField.NONE,
                static_parameters={"note": "Automated: credential compromise pattern detected — investigate immediately."},
            ),
            PlaybookStep(SoarActionType.TERMINATE_PROCESS, EvidenceField.PRIMARY_HOST),
            PlaybookStep(SoarActionType.ISOLATE_ENDPOINT, EvidenceField.PRIMARY_HOST),
        ),
    ),
    Playbook(
        id="pb-recon-to-exploitation",
        title="Reconnaissance to Exploitation Response",
        trigger=PlaybookTrigger(CorrelationPattern.RECON_TO_EXPLOITATION, min_confidence=0.5),
        steps=(
            PlaybookStep(SoarActionType.COLLECT_ADDITIONAL_EVIDENCE, EvidenceField.PRIMARY_HOST),
            PlaybookStep(
                SoarActionType.CREATE_INVESTIGATION_ACTION, EvidenceField.NONE,
                static_parameters={"description": "Review the reconnaissance-to-exploitation event sequence."},
            ),
        ),
    ),
    Playbook(
        id="pb-privilege-escalation",
        title="Privilege Escalation Response",
        trigger=PlaybookTrigger(CorrelationPattern.PRIVILEGE_ESCALATION, min_confidence=0.7),
        steps=(
            PlaybookStep(
                SoarActionType.INCREASE_INCIDENT_PRIORITY, EvidenceField.NONE,
                static_parameters={"reason": "Privilege escalation detected."},
            ),
            PlaybookStep(
                SoarActionType.CREATE_INVESTIGATION_ACTION, EvidenceField.NONE,
                static_parameters={"description": "Confirm the scope of the privilege escalation."},
            ),
            PlaybookStep(SoarActionType.DISABLE_ACCOUNT, EvidenceField.PRIMARY_USER),
        ),
    ),
    Playbook(
        id="pb-data-exfiltration",
        title="Data Exfiltration Response",
        trigger=PlaybookTrigger(CorrelationPattern.DATA_EXFILTRATION, min_confidence=0.6),
        steps=(
            PlaybookStep(SoarActionType.ENRICH_INDICATOR, EvidenceField.PRIMARY_IP),
            PlaybookStep(
                SoarActionType.ADD_INCIDENT_NOTE, EvidenceField.NONE,
                static_parameters={"note": "Automated: possible data exfiltration — abnormal outbound connection volume."},
            ),
            PlaybookStep(SoarActionType.BLOCK_INDICATOR, EvidenceField.PRIMARY_IP),
        ),
    ),
    Playbook(
        id="pb-lateral-movement",
        title="Lateral Movement Response",
        trigger=PlaybookTrigger(CorrelationPattern.LATERAL_MOVEMENT, min_confidence=0.5),
        steps=(
            PlaybookStep(SoarActionType.COLLECT_ADDITIONAL_EVIDENCE, EvidenceField.PRIMARY_HOST),
            PlaybookStep(
                SoarActionType.CREATE_INVESTIGATION_ACTION, EvidenceField.NONE,
                static_parameters={"description": "Trace the lateral movement path across hosts."},
            ),
            PlaybookStep(SoarActionType.REVOKE_CREDENTIALS, EvidenceField.PRIMARY_USER),
        ),
    ),
]

_PLAYBOOKS_BY_ID: dict[str, Playbook] = {playbook.id: playbook for playbook in SOAR_PLAYBOOKS}


def get_playbook(playbook_id: str) -> Optional[Playbook]:
    """Look up a static playbook by id (e.g. "pb-successful-compromise"). None if unknown."""
    return _PLAYBOOKS_BY_ID.get(playbook_id)


def match_playbook(pattern: CorrelationPattern, confidence: float) -> Optional[Playbook]:
    """
    Deterministic playbook selection for a just-detected correlation
    pattern (services/soar.py::evaluate_triggers, Phase 2): every
    SOAR_PLAYBOOKS entry whose trigger.pattern matches and whose
    trigger.min_confidence is met by `confidence`, ranked by the
    HIGHEST min_confidence satisfied (the most specific/conservative
    match), ties broken by playbook id. So even if a future playbook
    set ever had two entries targeting the same pattern, the outcome
    for a given (pattern, confidence) pair is always the same one —
    never ambiguous, never dependent on SOAR_PLAYBOOKS' list order.
    None if nothing matches.
    """
    candidates = [playbook for playbook in SOAR_PLAYBOOKS if playbook.trigger.pattern == pattern and confidence >= playbook.trigger.min_confidence]
    if not candidates:
        return None
    return sorted(candidates, key=lambda playbook: (-playbook.trigger.min_confidence, playbook.id))[0]


# EvidenceField -> (the key it reads from an evidence dict, the parameter
# name it populates). One map, used by BOTH resolve_step_parameters and
# step_evidence_is_available below, so "which evidence does this step
# need" and "where does that evidence come from" can never drift apart
# into two subtly different answers.
_EVIDENCE_FIELD_RESOLUTION: dict[EvidenceField, tuple[str, str]] = {
    EvidenceField.PRIMARY_HOST: ("hosts", "host_id"),
    EvidenceField.PRIMARY_IP: ("ips", "indicator"),
    EvidenceField.PRIMARY_USER: ("users", "user"),
}


def resolve_step_parameters(step: PlaybookStep, evidence: dict) -> dict:
    """
    Resolve a playbook step's parameters against a CLOSED set of known
    incident-evidence fields — a plain dict lookup, never eval/exec/
    string templating. `evidence` is a plain dict with "hosts"/"ips"/
    "users" keys, each a list of strings (the shape
    services/incident_evidence.py's IncidentEvidence already produces),
    passed in by the caller — this function does no I/O of its own.

    A field with no matching evidence resolves to None for that
    parameter (e.g. a host-scoped step on an incident with no host
    evidence yet) rather than raising here. Callers are expected to ask
    step_evidence_is_available() FIRST and skip the step entirely if it
    says no — see services/soar.py::create_playbook_run. Reaching
    validate_action_parameters with a None here means the caller chose
    not to check, and it will (still) reject the step.
    """
    params = dict(step.static_parameters)
    resolution = _EVIDENCE_FIELD_RESOLUTION.get(step.parameter_field)
    if resolution is not None:
        evidence_key, parameter_name = resolution
        values = evidence.get(evidence_key) or []
        params[parameter_name] = values[0] if values else None
    return params


def step_evidence_is_available(step: PlaybookStep, evidence: dict) -> bool:
    """
    Whether `evidence` actually carries what this step's parameter_field
    needs — pure, no I/O, same `evidence` dict shape as
    resolve_step_parameters.

    This is the "incomplete telemetry" question, deliberately kept
    separate from the "are these parameters valid" question
    (services/soar.py::validate_action_parameters). An incident whose
    alerts never carried a source/destination IP simply has no IP to
    act on — that's a gap in what was observed, not a malformed or
    hostile value, and the two must stay distinguishable: the first is
    a step to skip and record, the second is a step to refuse.

    A step with EvidenceField.NONE needs nothing and is always
    available (its parameters are static literals only).
    """
    resolution = _EVIDENCE_FIELD_RESOLUTION.get(step.parameter_field)
    if resolution is None:
        return True
    evidence_key, _ = resolution
    return bool(evidence.get(evidence_key))


def validate_playbook_definitions() -> None:
    """
    Sanity-check every static playbook: ids are unique, every playbook
    has at least one step, and every step's action_type is classified
    by core/soar_policy.py (classify() raises UnclassifiedSoarActionError
    otherwise). Called at import time (below) so a broken playbook
    definition fails the moment the app/tests start, not at request
    time — static config is either right or wrong at commit time.

    Raises:
        ValueError: duplicate playbook id, or a playbook with no steps.
        UnclassifiedSoarActionError: a step's action_type has no autonomy classification.
    """
    seen_ids: set[str] = set()
    for playbook in SOAR_PLAYBOOKS:
        if playbook.id in seen_ids:
            raise ValueError(f"Duplicate SOAR playbook id: {playbook.id}")
        seen_ids.add(playbook.id)
        if not playbook.steps:
            raise ValueError(f"SOAR playbook '{playbook.id}' has no steps.")
        for step in playbook.steps:
            classify(step.action_type)


validate_playbook_definitions()
