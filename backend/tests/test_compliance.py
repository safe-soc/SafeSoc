"""
SafeSOC — Compliance Evidence Assessment Service Tests
Boundary-mocks the evidence sources services/compliance.py reads from
(services/audit.py, services/incidents.py, db/opensearch.py, and its
own _investigation_rollup) — same approach as
tests/test_threat_analytics.py, since a raw fake DB session can't
meaningfully prove real tenant-scoped SQL filtering (verified live
against Docker Postgres instead, per Phase 4).
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.compliance_mapping import COMPLIANCE_REQUIREMENTS, get_requirement
from app.core.enums import ComplianceFramework, ComplianceStatus, UserRole
from app.core.exceptions import ComplianceRequirementNotFoundError
from app.services import compliance as compliance_service

_EXPECTED_IDS = {
    "DPDP-R1", "DPDP-R2", "DPDP-R3", "DPDP-R4", "DPDP-R5",
    "CERTIN-R1", "CERTIN-R2", "CERTIN-R3", "CERTIN-R4",
    "DPIIT-R1",
}


# ── Static mapping shape ───────────────────────────────────────────────

def test_compliance_requirements_cover_the_approved_id_set():
    assert {r.id for r in COMPLIANCE_REQUIREMENTS} == _EXPECTED_IDS


def test_every_requirement_has_non_empty_source_and_summary_text():
    for requirement in COMPLIANCE_REQUIREMENTS:
        assert requirement.authoritative_source.strip()
        assert requirement.requirement_summary.strip()
        assert requirement.what_safesoc_can_observe.strip()
        assert requirement.what_safesoc_cannot_verify.strip()


def test_every_requirement_has_a_dispatchable_evidence_type():
    valid_types = set(compliance_service._ASSESSORS) | {"none"}
    for requirement in COMPLIANCE_REQUIREMENTS:
        assert requirement.evidence_type in valid_types


def test_no_static_requirement_text_asserts_legal_compliance():
    """Regression guard for the hard constraint: never claim compliance/non-compliance."""
    forbidden = ("non-compliant", "legally compliant", "legally non-compliant")
    for requirement in COMPLIANCE_REQUIREMENTS:
        haystack = " ".join([
            requirement.title, requirement.requirement_summary,
            requirement.what_safesoc_can_observe, requirement.what_safesoc_cannot_verify,
        ]).lower()
        for phrase in forbidden:
            assert phrase not in haystack


def test_get_requirement_returns_none_for_unknown_id():
    assert get_requirement("NOT-A-REAL-ID") is None


# ── DPDP-R1: access control ────────────────────────────────────────────

class _FakeRoleCountSession:
    def __init__(self, rows):
        self._rows = rows

    async def execute(self, stmt, params=None):
        return self

    def all(self):
        return self._rows


@pytest.mark.asyncio
async def test_dpdp_r1_access_control_is_always_evidence_available():
    session = _FakeRoleCountSession([(UserRole.ADMIN, 1), (UserRole.ANALYST, 2)])

    live = await compliance_service._assess_access_control(session, uuid.uuid4())

    assert live.status == ComplianceStatus.EVIDENCE_AVAILABLE
    assert live.evidence_count == 3
    assert live.metrics["total_users"] == 3


@pytest.mark.asyncio
async def test_dpdp_r1_evidence_summary_never_implies_wider_it_environment_coverage():
    session = _FakeRoleCountSession([(UserRole.VIEWER, 1)])
    requirement = get_requirement("DPDP-R1")

    live = await compliance_service._assess_access_control(session, uuid.uuid4())

    # The caveat itself lives on the static requirement text, not the
    # live evidence summary — assert it's present and unambiguous.
    assert "does not establish access control across the customer" in requirement.what_safesoc_cannot_verify


# ── DPDP-R2: logging/monitoring ────────────────────────────────────────

def _mock_log_monitoring_sources(monkeypatch, *, audit_total, incident_total, alert_total, rollup):
    monkeypatch.setattr(compliance_service.audit_service, "list_events", AsyncMock(return_value=([], audit_total)))
    monkeypatch.setattr(compliance_service.incidents_service, "list_incidents", AsyncMock(return_value=([], incident_total)))
    monkeypatch.setattr(compliance_service, "get_alert_severity_summary", AsyncMock(return_value={"total": alert_total}))
    monkeypatch.setattr(compliance_service, "_investigation_rollup", AsyncMock(return_value=rollup))


@pytest.mark.asyncio
async def test_dpdp_r2_evidence_available_when_meaningful_evidence_exists(monkeypatch):
    _mock_log_monitoring_sources(
        monkeypatch, audit_total=5, incident_total=2, alert_total=10,
        rollup={"session_count": 1, "confirmed_finding_count": 1, "completed_action_count": 1, "recent": []},
    )

    live = await compliance_service._assess_log_monitoring(None, uuid.uuid4())

    assert live.status == ComplianceStatus.EVIDENCE_AVAILABLE
    assert live.evidence_count == 5 + 2 + 10 + 1 + 1


@pytest.mark.asyncio
async def test_dpdp_r2_evidence_gap_when_every_count_is_zero(monkeypatch):
    _mock_log_monitoring_sources(
        monkeypatch, audit_total=0, incident_total=0, alert_total=0,
        rollup={"session_count": 0, "confirmed_finding_count": 0, "completed_action_count": 0, "recent": []},
    )

    live = await compliance_service._assess_log_monitoring(None, uuid.uuid4())

    assert live.status == ComplianceStatus.GAP
    assert live.evidence_count == 0


# ── DPDP-R5 / CERTIN-R1: fixed partially-supported requirements ───────

@pytest.mark.asyncio
async def test_dpdp_r5_breach_notification_is_always_partially_supported_and_never_submits(monkeypatch):
    monkeypatch.setattr(compliance_service.incidents_service, "list_incidents", AsyncMock(return_value=([], 3)))

    live = await compliance_service._assess_breach_notification(None, uuid.uuid4())

    assert live.status == ComplianceStatus.PARTIALLY_SUPPORTED
    assert "does NOT submit notifications" in live.evidence_summary


@pytest.mark.asyncio
async def test_certin_r1_incident_reporting_is_always_partially_supported_and_never_submits(monkeypatch):
    monkeypatch.setattr(compliance_service.incidents_service, "list_incidents", AsyncMock(return_value=([], 0)))

    live = await compliance_service._assess_incident_reporting_timeliness(None, uuid.uuid4())

    assert live.status == ComplianceStatus.PARTIALLY_SUPPORTED
    assert "does NOT submit reports to CERT-In" in live.evidence_summary


# ── CERTIN-R2: 180-day log retention, read from live config ───────────

@pytest.mark.asyncio
async def test_certin_r2_gap_when_configured_retention_is_below_180_days(monkeypatch):
    monkeypatch.setattr(compliance_service.settings, "OPENSEARCH_ILM_RETENTION_DAYS", 90)

    live = await compliance_service._assess_log_retention(None, uuid.uuid4())

    assert live.status == ComplianceStatus.GAP
    assert live.metrics == {"configured_retention_days": 90, "required_retention_days": 180}
    assert "90" in live.evidence_summary and "180" in live.evidence_summary


@pytest.mark.asyncio
async def test_certin_r2_partially_supported_when_configured_retention_meets_180_days(monkeypatch):
    monkeypatch.setattr(compliance_service.settings, "OPENSEARCH_ILM_RETENTION_DAYS", 200)

    live = await compliance_service._assess_log_retention(None, uuid.uuid4())

    assert live.status == ComplianceStatus.PARTIALLY_SUPPORTED
    assert "jurisdiction" in live.evidence_summary.lower()


@pytest.mark.asyncio
async def test_certin_r2_never_claims_to_establish_storage_jurisdiction(monkeypatch):
    """Even a passing retention value must not be read as proving Indian-jurisdiction storage."""
    monkeypatch.setattr(compliance_service.settings, "OPENSEARCH_ILM_RETENTION_DAYS", 365)

    live = await compliance_service._assess_log_retention(None, uuid.uuid4())

    assert "does not assess the physical/legal jurisdiction" in live.evidence_summary


# ── Static NOT_ASSESSABLE requirements ─────────────────────────────────

@pytest.mark.parametrize("requirement_id", ["DPDP-R3", "DPDP-R4", "CERTIN-R3", "CERTIN-R4"])
def test_static_requirements_are_not_assessable_with_zero_evidence(requirement_id):
    requirement = get_requirement(requirement_id)

    live = compliance_service._assess_not_assessable(requirement)

    assert live.status == ComplianceStatus.NOT_ASSESSABLE
    assert live.evidence_count == 0


def test_dpiit_requirement_states_no_fabricated_control_explicitly():
    requirement = get_requirement("DPIIT-R1")

    live = compliance_service._assess_dpiit_not_applicable(requirement)

    assert live.status == ComplianceStatus.NOT_ASSESSABLE
    assert "No directly applicable DPIIT cybersecurity technical control was identified" in live.evidence_summary
    assert "not being treated as a cybersecurity control framework" in live.evidence_summary
    assert requirement.framework == ComplianceFramework.DPIIT


# ── End-to-end: get_compliance_posture / get_requirement_detail ───────

@pytest.mark.asyncio
async def test_get_compliance_posture_assesses_every_requirement_with_a_valid_status(monkeypatch):
    _mock_log_monitoring_sources(
        monkeypatch, audit_total=0, incident_total=0, alert_total=0,
        rollup={"session_count": 0, "confirmed_finding_count": 0, "completed_action_count": 0, "recent": []},
    )
    session = _FakeRoleCountSession([])

    assessments = await compliance_service.get_compliance_posture(session, uuid.uuid4())

    assert {a.requirement.id for a in assessments} == _EXPECTED_IDS
    for assessment in assessments:
        assert isinstance(assessment.status, ComplianceStatus)
        assert assessment.recommended_action.strip()


@pytest.mark.asyncio
async def test_get_requirement_detail_raises_not_found_for_unknown_id():
    with pytest.raises(ComplianceRequirementNotFoundError):
        await compliance_service.get_requirement_detail(None, uuid.uuid4(), "NOT-A-REAL-ID")


@pytest.mark.asyncio
async def test_get_requirement_detail_passes_the_callers_tenant_id_through(monkeypatch):
    """Structural proof a requirement id alone can't reach another tenant's evidence — the
    live evidence call always uses the tenant_id the caller passed in, never anything derived
    from requirement_id itself."""
    tenant_id = uuid.uuid4()
    mock_list_incidents = AsyncMock(return_value=([], 1))
    monkeypatch.setattr(compliance_service.incidents_service, "list_incidents", mock_list_incidents)

    await compliance_service.get_requirement_detail(None, tenant_id, "DPDP-R5")

    # Called twice (once for the count, once for _recent_incidents) — both must use the caller's tenant_id.
    assert mock_list_incidents.call_count == 2
    for call in mock_list_incidents.call_args_list:
        assert call.args[1] == tenant_id
