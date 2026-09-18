"""
SafeSOC — SOAR Adapter SDK + Simulated Integration Tests
Registry mechanics (registration, duplicate registration, unknown
adapter, Protocol validation) plus each built-in adapter's execute()/
verify() logic — success and the deterministic failure paths each one
supports. No real EDR/identity/firewall/email system is contacted by
anything under test here; that's the whole point being verified.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.adapters.soar.sdk import SoarActionAdapter, SoarActionResult, SoarAdapterRegistry, SoarVerificationResult
from app.adapters.soar.simulated_edr import SimulatedEDR
from app.adapters.soar.simulated_email import SimulatedEmailGateway
from app.adapters.soar.simulated_firewall import SimulatedFirewall
from app.adapters.soar.simulated_identity import SimulatedIdentityProvider
from app.core.enums import RiskLevel, SoarActionType
from app.models.endpoint import Endpoint


# ── Registry mechanics ───────────────────────────────────────────────

class _FakeAdapter:
    name = "fake"

    async def execute(self, db, tenant_id, action_type, parameters):
        return SoarActionResult(success=True, adapter=self.name, action=action_type.value, target="x", message="ok")

    async def verify(self, db, tenant_id, action_type, result):
        return SoarVerificationResult(verified=True, message="ok")


def test_registry_registers_and_retrieves_an_adapter():
    registry = SoarAdapterRegistry()
    adapter = _FakeAdapter()
    registry.register(SoarActionType.BLOCK_INDICATOR, adapter)
    assert registry.get(SoarActionType.BLOCK_INDICATOR) is adapter


def test_registry_returns_none_for_an_unregistered_action_type():
    registry = SoarAdapterRegistry()
    assert registry.get(SoarActionType.ISOLATE_ENDPOINT) is None


def test_registry_rejects_duplicate_registration_without_replace():
    registry = SoarAdapterRegistry()
    registry.register(SoarActionType.BLOCK_INDICATOR, _FakeAdapter())
    with pytest.raises(ValueError, match="already registered"):
        registry.register(SoarActionType.BLOCK_INDICATOR, _FakeAdapter())


def test_registry_allows_duplicate_registration_with_replace_true():
    registry = SoarAdapterRegistry()
    first, second = _FakeAdapter(), _FakeAdapter()
    registry.register(SoarActionType.BLOCK_INDICATOR, first)
    registry.register(SoarActionType.BLOCK_INDICATOR, second, replace=True)
    assert registry.get(SoarActionType.BLOCK_INDICATOR) is second


def test_registry_rejects_an_object_that_does_not_satisfy_the_protocol():
    registry = SoarAdapterRegistry()

    class _NotAnAdapter:
        pass

    with pytest.raises(TypeError):
        registry.register(SoarActionType.BLOCK_INDICATOR, _NotAnAdapter())


def test_action_types_lists_every_registered_key():
    registry = SoarAdapterRegistry()
    registry.register(SoarActionType.BLOCK_INDICATOR, _FakeAdapter())
    registry.register(SoarActionType.ISOLATE_ENDPOINT, _FakeAdapter())
    assert set(registry.action_types()) == {SoarActionType.BLOCK_INDICATOR, SoarActionType.ISOLATE_ENDPOINT}


@pytest.mark.parametrize("adapter", [SimulatedEDR(), SimulatedIdentityProvider(), SimulatedFirewall(), SimulatedEmailGateway()])
def test_every_built_in_adapter_satisfies_the_protocol(adapter):
    assert isinstance(adapter, SoarActionAdapter)


def test_real_registry_from_app_package_has_no_never_autonomous_or_automatic_action_registered():
    """Only the 5 APPROVAL_REQUIRED action types should ever have an adapter — automatic actions are internal handlers, not adapter-routed."""
    from app.adapters.soar import registry as real_registry
    from app.core.soar_policy import ACTION_AUTONOMY
    from app.core.enums import AutonomyClass

    for action_type in real_registry.action_types():
        assert ACTION_AUTONOMY[action_type] == AutonomyClass.APPROVAL_REQUIRED


# ── SimulatedEDR ─────────────────────────────────────────────────────

def _endpoint(tenant_id, host_id="DESKTOP-042") -> Endpoint:
    return Endpoint(id=uuid.uuid4(), tenant_id=tenant_id, host_id=host_id, risk_score=50, risk_level=RiskLevel.MEDIUM, updated_at=datetime.now(timezone.utc))


@pytest.mark.asyncio
async def test_simulated_edr_isolate_endpoint_succeeds_for_a_known_host(monkeypatch):
    adapter = SimulatedEDR()
    tenant_id = uuid.uuid4()
    monkeypatch.setattr("app.adapters.soar.simulated_edr.get_endpoint", AsyncMock(return_value=_endpoint(tenant_id)))

    result = await adapter.execute(None, tenant_id, SoarActionType.ISOLATE_ENDPOINT, {"host_id": "DESKTOP-042"})

    assert result.success is True
    assert result.adapter == "simulated_edr"
    assert result.state_change == {"host_id": "DESKTOP-042", "status": "isolated"}
    assert "[SIMULATED]" in result.message


@pytest.mark.asyncio
async def test_simulated_edr_isolate_endpoint_fails_for_an_unknown_host(monkeypatch):
    adapter = SimulatedEDR()
    monkeypatch.setattr("app.adapters.soar.simulated_edr.get_endpoint", AsyncMock(return_value=None))

    result = await adapter.execute(None, uuid.uuid4(), SoarActionType.ISOLATE_ENDPOINT, {"host_id": "GHOST-HOST"})

    assert result.success is False
    assert "no record of host" in result.message.lower()


@pytest.mark.asyncio
async def test_simulated_edr_terminate_process_succeeds_for_a_known_host(monkeypatch):
    adapter = SimulatedEDR()
    tenant_id = uuid.uuid4()
    monkeypatch.setattr("app.adapters.soar.simulated_edr.get_endpoint", AsyncMock(return_value=_endpoint(tenant_id)))

    result = await adapter.execute(None, tenant_id, SoarActionType.TERMINATE_PROCESS, {"host_id": "DESKTOP-042", "process": "evil.exe"})

    assert result.success is True
    assert result.state_change["process"] == "evil.exe"
    assert result.state_change["status"] == "terminated"


@pytest.mark.asyncio
async def test_simulated_edr_verify_succeeds_after_a_successful_isolation(monkeypatch):
    adapter = SimulatedEDR()
    result = SoarActionResult(success=True, adapter="simulated_edr", action="isolate_endpoint", target="DESKTOP-042", message="x", state_change={"host_id": "DESKTOP-042", "status": "isolated"})

    verification = await adapter.verify(None, uuid.uuid4(), SoarActionType.ISOLATE_ENDPOINT, result)

    assert verification.verified is True


@pytest.mark.asyncio
async def test_simulated_edr_verify_fails_for_a_failed_execution_result():
    adapter = SimulatedEDR()
    result = SoarActionResult(success=False, adapter="simulated_edr", action="isolate_endpoint", target="DESKTOP-042", message="failed")

    verification = await adapter.verify(None, uuid.uuid4(), SoarActionType.ISOLATE_ENDPOINT, result)

    assert verification.verified is False


@pytest.mark.asyncio
async def test_simulated_edr_verify_fails_when_state_change_is_inconsistent():
    """Even a success=True result with a malformed/mismatched state_change must fail verification, not be trusted blindly."""
    adapter = SimulatedEDR()
    result = SoarActionResult(success=True, adapter="simulated_edr", action="isolate_endpoint", target="DESKTOP-042", message="x", state_change={"host_id": "DESKTOP-042", "status": "something_else"})

    verification = await adapter.verify(None, uuid.uuid4(), SoarActionType.ISOLATE_ENDPOINT, result)

    assert verification.verified is False


# ── SimulatedIdentityProvider ────────────────────────────────────────

@pytest.mark.asyncio
async def test_simulated_identity_disable_account_succeeds_for_a_named_user():
    adapter = SimulatedIdentityProvider()
    result = await adapter.execute(None, uuid.uuid4(), SoarActionType.DISABLE_ACCOUNT, {"user": "tom.thompson"})
    assert result.success is True
    assert result.state_change == {"user": "tom.thompson", "status": "disabled"}


@pytest.mark.asyncio
async def test_simulated_identity_revoke_credentials_succeeds_for_a_named_user():
    adapter = SimulatedIdentityProvider()
    result = await adapter.execute(None, uuid.uuid4(), SoarActionType.REVOKE_CREDENTIALS, {"user": "tom.thompson"})
    assert result.success is True
    assert result.state_change["status"] == "credentials_revoked"


@pytest.mark.asyncio
async def test_simulated_identity_fails_for_an_empty_user():
    adapter = SimulatedIdentityProvider()
    result = await adapter.execute(None, uuid.uuid4(), SoarActionType.DISABLE_ACCOUNT, {"user": ""})
    assert result.success is False


@pytest.mark.asyncio
async def test_simulated_identity_verify_round_trip():
    adapter = SimulatedIdentityProvider()
    result = await adapter.execute(None, uuid.uuid4(), SoarActionType.DISABLE_ACCOUNT, {"user": "tom.thompson"})
    verification = await adapter.verify(None, uuid.uuid4(), SoarActionType.DISABLE_ACCOUNT, result)
    assert verification.verified is True


# ── SimulatedFirewall ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_simulated_firewall_block_indicator_succeeds():
    adapter = SimulatedFirewall()
    result = await adapter.execute(None, uuid.uuid4(), SoarActionType.BLOCK_INDICATOR, {"indicator": "203.0.113.5"})
    assert result.success is True
    assert result.state_change == {"indicator": "203.0.113.5", "status": "blocked"}


@pytest.mark.asyncio
async def test_simulated_firewall_verify_round_trip():
    adapter = SimulatedFirewall()
    result = await adapter.execute(None, uuid.uuid4(), SoarActionType.BLOCK_INDICATOR, {"indicator": "203.0.113.5"})
    verification = await adapter.verify(None, uuid.uuid4(), SoarActionType.BLOCK_INDICATOR, result)
    assert verification.verified is True


@pytest.mark.asyncio
async def test_simulated_firewall_fails_for_missing_indicator():
    adapter = SimulatedFirewall()
    result = await adapter.execute(None, uuid.uuid4(), SoarActionType.BLOCK_INDICATOR, {})
    assert result.success is False


# ── Every message is honestly labeled as simulated ──────────────────

@pytest.mark.asyncio
async def test_every_adapter_success_message_says_simulated_and_no_real_system(monkeypatch):
    monkeypatch.setattr("app.adapters.soar.simulated_edr.get_endpoint", AsyncMock(return_value=_endpoint(uuid.uuid4())))
    edr_result = await SimulatedEDR().execute(None, uuid.uuid4(), SoarActionType.ISOLATE_ENDPOINT, {"host_id": "DESKTOP-042"})
    identity_result = await SimulatedIdentityProvider().execute(None, uuid.uuid4(), SoarActionType.DISABLE_ACCOUNT, {"user": "tom.thompson"})
    firewall_result = await SimulatedFirewall().execute(None, uuid.uuid4(), SoarActionType.BLOCK_INDICATOR, {"indicator": "203.0.113.5"})
    email_result = await SimulatedEmailGateway().execute(None, uuid.uuid4(), SoarActionType.ADD_INCIDENT_NOTE, {})

    for result in (edr_result, identity_result, firewall_result, email_result):
        assert "[SIMULATED]" in result.message
        assert "no real" in result.message.lower()
