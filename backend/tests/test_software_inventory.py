"""
SafeSOC — Endpoint Software Inventory Service Tests
"""

import uuid

import pytest

from app.core.enums import SoftwareCategory
from app.models.endpoint_software import EndpointSoftware
from app.services.software_inventory import list_endpoint_software, upsert_software


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class _FakeSession:
    def __init__(self, existing=None):
        self.existing: list[EndpointSoftware] = list(existing or [])
        self.added: list = []
        self.commit_count = 0

    async def execute(self, stmt):
        return _FakeResult(self.existing)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.commit_count += 1
        for obj in self.added:
            if obj not in self.existing:
                self.existing.append(obj)
        self.added = []

    async def refresh(self, obj):
        pass


@pytest.mark.asyncio
async def test_list_endpoint_software_returns_the_hosts_rows():
    tenant_id = uuid.uuid4()
    row = EndpointSoftware(
        id=uuid.uuid4(), tenant_id=tenant_id, host_id="DESKTOP-042", name="Windows 11", version="23H2",
        category=SoftwareCategory.OPERATING_SYSTEM, vulnerabilities=[],
    )
    session = _FakeSession(existing=[row])

    result = await list_endpoint_software(session, tenant_id, "DESKTOP-042")

    assert result == [row]


@pytest.mark.asyncio
async def test_list_endpoint_software_returns_empty_list_when_none_recorded():
    result = await list_endpoint_software(_FakeSession(), uuid.uuid4(), "DESKTOP-999")
    assert result == []


@pytest.mark.asyncio
async def test_upsert_software_creates_a_new_row_when_none_exists():
    tenant_id = uuid.uuid4()
    session = _FakeSession()

    row = await upsert_software(
        session, tenant_id, "DESKTOP-042", "Google Chrome", "118.0.5993.70", SoftwareCategory.BROWSER,
        [{"id": "DEMO-VULN-0001", "severity": "medium", "title": "Demo vulnerability", "is_synthetic": True}],
    )

    assert row.tenant_id == tenant_id
    assert row.host_id == "DESKTOP-042"
    assert row.name == "Google Chrome"
    assert row.version == "118.0.5993.70"
    assert row.category == SoftwareCategory.BROWSER
    assert len(row.vulnerabilities) == 1
    assert session.commit_count == 1


@pytest.mark.asyncio
async def test_upsert_software_updates_an_existing_row_in_place_idempotently():
    """Re-running the seed simulation must refresh, not duplicate."""
    tenant_id = uuid.uuid4()
    existing = EndpointSoftware(
        id=uuid.uuid4(), tenant_id=tenant_id, host_id="DESKTOP-042", name="Google Chrome", version="117.0.0.0",
        category=SoftwareCategory.BROWSER, vulnerabilities=[],
    )
    session = _FakeSession(existing=[existing])

    row = await upsert_software(
        session, tenant_id, "DESKTOP-042", "Google Chrome", "118.0.5993.70", SoftwareCategory.BROWSER, []
    )

    assert row.id == existing.id
    assert row.version == "118.0.5993.70"
    assert len(session.existing) == 1  # updated in place, not duplicated
