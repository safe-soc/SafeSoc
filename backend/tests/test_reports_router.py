"""
SafeSOC — Reports Router Tests (SS-054)
Uses real REPORT_OUTPUT_DIR filesystem writes under tmp_path rather
than mocking list_reports/get_report_path — the AC is specifically
about tenant isolation at the storage layer, so these tests exercise
the real path-resolution logic end-to-end through the HTTP layer.
"""

import uuid
from pathlib import Path

import pytest

from app.core.config import settings


def _write_report(tenant_id: uuid.UUID, filename: str, content: bytes = b"%PDF-1.7 fake report content") -> None:
    report_dir = Path(settings.REPORT_OUTPUT_DIR) / str(tenant_id)
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / filename).write_bytes(content)


@pytest.fixture(autouse=True)
def _report_output_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "REPORT_OUTPUT_DIR", str(tmp_path))
    return tmp_path


def test_list_reports_requires_authentication(client):
    response = client.get("/api/v1/reports")

    assert response.status_code == 401


def test_list_reports_is_empty_for_a_tenant_with_none_generated_yet(client, auth_headers):
    response = client.get("/api/v1/reports", headers=auth_headers)

    assert response.status_code == 200
    assert response.json() == {"reports": []}


def test_list_reports_returns_the_authenticated_tenants_reports(client, make_auth_headers):
    tenant_id = uuid.uuid4()
    _write_report(tenant_id, "20260101T060000Z.pdf")
    headers = make_auth_headers(tenant_id=tenant_id)

    response = client.get("/api/v1/reports", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert len(body["reports"]) == 1
    assert body["reports"][0]["filename"] == "20260101T060000Z.pdf"
    assert body["reports"][0]["size_bytes"] > 0


def test_list_reports_does_not_include_another_tenants_reports(client, make_auth_headers):
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    _write_report(tenant_b, "20260101T060000Z.pdf")
    headers_a = make_auth_headers(tenant_id=tenant_a)

    response = client.get("/api/v1/reports", headers=headers_a)

    assert response.json() == {"reports": []}


def test_download_requires_authentication(client):
    response = client.get("/api/v1/reports/20260101T060000Z.pdf")

    assert response.status_code == 401


def test_download_returns_the_pdf_for_the_owning_tenant(client, make_auth_headers):
    tenant_id = uuid.uuid4()
    _write_report(tenant_id, "20260101T060000Z.pdf", content=b"%PDF-1.7 real bytes")
    headers = make_auth_headers(tenant_id=tenant_id)

    response = client.get("/api/v1/reports/20260101T060000Z.pdf", headers=headers)

    assert response.status_code == 200
    assert response.content == b"%PDF-1.7 real bytes"
    assert response.headers["content-type"] == "application/pdf"


def test_download_404s_for_a_report_that_does_not_exist(client, auth_headers):
    response = client.get("/api/v1/reports/does-not-exist.pdf", headers=auth_headers)

    assert response.status_code == 404


def test_cannot_download_another_tenants_report_by_guessing_its_filename(client, make_auth_headers):
    """AC: tenant isolation enforced — a filename that exists under a different tenant returns 404, not the file."""
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    _write_report(tenant_b, "20260101T060000Z.pdf")
    headers_a = make_auth_headers(tenant_id=tenant_a)

    response = client.get("/api/v1/reports/20260101T060000Z.pdf", headers=headers_a)

    assert response.status_code == 404


def test_download_rejects_a_path_traversal_attempt(client, make_auth_headers):
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    _write_report(tenant_b, "secret.pdf")
    headers_a = make_auth_headers(tenant_id=tenant_a)

    response = client.get(f"/api/v1/reports/..%2F{tenant_b}%2Fsecret.pdf", headers=headers_a)

    assert response.status_code in (404, 400)
