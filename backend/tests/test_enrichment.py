"""
SafeSOC — Enrichment Service Tests
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from app.clients.abuseipdb import AbuseIPDBError
from app.clients.virustotal import VirusTotalError
from app.schemas.log import NormalizedLog, TIResult
from app.services import enrichment


def _make_log(**overrides) -> NormalizedLog:
    fields = {
        "tenant_id": "acme-corp",
        "source": "synthetic",
        "log_type": "authentication",
        "timestamp": "2026-08-06T02:47:11Z",
        "host_id": "DESKTOP-042",
        "host_ip": "192.168.1.42",
        "action": "failed_login",
        "description": "Failed SSH authentication attempt",
        "severity": "low",
    }
    fields.update(overrides)
    return NormalizedLog(**fields)


class _FakeCacheRow:
    def __init__(self, result: dict, is_malicious: bool, expires_at: datetime):
        self.result = result
        self.is_malicious = is_malicious
        self.expires_at = expires_at
        self.id = "fake-id"


class _FakeResult:
    def __init__(self, row):
        self._row = row

    def scalar_one_or_none(self):
        return self._row


class _FakeSession:
    """
    Returns cache rows from a pre-loaded queue, one per db.execute() call,
    in the same order the service code issues them (VT check, then
    AbuseIPDB check, for an IP; just VT for a hash).
    """

    def __init__(self, cache_rows=None):
        self._cache_rows = list(cache_rows or [])
        self.added = []
        self.committed = False

    async def execute(self, stmt):
        row = self._cache_rows.pop(0) if self._cache_rows else None
        return _FakeResult(row)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.committed = True

    async def refresh(self, obj):
        pass


@pytest.fixture(autouse=True)
def _mock_opensearch_update(monkeypatch):
    """Every test gets a mocked OpenSearch update-by-id, asserted on individually where relevant."""
    mock = AsyncMock(return_value=True)
    monkeypatch.setattr(enrichment, "update_alert_ti_fields", mock)
    return mock


# ── SS-025: cache hit path makes zero external HTTP calls ────────

@pytest.mark.asyncio
async def test_cache_hit_makes_zero_external_calls(monkeypatch):
    now = datetime.now(timezone.utc)
    vt_row = _FakeCacheRow({"vt_malicious": 3, "vt_total": 70, "is_malicious": True}, True, now + timedelta(days=1))
    abuse_row = _FakeCacheRow({"abuse_confidence": 60, "abuse_total_reports": 5, "is_malicious": True}, True, now + timedelta(days=1))
    session = _FakeSession(cache_rows=[vt_row, abuse_row])

    vt_lookup = AsyncMock(side_effect=AssertionError("VirusTotal should not be called on a cache hit"))
    abuse_lookup = AsyncMock(side_effect=AssertionError("AbuseIPDB should not be called on a cache hit"))
    monkeypatch.setattr(enrichment.virustotal, "lookup_ip", vt_lookup)
    monkeypatch.setattr(enrichment.abuseipdb, "lookup_ip", abuse_lookup)

    log = _make_log(source_ip="45.33.32.156")
    enriched = await enrichment.enrich_log(session, log)

    vt_lookup.assert_not_called()
    abuse_lookup.assert_not_called()
    assert enriched.ti_enriched is True
    assert enriched.ti_result.is_malicious is True
    assert enriched.ti_result.vt_malicious == 3
    assert enriched.ti_result.abuse_confidence == 60
    assert session.committed is False  # no cache write on a pure hit


# ── SS-025: cache miss calls the client and writes back to cache ──

@pytest.mark.asyncio
async def test_cache_miss_calls_clients_and_writes_back_to_cache(monkeypatch):
    session = _FakeSession(cache_rows=[None, None])

    monkeypatch.setattr(
        enrichment.virustotal, "lookup_ip",
        AsyncMock(return_value=TIResult(source_ip="45.33.32.156", vt_malicious=5, vt_total=76, is_malicious=True)),
    )
    monkeypatch.setattr(
        enrichment.abuseipdb, "lookup_ip",
        AsyncMock(return_value=TIResult(source_ip="45.33.32.156", abuse_confidence=10, abuse_total_reports=1, is_malicious=False)),
    )

    log = _make_log(source_ip="45.33.32.156")
    enriched = await enrichment.enrich_log(session, log)

    assert enriched.ti_result.vt_malicious == 5
    assert enriched.ti_result.is_malicious is True  # VT says malicious even though AbuseIPDB doesn't
    assert len(session.added) == 2  # one ti_cache row per provider
    assert session.committed is True


@pytest.mark.asyncio
async def test_hash_indicator_only_queries_virustotal(monkeypatch):
    session = _FakeSession(cache_rows=[None])
    vt_lookup = AsyncMock(return_value=TIResult(file_hash="abc123", vt_malicious=40, vt_total=60, is_malicious=True))
    abuse_lookup = AsyncMock(side_effect=AssertionError("AbuseIPDB doesn't support hash lookups"))
    monkeypatch.setattr(enrichment.virustotal, "lookup_hash", vt_lookup)
    monkeypatch.setattr(enrichment.abuseipdb, "lookup_ip", abuse_lookup)

    log = _make_log(file_hash="abc123")
    enriched = await enrichment.enrich_log(session, log)

    vt_lookup.assert_called_once_with("abc123")
    abuse_lookup.assert_not_called()
    assert enriched.ti_result.file_hash == "abc123"
    assert enriched.ti_result.is_malicious is True


# ── SS-025: external API outage doesn't raise past the service boundary ──

@pytest.mark.asyncio
async def test_provider_outage_with_no_cache_falls_back_to_no_op_for_that_provider(monkeypatch):
    session = _FakeSession(cache_rows=[None, None])
    monkeypatch.setattr(enrichment.virustotal, "lookup_ip", AsyncMock(side_effect=VirusTotalError("VT is down")))
    monkeypatch.setattr(enrichment.abuseipdb, "lookup_ip", AsyncMock(side_effect=AbuseIPDBError("AbuseIPDB is down")))

    log = _make_log(source_ip="45.33.32.156")
    enriched = await enrichment.enrich_log(session, log)  # must not raise

    assert enriched.ti_enriched is True
    assert enriched.ti_result.vt_malicious == 0
    assert enriched.ti_result.abuse_confidence == 0
    assert enriched.ti_result.is_malicious is False


@pytest.mark.asyncio
async def test_provider_outage_with_stale_cache_falls_back_to_stale_result(monkeypatch):
    expired_at = datetime.now(timezone.utc) - timedelta(hours=1)
    stale_row = _FakeCacheRow({"vt_malicious": 8, "vt_total": 70, "is_malicious": True}, True, expired_at)
    session = _FakeSession(cache_rows=[stale_row, None])

    monkeypatch.setattr(enrichment.virustotal, "lookup_ip", AsyncMock(side_effect=VirusTotalError("VT is down")))
    monkeypatch.setattr(enrichment.abuseipdb, "lookup_ip", AsyncMock(side_effect=AbuseIPDBError("AbuseIPDB is down")))

    log = _make_log(source_ip="45.33.32.156")
    enriched = await enrichment.enrich_log(session, log)  # must not raise

    assert enriched.ti_result.vt_malicious == 8  # served from stale cache
    assert enriched.ti_result.is_malicious is True


# ── SS-025: no indicator present is a no-op ───────────────────────

@pytest.mark.asyncio
async def test_log_without_ip_or_hash_is_a_no_op(_mock_opensearch_update):
    session = _FakeSession()
    log = _make_log()  # no source_ip, no file_hash

    result = await enrichment.enrich_log(session, log)

    assert result is log
    assert result.ti_enriched is False
    _mock_opensearch_update.assert_not_called()


# ── SS-025: writes back to the OpenSearch document ────────────────

@pytest.mark.asyncio
async def test_enrichment_updates_the_opensearch_document(monkeypatch, _mock_opensearch_update):
    session = _FakeSession(cache_rows=[None, None])
    monkeypatch.setattr(
        enrichment.virustotal, "lookup_ip",
        AsyncMock(return_value=TIResult(source_ip="45.33.32.156", vt_malicious=5, vt_total=76, is_malicious=True)),
    )
    monkeypatch.setattr(
        enrichment.abuseipdb, "lookup_ip",
        AsyncMock(return_value=TIResult(source_ip="45.33.32.156", is_malicious=False)),
    )

    log = _make_log(source_ip="45.33.32.156")
    enriched = await enrichment.enrich_log(session, log)

    _mock_opensearch_update.assert_called_once()
    call_kwargs = _mock_opensearch_update.call_args.kwargs
    assert call_kwargs["alert_id"] == enriched.alert_id
    assert call_kwargs["ti_enriched"] is True
    assert call_kwargs["risk_score"] == enriched.risk_score


@pytest.mark.asyncio
async def test_malicious_result_applies_the_configured_risk_score_bonus(monkeypatch):
    from app.core.config import settings

    session = _FakeSession(cache_rows=[None, None])
    monkeypatch.setattr(
        enrichment.virustotal, "lookup_ip",
        AsyncMock(return_value=TIResult(source_ip="45.33.32.156", vt_malicious=5, is_malicious=True)),
    )
    monkeypatch.setattr(
        enrichment.abuseipdb, "lookup_ip",
        AsyncMock(return_value=TIResult(source_ip="45.33.32.156", is_malicious=False)),
    )

    log = _make_log(source_ip="45.33.32.156")
    enriched = await enrichment.enrich_log(session, log)

    assert enriched.risk_score == settings.RISK_SCORE_TI_MALICIOUS_BONUS
