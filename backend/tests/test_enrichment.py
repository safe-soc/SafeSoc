"""
SafeSOC — Enrichment Service Tests
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock

import pytest
import requests

from app.clients.abuseipdb import AbuseIPDBError
from app.clients.virustotal import VirusTotalError
from app.core.config import Settings, settings
from app.core.enums import TIDetailStatus, TIProvider
from app.schemas.log import NormalizedLog, TIResult
from app.services import enrichment
from app.services.ip_threat_intel import get_ip_threat_intel


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

    log = _make_log(file_hash="abc123", severity="high")  # at HASH_ENRICHMENT_MIN_SEVERITY
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


# ── Per-provider IP details survive the merge ─────────────────────

@pytest.mark.asyncio
async def test_merge_keeps_vt_details_from_vt_and_abuse_details_from_abuseipdb(monkeypatch, _mock_opensearch_update):
    from app.schemas.log import AbuseIPDetails, VTIPDetails

    session = _FakeSession(cache_rows=[None, None])
    monkeypatch.setattr(
        enrichment.virustotal, "lookup_ip",
        AsyncMock(return_value=TIResult(
            source_ip="140.246.61.93", vt_malicious=2, vt_total=80, is_malicious=True,
            vt=VTIPDetails(malicious=2, total=80, as_owner="Example AS"),
        )),
    )
    monkeypatch.setattr(
        enrichment.abuseipdb, "lookup_ip",
        AsyncMock(return_value=TIResult(
            source_ip="140.246.61.93", abuse_confidence=40, is_malicious=False,
            abuse=AbuseIPDetails(confidence=40, isp="Example ISP"),
        )),
    )

    enriched = await enrichment.enrich_log(session, _make_log(source_ip="140.246.61.93"))

    assert enriched.ti_result.vt is not None and enriched.ti_result.vt.as_owner == "Example AS"
    assert enriched.ti_result.abuse is not None and enriched.ti_result.abuse.isp == "Example ISP"
    # Written to OpenSearch with both blocks too.
    dumped = _mock_opensearch_update.call_args.kwargs["ti_result"]
    assert dumped["vt"]["malicious"] == 2 and dumped["abuse"]["confidence"] == 40


@pytest.mark.asyncio
async def test_old_cache_rows_without_details_still_load(monkeypatch):
    now = datetime.now(timezone.utc)
    vt_row = _FakeCacheRow({"vt_malicious": 0, "vt_total": 70, "is_malicious": False}, False, now + timedelta(days=1))
    abuse_row = _FakeCacheRow({"abuse_confidence": 0, "is_malicious": False}, False, now + timedelta(days=1))
    session = _FakeSession(cache_rows=[vt_row, abuse_row])

    enriched = await enrichment.enrich_log(session, _make_log(source_ip="140.246.61.93"))

    assert enriched.ti_result.vt is None
    assert enriched.ti_result.abuse is None
    assert enriched.ti_result.vt_total == 70


# ── fetched_at and forced refresh ─────────────────────────────────

@pytest.mark.asyncio
async def test_successful_provider_call_stamps_fetched_at(monkeypatch):
    from app.core.enums import TIProvider

    session = _FakeSession(cache_rows=[None])
    monkeypatch.setattr(enrichment, "_write_cache", AsyncMock())
    before = datetime.now(timezone.utc)

    result = await enrichment._get_or_fetch(session, "140.246.61.93", TIProvider.VIRUSTOTAL, AsyncMock(return_value=TIResult(vt_total=70)))

    assert result.fetched_at is not None and result.fetched_at >= before
    written = enrichment._write_cache.call_args.args[3]
    assert written.fetched_at == result.fetched_at  # persisted with the row


@pytest.mark.asyncio
async def test_cache_hit_keeps_the_stored_fetched_at(monkeypatch):
    from app.core.enums import TIProvider

    stored = "2026-10-01T12:00:00+00:00"
    row = _FakeCacheRow({"vt_total": 70, "fetched_at": stored}, False, datetime.now(timezone.utc) + timedelta(days=1))
    fetch = AsyncMock(side_effect=AssertionError("must not be called on a fresh cache hit"))

    result = await enrichment._get_or_fetch(_FakeSession(cache_rows=[row]), "140.246.61.93", TIProvider.VIRUSTOTAL, fetch)

    assert result.fetched_at == datetime(2026, 10, 1, 12, tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_force_calls_the_provider_even_with_a_fresh_cache_row(monkeypatch):
    from app.core.enums import TIProvider

    row = _FakeCacheRow({"vt_total": 70}, False, datetime.now(timezone.utc) + timedelta(days=1))
    monkeypatch.setattr(enrichment, "_write_cache", AsyncMock())
    fetch = AsyncMock(return_value=TIResult(vt_total=90))

    result = await enrichment._get_or_fetch(_FakeSession(cache_rows=[row]), "140.246.61.93", TIProvider.VIRUSTOTAL, fetch, force=True)

    fetch.assert_awaited_once()
    assert result.vt_total == 90
    enrichment._write_cache.assert_awaited_once()


@pytest.mark.asyncio
async def test_force_with_provider_failure_falls_back_to_the_stored_row(monkeypatch):
    from app.core.enums import TIProvider

    row = _FakeCacheRow({"vt_total": 70, "fetched_at": "2026-10-01T12:00:00+00:00"}, False, datetime.now(timezone.utc) + timedelta(days=1))
    monkeypatch.setattr(enrichment, "_write_cache", AsyncMock())
    fetch = AsyncMock(side_effect=VirusTotalError("down"))

    result = await enrichment._get_or_fetch(_FakeSession(cache_rows=[row]), "140.246.61.93", TIProvider.VIRUSTOTAL, fetch, force=True)

    assert result.vt_total == 70
    assert result.fetched_at == datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
    enrichment._write_cache.assert_not_awaited()


@pytest.mark.asyncio
async def test_refresh_ip_forces_both_providers(monkeypatch):
    now = datetime.now(timezone.utc)
    fresh = lambda r: _FakeCacheRow(r, False, now + timedelta(days=1))  # noqa: E731
    session = _FakeSession(cache_rows=[fresh({"vt_total": 1}), None, fresh({"abuse_confidence": 1}), None])
    vt_lookup = AsyncMock(return_value=TIResult(vt_total=70))
    abuse_lookup = AsyncMock(return_value=TIResult(abuse_confidence=5))
    monkeypatch.setattr(enrichment.virustotal, "lookup_ip", vt_lookup)
    monkeypatch.setattr(enrichment.abuseipdb, "lookup_ip", abuse_lookup)

    result = await enrichment.refresh_ip(session, "140.246.61.93")

    vt_lookup.assert_awaited_once()
    abuse_lookup.assert_awaited_once()
    assert result.vt_total == 70 and result.abuse_confidence == 5


# ── Non-public IPs are never looked up ───────────────────────────

def _mock_providers(monkeypatch) -> tuple[AsyncMock, AsyncMock, AsyncMock]:
    vt_lookup = AsyncMock(return_value=TIResult(vt_total=70))
    abuse_lookup = AsyncMock(return_value=TIResult(abuse_confidence=5))
    write_cache = AsyncMock()
    monkeypatch.setattr(enrichment.virustotal, "lookup_ip", vt_lookup)
    monkeypatch.setattr(enrichment.abuseipdb, "lookup_ip", abuse_lookup)
    monkeypatch.setattr(enrichment, "_write_cache", write_cache)
    return vt_lookup, abuse_lookup, write_cache


NON_PUBLIC_IPS = [
    "10.10.10.23",      # private
    "192.168.1.42",     # private
    "203.0.113.5",      # documentation (TEST-NET-3)
    "198.51.100.23",    # documentation (TEST-NET-2)
    "127.0.0.1",        # loopback
    "0.0.0.0",          # unspecified
    "not-an-ip",        # invalid
]


@pytest.mark.asyncio
@pytest.mark.parametrize("ip", NON_PUBLIC_IPS)
async def test_enrich_log_never_looks_up_a_non_public_ip(monkeypatch, _mock_opensearch_update, ip):
    vt_lookup, abuse_lookup, write_cache = _mock_providers(monkeypatch)
    session = _FakeSession()
    log = _make_log(source_ip=ip)

    result = await enrichment.enrich_log(session, log)

    vt_lookup.assert_not_awaited()
    abuse_lookup.assert_not_awaited()
    write_cache.assert_not_awaited()
    assert session.added == []
    _mock_opensearch_update.assert_not_awaited()
    assert result.ti_enriched is False and result.ti_result is None


@pytest.mark.asyncio
async def test_enrich_log_with_a_private_ip_falls_through_to_its_file_hash(monkeypatch):
    vt_lookup, abuse_lookup, _ = _mock_providers(monkeypatch)
    hash_lookup = AsyncMock(return_value=TIResult(vt_malicious=0, vt_total=70))
    monkeypatch.setattr(enrichment.virustotal, "lookup_hash", hash_lookup)

    result = await enrichment.enrich_log(_FakeSession(), _make_log(source_ip="10.10.10.23", file_hash="ab" * 32, severity="high"))

    vt_lookup.assert_not_awaited()
    abuse_lookup.assert_not_awaited()
    hash_lookup.assert_awaited_once_with("ab" * 32)
    assert result.ti_enriched is True and result.ti_result.file_hash == "ab" * 32


@pytest.mark.asyncio
async def test_enrich_log_looks_up_a_public_ip(monkeypatch):
    vt_lookup, abuse_lookup, write_cache = _mock_providers(monkeypatch)

    result = await enrichment.enrich_log(_FakeSession(), _make_log(source_ip="140.246.61.93"))

    vt_lookup.assert_awaited_once_with("140.246.61.93")
    abuse_lookup.assert_awaited_once_with("140.246.61.93")
    assert write_cache.await_count == 2
    assert result.ti_enriched is True


@pytest.mark.asyncio
@pytest.mark.parametrize("ip", NON_PUBLIC_IPS)
async def test_enrich_indicator_and_refresh_never_look_up_a_non_public_ip(monkeypatch, ip):
    vt_lookup, abuse_lookup, write_cache = _mock_providers(monkeypatch)

    await enrichment.enrich_indicator(_FakeSession(), ip)
    await enrichment.refresh_ip(_FakeSession(), ip)

    vt_lookup.assert_not_awaited()
    abuse_lookup.assert_not_awaited()
    write_cache.assert_not_awaited()


# ── VirusTotal 404 is cached like a clean result ─────────────────

def _vt_status(monkeypatch, status_code: int) -> Mock:
    response = Mock(status_code=status_code)
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(f"{status_code} error")
    get = Mock(return_value=response)
    monkeypatch.setattr(enrichment.virustotal.requests, "get", get)
    monkeypatch.setattr(enrichment.virustotal, "_enforce_rate_limit", lambda: None)
    return get


def _fetch_hash():
    return enrichment.virustotal.lookup_hash("ab" * 32)


@pytest.mark.asyncio
async def test_a_vt_404_is_cached_as_not_found_and_the_next_lookup_hits_the_cache(monkeypatch):
    get = _vt_status(monkeypatch, 404)
    first_session = _FakeSession()

    first = await enrichment._get_or_fetch(first_session, "ab" * 32, TIProvider.VIRUSTOTAL, _fetch_hash)

    assert first.not_found is True and first.is_malicious is False
    assert get.call_count == 1
    [row] = first_session.added
    assert row.result["not_found"] is True and row.is_malicious is False
    clean_expiry = datetime.now(timezone.utc) + timedelta(seconds=settings.TI_CACHE_CLEAN_TTL)
    assert abs((row.expires_at - clean_expiry).total_seconds()) < 60

    second = await enrichment._get_or_fetch(_FakeSession(cache_rows=[row]), "ab" * 32, TIProvider.VIRUSTOTAL, _fetch_hash)

    assert get.call_count == 1  # served from ti_cache: VirusTotal not called again
    assert second.not_found is True


@pytest.mark.asyncio
async def test_a_vt_500_still_fails_and_falls_back(monkeypatch):
    _vt_status(monkeypatch, 500)

    with pytest.raises(VirusTotalError):
        await _fetch_hash()

    nothing_cached = _FakeSession()
    assert await enrichment._get_or_fetch(nothing_cached, "ab" * 32, TIProvider.VIRUSTOTAL, _fetch_hash) is None
    assert nothing_cached.added == []

    stale = _FakeCacheRow({"vt_malicious": 2, "vt_total": 70, "is_malicious": True}, True, datetime.now(timezone.utc) - timedelta(days=1))
    fallback = await enrichment._get_or_fetch(_FakeSession(cache_rows=[stale]), "ab" * 32, TIProvider.VIRUSTOTAL, _fetch_hash)
    assert fallback.vt_malicious == 2 and fallback.not_found is False


@pytest.mark.asyncio
async def test_merged_alert_result_carries_vt_not_found(monkeypatch):
    monkeypatch.setattr(enrichment.virustotal, "lookup_hash", AsyncMock(return_value=TIResult(file_hash="ab" * 32, not_found=True)))

    enriched = await enrichment.enrich_log(_FakeSession(), _make_log(file_hash="ab" * 32, severity="critical"))

    assert enriched.ti_result.not_found is True


# ── HASH_ENRICHMENT_MIN_SEVERITY gate ────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("minimum, severity, looked_up", [
    ("high", "low", False),
    ("high", "medium", False),
    ("high", "high", True),
    ("high", "critical", True),
    ("low", "low", True),
    ("critical", "high", False),
    ("critical", "critical", True),
    ("off", "low", False),
    ("off", "critical", False),
])
async def test_hash_enrichment_respects_the_minimum_severity(monkeypatch, _mock_opensearch_update, minimum, severity, looked_up):
    monkeypatch.setattr(enrichment.settings, "HASH_ENRICHMENT_MIN_SEVERITY", minimum)
    hash_lookup = AsyncMock(return_value=TIResult(vt_total=70))
    monkeypatch.setattr(enrichment.virustotal, "lookup_hash", hash_lookup)

    result = await enrichment.enrich_log(_FakeSession(), _make_log(file_hash="ab" * 32, severity=severity))

    assert hash_lookup.await_count == (1 if looked_up else 0)
    assert result.ti_enriched is looked_up
    assert _mock_opensearch_update.await_count == (1 if looked_up else 0)


@pytest.mark.asyncio
async def test_the_hash_gate_does_not_affect_ip_enrichment(monkeypatch):
    monkeypatch.setattr(enrichment.settings, "HASH_ENRICHMENT_MIN_SEVERITY", "off")
    vt_lookup, abuse_lookup, _ = _mock_providers(monkeypatch)

    result = await enrichment.enrich_log(_FakeSession(), _make_log(source_ip="140.246.61.93", severity="low"))

    vt_lookup.assert_awaited_once()
    abuse_lookup.assert_awaited_once()
    assert result.ti_enriched is True


def test_hash_enrichment_min_severity_rejects_unknown_values():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Settings(HASH_ENRICHMENT_MIN_SEVERITY="sometimes")


# ── Threat-intel card status for a VirusTotal "not found" row ────

class _IntelRow:
    def __init__(self, provider: TIProvider, result: TIResult):
        self.indicator, self.provider = "140.246.61.93", provider
        self.result = result.model_dump(mode="json")
        self.is_malicious, self.created_at = False, datetime.now(timezone.utc)


class _IntelDb:
    def __init__(self, rows):
        self._rows = rows

    async def execute(self, stmt):
        return self

    def scalars(self):
        return self

    def all(self):
        return self._rows


@pytest.mark.asyncio
async def test_ip_threat_intel_reports_vt_not_found_rather_than_legacy():
    db = _IntelDb([
        _IntelRow(TIProvider.VIRUSTOTAL, TIResult(source_ip="140.246.61.93", not_found=True)),
        _IntelRow(TIProvider.ABUSEIPDB, TIResult(source_ip="140.246.61.93")),
    ])

    intel = (await get_ip_threat_intel(db, ["140.246.61.93"]))["140.246.61.93"]

    assert intel.vt_status == TIDetailStatus.NOT_FOUND
    assert intel.vt is None
    assert intel.abuse_status == TIDetailStatus.LEGACY
