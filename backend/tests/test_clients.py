"""
SafeSOC — Threat Intel Client Tests
"""

from unittest.mock import Mock

import pytest
import requests

from app.clients import abuseipdb, virustotal
from app.schemas.log import TIResult


@pytest.fixture(autouse=True)
def _reset_vt_rate_limiter():
    """Each test starts with a clean rate-limit window, regardless of test order."""
    virustotal._call_timestamps.clear()
    yield
    virustotal._call_timestamps.clear()


@pytest.fixture(autouse=True)
def _reset_abuseipdb_rate_limiter():
    """Each test starts with a clean rate-limit window, regardless of test order."""
    abuseipdb._call_timestamps.clear()
    yield
    abuseipdb._call_timestamps.clear()


def _fake_response(stats: dict) -> Mock:
    response = Mock()
    response.raise_for_status = Mock()
    response.json.return_value = {"data": {"attributes": {"last_analysis_stats": stats}}}
    return response


# ── SS-022: normalized TIResult shape ─────────────────────────────

@pytest.mark.asyncio
async def test_lookup_ip_returns_normalized_ti_result_for_a_malicious_ip(monkeypatch):
    stats = {"malicious": 5, "suspicious": 1, "undetected": 60, "harmless": 10, "timeout": 0}
    monkeypatch.setattr(virustotal.requests, "get", Mock(return_value=_fake_response(stats)))

    result = await virustotal.lookup_ip("45.33.32.156")

    assert isinstance(result, TIResult)
    assert result.source_ip == "45.33.32.156"
    assert result.vt_malicious == 5
    assert result.vt_total == 76
    assert result.is_malicious is True


@pytest.mark.asyncio
async def test_lookup_ip_returns_not_malicious_for_a_clean_ip(monkeypatch):
    stats = {"malicious": 0, "suspicious": 0, "undetected": 70, "harmless": 10, "timeout": 0}
    monkeypatch.setattr(virustotal.requests, "get", Mock(return_value=_fake_response(stats)))

    result = await virustotal.lookup_ip("8.8.8.8")

    assert result.vt_malicious == 0
    assert result.is_malicious is False


@pytest.mark.asyncio
async def test_lookup_hash_returns_normalized_ti_result(monkeypatch):
    stats = {"malicious": 40, "suspicious": 2, "undetected": 20, "harmless": 0, "timeout": 0}
    monkeypatch.setattr(virustotal.requests, "get", Mock(return_value=_fake_response(stats)))

    result = await virustotal.lookup_hash("d41d8cd98f00b204e9800998ecf8427e")

    assert result.file_hash == "d41d8cd98f00b204e9800998ecf8427e"
    assert result.vt_malicious == 40
    assert result.is_malicious is True


# ── SS-022: client-side rate limiting ──────────────────────────────

def test_rate_limit_is_enforced_when_limit_is_reached(monkeypatch):
    monkeypatch.setattr(virustotal.settings, "VT_RATE_LIMIT_PER_MINUTE", 1)
    sleep_mock = Mock()
    monkeypatch.setattr(virustotal.time, "sleep", sleep_mock)

    virustotal._enforce_rate_limit()  # 1st call: under the limit of 1, no sleep
    sleep_mock.assert_not_called()

    virustotal._enforce_rate_limit()  # 2nd call: limit reached, must block
    sleep_mock.assert_called_once()


def test_rate_limit_does_not_block_when_under_the_limit(monkeypatch):
    monkeypatch.setattr(virustotal.settings, "VT_RATE_LIMIT_PER_MINUTE", 4)
    sleep_mock = Mock()
    monkeypatch.setattr(virustotal.time, "sleep", sleep_mock)

    for _ in range(4):
        virustotal._enforce_rate_limit()

    sleep_mock.assert_not_called()


# ── SS-022: typed exception on network failure ─────────────────────

def test_network_failure_raises_typed_exception_not_requests_exception(monkeypatch):
    def _raise(*args, **kwargs):
        raise requests.exceptions.ConnectionError("connection refused")

    monkeypatch.setattr(virustotal.requests, "get", _raise)

    with pytest.raises(virustotal.VirusTotalError):
        virustotal._get("ip_addresses/45.33.32.156")


def test_http_error_status_raises_typed_exception(monkeypatch):
    response = Mock()
    response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Not Found")
    monkeypatch.setattr(virustotal.requests, "get", Mock(return_value=response))

    with pytest.raises(virustotal.VirusTotalError):
        virustotal._get("ip_addresses/45.33.32.156")


# ── SS-023: AbuseIPDB client (same shape/behavior contract as SS-022) ──

def _fake_abuseipdb_response(confidence: int, total_reports: int) -> Mock:
    response = Mock()
    response.raise_for_status = Mock()
    response.json.return_value = {
        "data": {"abuseConfidenceScore": confidence, "totalReports": total_reports}
    }
    return response


@pytest.mark.asyncio
async def test_abuseipdb_lookup_ip_returns_normalized_ti_result_for_a_malicious_ip(monkeypatch):
    monkeypatch.setattr(abuseipdb.requests, "get", Mock(return_value=_fake_abuseipdb_response(90, 15)))

    result = await abuseipdb.lookup_ip("45.33.32.156")

    assert isinstance(result, TIResult)
    assert result.source_ip == "45.33.32.156"
    assert result.abuse_confidence == 90
    assert result.abuse_total_reports == 15
    assert result.is_malicious is True


@pytest.mark.asyncio
async def test_abuseipdb_lookup_ip_returns_not_malicious_for_a_clean_ip(monkeypatch):
    monkeypatch.setattr(abuseipdb.requests, "get", Mock(return_value=_fake_abuseipdb_response(0, 0)))

    result = await abuseipdb.lookup_ip("8.8.8.8")

    assert result.abuse_confidence == 0
    assert result.is_malicious is False


@pytest.mark.asyncio
async def test_abuseipdb_confidence_below_threshold_is_not_malicious(monkeypatch):
    monkeypatch.setattr(
        abuseipdb.requests, "get",
        Mock(return_value=_fake_abuseipdb_response(abuseipdb.MALICIOUS_CONFIDENCE_THRESHOLD - 1, 1)),
    )

    result = await abuseipdb.lookup_ip("1.2.3.4")

    assert result.is_malicious is False


def test_abuseipdb_daily_rate_limit_is_tracked_and_raises_once_exhausted(monkeypatch):
    monkeypatch.setattr(abuseipdb.settings, "ABUSEIPDB_RATE_LIMIT_PER_DAY", 2)

    abuseipdb._check_rate_limit()  # 1st call: fine
    abuseipdb._check_rate_limit()  # 2nd call: fine, quota now exhausted

    with pytest.raises(abuseipdb.AbuseIPDBError):
        abuseipdb._check_rate_limit()  # 3rd call: over the daily limit


def test_abuseipdb_network_failure_raises_typed_exception(monkeypatch):
    def _raise(*args, **kwargs):
        raise requests.exceptions.ConnectionError("connection refused")

    monkeypatch.setattr(abuseipdb.requests, "get", _raise)

    with pytest.raises(abuseipdb.AbuseIPDBError):
        abuseipdb._get("check", {"ipAddress": "45.33.32.156"})
