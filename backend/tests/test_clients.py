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
    # 404 is "not found", not an error (see the not_found tests below); any other HTTP error still raises.
    response = Mock(status_code=500)
    response.raise_for_status.side_effect = requests.exceptions.HTTPError("500 Server Error")
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


# ── Rich IP details (VTIPDetails / AbuseIPDetails) ─────────────────

def _fake_json_response(payload: dict) -> Mock:
    response = Mock()
    response.raise_for_status = Mock()
    response.json.return_value = payload
    return response


def _vt_engine(name: str, category: str, result: str) -> dict:
    return {"method": "blacklist", "engine_name": name, "category": category, "result": result}


# Trimmed but structurally faithful VirusTotal v3 ip_addresses/{ip} response.
VT_IP_FIXTURE = {
    "data": {
        "id": "140.246.61.93",
        "type": "ip_address",
        "attributes": {
            "network": "140.246.0.0/16",
            "tags": ["suspicious-udp", "scanner"],
            "country": "CN",
            "as_owner": "Example Hosting Ltd",
            "asn": 4134,
            "continent": "AS",
            "reputation": -11,
            "last_analysis_date": 1767225600,  # 2026-01-01T00:00:00Z
            "last_analysis_stats": {"malicious": 3, "suspicious": 1, "undetected": 25, "harmless": 60, "timeout": 0},
            "last_analysis_results": {
                "Zeta": _vt_engine("Zeta", "suspicious", "suspicious"),
                "BitDefender": _vt_engine("BitDefender", "malicious", "malware"),
                "Kaspersky": _vt_engine("Kaspersky", "harmless", "clean"),
                "alphaMountain.ai": _vt_engine("alphaMountain.ai", "malicious", "malicious"),
                "CRDF": _vt_engine("CRDF", "malicious", "malicious"),
                "Avira": _vt_engine("Avira", "undetected", "unrated"),
            },
            "whois": "irrelevant",
        },
    }
}

# AbuseIPDB v2 /check response.
ABUSE_CHECK_FIXTURE = {
    "data": {
        "ipAddress": "140.246.61.93",
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 87,
        "countryCode": "CN",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example Hosting Ltd",
        "domain": "example-hosting.cn",
        "hostnames": ["scan-1.example-hosting.cn"],
        "isTor": False,
        "totalReports": 42,
        "numDistinctUsers": 17,
        "lastReportedAt": "2026-10-20T08:15:30+00:00",
    }
}


@pytest.mark.asyncio
async def test_vt_lookup_ip_maps_every_detail_field(monkeypatch):
    from datetime import datetime, timezone

    monkeypatch.setattr(virustotal.requests, "get", Mock(return_value=_fake_json_response(VT_IP_FIXTURE)))

    result = await virustotal.lookup_ip("140.246.61.93")

    vt = result.vt
    assert (vt.malicious, vt.suspicious, vt.harmless, vt.undetected, vt.total) == (3, 1, 60, 25, 89)
    assert vt.total == result.vt_total
    assert vt.reputation == -11
    assert vt.asn == 4134
    assert vt.as_owner == "Example Hosting Ltd"
    assert vt.network == "140.246.0.0/16"
    assert vt.country == "CN"
    assert vt.last_analysis_date == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert vt.tags == ["suspicious-udp", "scanner"]
    assert result.abuse is None
    # Headline fields and verdict are unchanged by the richer parse.
    assert result.vt_malicious == 3
    assert result.is_malicious is True


@pytest.mark.asyncio
async def test_vt_flagged_by_keeps_only_malicious_and_suspicious_malicious_first(monkeypatch):
    monkeypatch.setattr(virustotal.requests, "get", Mock(return_value=_fake_json_response(VT_IP_FIXTURE)))

    result = await virustotal.lookup_ip("140.246.61.93")

    flagged = [(f.engine, f.category, f.result) for f in result.vt.flagged_by]
    assert flagged == [
        ("alphaMountain.ai", "malicious", "malicious"),
        ("BitDefender", "malicious", "malware"),
        ("CRDF", "malicious", "malicious"),
        ("Zeta", "suspicious", "suspicious"),
    ]


@pytest.mark.asyncio
async def test_vt_flagged_by_is_capped_at_twenty(monkeypatch):
    results = {f"S{i:02}": _vt_engine(f"S{i:02}", "suspicious", "suspicious") for i in range(10)}
    results.update({f"M{i:02}": _vt_engine(f"M{i:02}", "malicious", "malware") for i in range(25)})
    payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 25, "suspicious": 10}, "last_analysis_results": results}}}
    monkeypatch.setattr(virustotal.requests, "get", Mock(return_value=_fake_json_response(payload)))

    result = await virustotal.lookup_ip("140.246.61.93")

    assert len(result.vt.flagged_by) == virustotal.FLAGGED_BY_LIMIT == 20
    assert all(f.category == "malicious" for f in result.vt.flagged_by)


@pytest.mark.asyncio
async def test_vt_lookup_ip_with_missing_keys_defaults_instead_of_raising(monkeypatch):
    payload = {"data": {"attributes": {"last_analysis_date": "not-a-number"}}}
    monkeypatch.setattr(virustotal.requests, "get", Mock(return_value=_fake_json_response(payload)))

    result = await virustotal.lookup_ip("140.246.61.93")

    vt = result.vt
    assert vt.reputation is None and vt.asn is None and vt.as_owner is None
    assert vt.network is None and vt.country is None and vt.last_analysis_date is None
    assert vt.tags == [] and vt.flagged_by == [] and vt.total == 0
    assert result.is_malicious is False


@pytest.mark.asyncio
async def test_vt_hash_lookup_carries_no_ip_details(monkeypatch):
    monkeypatch.setattr(virustotal.requests, "get", Mock(return_value=_fake_json_response(VT_IP_FIXTURE)))

    result = await virustotal.lookup_hash("44d88612fea8a8f36de82e1278abb02f")

    assert result.vt is None


@pytest.mark.asyncio
async def test_abuseipdb_lookup_ip_maps_every_detail_field(monkeypatch):
    from datetime import datetime, timezone

    monkeypatch.setattr(abuseipdb.requests, "get", Mock(return_value=_fake_json_response(ABUSE_CHECK_FIXTURE)))

    result = await abuseipdb.lookup_ip("140.246.61.93")

    abuse = result.abuse
    assert abuse.confidence == 87
    assert abuse.total_reports == 42
    assert abuse.num_distinct_users == 17
    assert abuse.last_reported_at == datetime(2026, 10, 20, 8, 15, 30, tzinfo=timezone.utc)
    assert abuse.isp == "Example Hosting Ltd"
    assert abuse.usage_type == "Data Center/Web Hosting/Transit"
    assert abuse.domain == "example-hosting.cn"
    assert abuse.country_code == "CN"
    assert abuse.hostnames == ["scan-1.example-hosting.cn"]
    assert abuse.is_tor is False
    assert abuse.is_whitelisted is False
    assert abuse.max_age_days == 90
    assert result.vt is None
    assert result.abuse_confidence == 87 and result.is_malicious is True


@pytest.mark.asyncio
async def test_abuseipdb_lookup_ip_with_missing_keys_defaults_instead_of_raising(monkeypatch):
    payload = {"data": {"lastReportedAt": None, "hostnames": None}}
    monkeypatch.setattr(abuseipdb.requests, "get", Mock(return_value=_fake_json_response(payload)))

    result = await abuseipdb.lookup_ip("140.246.61.93")

    abuse = result.abuse
    assert (abuse.confidence, abuse.total_reports, abuse.num_distinct_users) == (0, 0, 0)
    assert abuse.last_reported_at is None and abuse.isp is None and abuse.usage_type is None
    assert abuse.domain is None and abuse.country_code is None and abuse.is_whitelisted is None
    assert abuse.hostnames == [] and abuse.is_tor is False
    assert result.is_malicious is False


# ── VirusTotal 404 = "not seen before", not an error ─────────────

def _not_found_response() -> Mock:
    response = Mock(status_code=404)
    response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Not Found")
    return response


@pytest.mark.asyncio
async def test_vt_lookup_hash_404_is_a_not_found_result_not_an_error(monkeypatch):
    monkeypatch.setattr(virustotal.requests, "get", Mock(return_value=_not_found_response()))

    result = await virustotal.lookup_hash("ab" * 32)

    assert result.not_found is True
    assert (result.is_malicious, result.vt_malicious, result.vt_total) == (False, 0, 0)
    assert result.file_hash == "ab" * 32


@pytest.mark.asyncio
async def test_vt_lookup_ip_404_is_a_not_found_result_not_an_error(monkeypatch):
    monkeypatch.setattr(virustotal.requests, "get", Mock(return_value=_not_found_response()))

    result = await virustotal.lookup_ip("140.246.61.93")

    assert result.not_found is True
    assert (result.is_malicious, result.vt_malicious, result.vt_total) == (False, 0, 0)
    assert result.source_ip == "140.246.61.93" and result.vt is None


@pytest.mark.asyncio
async def test_vt_found_result_is_not_marked_not_found(monkeypatch):
    monkeypatch.setattr(virustotal.requests, "get", Mock(return_value=_fake_response({"harmless": 70})))
    assert (await virustotal.lookup_hash("ab" * 32)).not_found is False
