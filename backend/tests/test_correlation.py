"""
SafeSOC — Correlation Engine Tests
"""

import pytest

from app.core.config import settings
from app.core.enums import CorrelationPattern
from app.services import correlation


class _FakeRedisClient:
    """
    Minimal in-memory sorted-set fake — enough to exercise correlation.py's
    real query/filter logic without a live Redis connection.
    """

    def __init__(self):
        self._zsets: dict[str, dict[str, float]] = {}
        self.expire_calls: list[tuple[str, int]] = []

    async def zadd(self, key, mapping):
        self._zsets.setdefault(key, {}).update(mapping)

    async def expire(self, key, ttl):
        self.expire_calls.append((key, ttl))

    async def zrangebyscore(self, key, min, max):
        members = self._zsets.get(key, {})
        return [
            member for member, score in sorted(members.items(), key=lambda kv: kv[1])
            if min <= score <= max
        ]


@pytest.fixture
def fake_redis(monkeypatch) -> _FakeRedisClient:
    client = _FakeRedisClient()
    monkeypatch.setattr(correlation, "get_client", lambda: client)
    return client


# ── SS-027: add + query a window ──────────────────────────────

@pytest.mark.asyncio
async def test_added_event_is_returned_by_get_events(fake_redis):
    now = 1_700_000_000.0
    await correlation.add_event("acme-corp", "DESKTOP-042", {"action": "failed_login"}, timestamp=now)

    events = await correlation.get_events("acme-corp", "DESKTOP-042", window_minutes=5, now=now)

    # add_event copies the score into the member so equal-score events
    # have a deterministic order (Redis would otherwise fall back to
    # comparing the JSON text).
    assert events == [{"action": "failed_login", "timestamp": now}]


@pytest.mark.asyncio
async def test_get_events_returns_multiple_events_oldest_first(fake_redis):
    now = 1_700_000_000.0
    await correlation.add_event("acme-corp", "DESKTOP-042", {"seq": 2}, timestamp=now - 10)
    await correlation.add_event("acme-corp", "DESKTOP-042", {"seq": 1}, timestamp=now - 20)
    await correlation.add_event("acme-corp", "DESKTOP-042", {"seq": 3}, timestamp=now)

    events = await correlation.get_events("acme-corp", "DESKTOP-042", window_minutes=5, now=now)

    assert [e["seq"] for e in events] == [1, 2, 3]


@pytest.mark.asyncio
async def test_get_events_is_scoped_per_host(fake_redis):
    now = 1_700_000_000.0
    await correlation.add_event("acme-corp", "HOST-A", {"host": "a"}, timestamp=now)
    await correlation.add_event("acme-corp", "HOST-B", {"host": "b"}, timestamp=now)

    events = await correlation.get_events("acme-corp", "HOST-A", window_minutes=5, now=now)

    assert [e["host"] for e in events] == ["a"]


@pytest.mark.asyncio
async def test_get_events_is_scoped_per_tenant(fake_redis):
    """Two tenants with the same host_id must not see each other's events — multi-tenancy isolation."""
    now = 1_700_000_000.0
    await correlation.add_event("tenant-a", "DESKTOP-042", {"tenant": "a"}, timestamp=now)
    await correlation.add_event("tenant-b", "DESKTOP-042", {"tenant": "b"}, timestamp=now)

    events = await correlation.get_events("tenant-a", "DESKTOP-042", window_minutes=5, now=now)

    assert [e["tenant"] for e in events] == ["a"]


# ── SS-027: old entries don't come back — time-manipulated, no real wait ──

@pytest.mark.asyncio
async def test_get_events_excludes_events_older_than_the_window(fake_redis):
    now = 1_700_000_000.0
    two_hours_ago = now - (2 * 3600)
    await correlation.add_event("acme-corp", "DESKTOP-042", {"stale": True}, timestamp=two_hours_ago)

    events = await correlation.get_events("acme-corp", "DESKTOP-042", window_minutes=60, now=now)

    assert events == []


@pytest.mark.asyncio
async def test_get_events_includes_events_at_the_exact_window_boundary(fake_redis):
    now = 1_700_000_000.0
    exactly_at_boundary = now - (60 * 60)  # exactly 60 minutes ago
    await correlation.add_event("acme-corp", "DESKTOP-042", {"boundary": True}, timestamp=exactly_at_boundary)

    events = await correlation.get_events("acme-corp", "DESKTOP-042", window_minutes=60, now=now)

    assert [e["boundary"] for e in events] == [True]


@pytest.mark.asyncio
async def test_get_events_defaults_to_the_current_time_when_now_is_omitted(fake_redis):
    await correlation.add_event("acme-corp", "DESKTOP-042", {"recent": True})

    events = await correlation.get_events("acme-corp", "DESKTOP-042", window_minutes=5)

    assert [e["recent"] for e in events] == [True]


def _event(alert_id, log_type, action, severity="low", user="john.doe", destination_ip=None):
    return {
        "alert_id": alert_id,
        "log_type": log_type,
        "action": action,
        "severity": severity,
        "user": user,
        "destination_ip": destination_ip,
    }


# ── Event-time ordering (ADR-011) ──────────────────────────────
#
# queue_post_ingest_tasks queues one Celery task per accepted alert and
# they run concurrently, so a window scored at PROCESSING time can hold
# the events of an attack chain in any order. Every test below adds
# events in the WRONG processing order with the RIGHT event timestamps,
# and asserts the order-sensitive detectors still fire — the
# privilege_escalation scenario's "alerts but no incident" bug.

@pytest.mark.asyncio
async def test_privilege_escalation_is_detected_when_the_events_are_processed_out_of_order(fake_redis):
    now = 1_700_000_000.0
    # Processed privilege-change first (the task that finished first)…
    await correlation.add_event(
        "acme-corp", "DESKTOP-042",
        _event("a2", "privilege", "permission_change", severity="critical"),
        timestamp=now - 30,
    )
    # …but it HAPPENED after the login.
    await correlation.add_event(
        "acme-corp", "DESKTOP-042",
        _event("a1", "authentication", "login_success"),
        timestamp=now - 60,
    )

    chains = await correlation.evaluate_host("acme-corp", "DESKTOP-042", now=now)

    patterns = {chain.pattern for chain in chains}
    assert CorrelationPattern.PRIVILEGE_ESCALATION in patterns
    chain = next(c for c in chains if c.pattern == CorrelationPattern.PRIVILEGE_ESCALATION)
    assert chain.alert_ids == ("a1", "a2")  # login first, in event order


@pytest.mark.asyncio
async def test_successful_compromise_is_detected_when_the_success_is_processed_first(fake_redis):
    now = 1_700_000_000.0
    await correlation.add_event(
        "acme-corp", "DESKTOP-042", _event("a-success", "authentication", "login_success"), timestamp=now - 10,
    )
    for i in range(correlation.BRUTE_FORCE_MIN_ATTEMPTS):
        await correlation.add_event(
            "acme-corp", "DESKTOP-042",
            _event(f"a{i}", "authentication", "failed_login"),
            timestamp=now - 60 + i,  # all earlier than the success
        )

    chains = await correlation.evaluate_host("acme-corp", "DESKTOP-042", now=now)

    patterns = {chain.pattern for chain in chains}
    assert CorrelationPattern.SUCCESSFUL_COMPROMISE in patterns
    chain = next(c for c in chains if c.pattern == CorrelationPattern.SUCCESSFUL_COMPROMISE)
    assert chain.alert_ids[-1] == "a-success"  # the success is last, after its failures


@pytest.mark.asyncio
async def test_privilege_escalation_is_not_detected_when_the_privilege_change_came_first(fake_redis):
    """The ordering still MATTERS — this isn't order-insensitivity, it's correct ordering."""
    now = 1_700_000_000.0
    await correlation.add_event(
        "acme-corp", "DESKTOP-042",
        _event("a1", "privilege", "permission_change", severity="critical"),
        timestamp=now - 60,
    )
    await correlation.add_event(
        "acme-corp", "DESKTOP-042", _event("a2", "authentication", "login_success"), timestamp=now - 30,
    )

    chains = await correlation.evaluate_host("acme-corp", "DESKTOP-042", now=now)

    assert CorrelationPattern.PRIVILEGE_ESCALATION not in {chain.pattern for chain in chains}


@pytest.mark.asyncio
async def test_an_event_whose_own_timestamp_predates_the_window_is_excluded(fake_redis):
    """
    A late-arriving (or deliberately backdated — injector/demo.py seeds
    weeks of history) log is not correlated, however recently it was
    processed. Intended: the window is "what happened in the last N
    minutes", in event time.
    """
    now = 1_700_000_000.0
    await correlation.add_event(
        "acme-corp", "DESKTOP-042", _event("old", "authentication", "login_success"), timestamp=now - (3 * 3600),
    )
    await correlation.add_event(
        "acme-corp", "DESKTOP-042",
        _event("new", "privilege", "permission_change", severity="critical"),
        timestamp=now - 30,
    )

    events = await correlation.get_events("acme-corp", "DESKTOP-042", window_minutes=60, now=now)
    chains = await correlation.evaluate_host("acme-corp", "DESKTOP-042", now=now)

    assert [e["alert_id"] for e in events] == ["new"]
    assert CorrelationPattern.PRIVILEGE_ESCALATION not in {chain.pattern for chain in chains}


@pytest.mark.asyncio
async def test_a_slightly_future_event_within_the_clock_skew_allowance_is_included(fake_redis):
    """An endpoint with a slightly fast clock still gets correlated, not silently skipped."""
    now = 1_700_000_000.0
    skewed = now + settings.CORRELATION_CLOCK_SKEW_SECONDS - 1
    await correlation.add_event("acme-corp", "DESKTOP-042", {"fast_clock": True}, timestamp=skewed)

    events = await correlation.get_events("acme-corp", "DESKTOP-042", window_minutes=60, now=now)

    assert [e["fast_clock"] for e in events] == [True]


@pytest.mark.asyncio
async def test_an_event_beyond_the_clock_skew_allowance_is_excluded(fake_redis):
    now = 1_700_000_000.0
    way_ahead = now + settings.CORRELATION_CLOCK_SKEW_SECONDS + 60
    await correlation.add_event("acme-corp", "DESKTOP-042", {"far_future": True}, timestamp=way_ahead)

    events = await correlation.get_events("acme-corp", "DESKTOP-042", window_minutes=60, now=now)

    assert events == []


@pytest.mark.asyncio
async def test_allow_future_skew_false_pins_the_ceiling_to_now(fake_redis):
    """services/anomaly.py's historical windows must not reach past their own `now`."""
    now = 1_700_000_000.0
    await correlation.add_event("acme-corp", "DESKTOP-042", {"slightly_ahead": True}, timestamp=now + 30)

    events = await correlation.get_events(
        "acme-corp", "DESKTOP-042", window_minutes=60, now=now, allow_future_skew=False
    )

    assert events == []


@pytest.mark.asyncio
async def test_add_event_stores_the_event_time_in_the_member(fake_redis):
    """Ties between equal scores are ordered by member string in Redis — the stored timestamp makes that deterministic."""
    now = 1_700_000_000.0
    await correlation.add_event("acme-corp", "DESKTOP-042", {"action": "failed_login"}, timestamp=now)

    events = await correlation.get_events("acme-corp", "DESKTOP-042", window_minutes=5, now=now)

    assert events[0]["timestamp"] == now


# ── SS-027: storage TTL (Redis-level expiry, from CORRELATION_WINDOW_TTL) ──

@pytest.mark.asyncio
async def test_add_event_sets_the_configured_ttl_on_the_window_key(fake_redis):
    await correlation.add_event("acme-corp", "DESKTOP-042", {"action": "failed_login"}, timestamp=1_700_000_000.0)

    assert fake_redis.expire_calls == [
        (correlation._window_key("acme-corp", "DESKTOP-042"), settings.CORRELATION_WINDOW_TTL)
    ]


def test_window_key_format_matches_the_documented_tenant_host_scheme():
    key = correlation._window_key("acme-corp", "DESKTOP-042")

    assert key.endswith("acme-corp:DESKTOP-042")


# ── SS-028: pattern detectors ─────────────────────────────────
#
# Each fixture below is a list of synthetic-log-shaped event dicts (the
# same shape add_event()/get_events() round-trip), oldest first — matching
# what get_events() actually returns. Detectors are called directly with
# these lists rather than through Redis, since the detection *logic* is
# what's under test here (SS-027 already covers the storage primitives).

def test_credential_brute_force_triggers_on_enough_failed_logins():
    events = [
        _event(f"a{i}", "authentication", "failed_login") for i in range(correlation.BRUTE_FORCE_MIN_ATTEMPTS)
    ]

    chain = correlation.detect_credential_brute_force(events, "acme-corp", "DESKTOP-042")

    assert chain is not None
    assert chain.pattern == CorrelationPattern.CREDENTIAL_BRUTE_FORCE
    assert chain.confidence >= settings.CORRELATION_CONFIDENCE_THRESHOLD
    assert len(chain.alert_ids) == correlation.BRUTE_FORCE_MIN_ATTEMPTS
    assert chain.mitre_technique_ids == ("T1110",)


def test_credential_brute_force_does_not_trigger_below_the_threshold():
    events = [
        _event(f"a{i}", "authentication", "failed_login")
        for i in range(correlation.BRUTE_FORCE_MIN_ATTEMPTS - 1)
    ]

    assert correlation.detect_credential_brute_force(events, "acme-corp", "DESKTOP-042") is None


def test_credential_brute_force_confidence_saturates_with_more_attempts():
    minimal = [_event(f"a{i}", "authentication", "failed_login") for i in range(correlation.BRUTE_FORCE_MIN_ATTEMPTS)]
    heavy = [
        _event(f"a{i}", "authentication", "failed_login")
        for i in range(correlation.BRUTE_FORCE_SATURATE_ATTEMPTS)
    ]

    minimal_chain = correlation.detect_credential_brute_force(minimal, "acme-corp", "DESKTOP-042")
    heavy_chain = correlation.detect_credential_brute_force(heavy, "acme-corp", "DESKTOP-042")

    assert minimal_chain.confidence == pytest.approx(settings.CORRELATION_CONFIDENCE_THRESHOLD)
    assert heavy_chain.confidence == pytest.approx(1.0)


def test_successful_compromise_triggers_on_brute_force_then_success():
    events = [
        _event(f"a{i}", "authentication", "failed_login") for i in range(correlation.BRUTE_FORCE_MIN_ATTEMPTS)
    ] + [_event("a-success", "authentication", "login_success")]

    chain = correlation.detect_successful_compromise(events, "acme-corp", "DESKTOP-042")

    assert chain is not None
    assert chain.pattern == CorrelationPattern.SUCCESSFUL_COMPROMISE
    assert "a-success" in chain.alert_ids
    # The detector requires failed logons BEFORE the success, so the
    # brute force (T1110) is detected evidence alongside T1078.
    assert chain.mitre_technique_ids == ("T1110", "T1078")


def test_successful_compromise_does_not_trigger_on_a_lone_successful_login():
    events = [_event("a1", "authentication", "login_success")]

    assert correlation.detect_successful_compromise(events, "acme-corp", "DESKTOP-042") is None


def test_successful_compromise_does_not_trigger_without_a_login_success():
    events = [
        _event(f"a{i}", "authentication", "failed_login")
        for i in range(correlation.BRUTE_FORCE_SATURATE_ATTEMPTS)
    ]

    assert correlation.detect_successful_compromise(events, "acme-corp", "DESKTOP-042") is None


def test_recon_to_exploitation_triggers_on_scanning_then_process_activity():
    events = [
        _event(f"a{i}", "network", "web_attack") for i in range(correlation.RECON_MIN_EVENTS)
    ] + [_event("a-exploit", "process", "process_start")]

    chain = correlation.detect_recon_to_exploitation(events, "acme-corp", "DESKTOP-042")

    assert chain is not None
    assert chain.pattern == CorrelationPattern.RECON_TO_EXPLOITATION
    assert set(chain.mitre_technique_ids) == {"T1595", "T1190"}


def test_recon_to_exploitation_does_not_trigger_on_network_activity_alone():
    events = [
        _event(f"a{i}", "network", "outbound_connection")
        for i in range(correlation.RECON_MIN_EVENTS + 5)
    ]

    assert correlation.detect_recon_to_exploitation(events, "acme-corp", "DESKTOP-042") is None


def test_privilege_escalation_triggers_after_login_with_high_severity():
    events = [
        _event("a1", "authentication", "login_success"),
        _event("a2", "privilege", "permission_change", severity="high"),
    ]

    chain = correlation.detect_privilege_escalation(events, "acme-corp", "DESKTOP-042")

    assert chain is not None
    assert chain.pattern == CorrelationPattern.PRIVILEGE_ESCALATION
    assert chain.confidence >= settings.CORRELATION_CONFIDENCE_THRESHOLD
    # T1548 (Abuse Elevation Control Mechanism), not T1068 — nothing in
    # a login-then-privilege-change signal indicates an exploit.
    assert chain.mitre_technique_ids == ("T1548",)


def test_privilege_escalation_does_not_trigger_on_low_severity_change():
    events = [
        _event("a1", "authentication", "login_success"),
        _event("a2", "privilege", "permission_change", severity="low"),
    ]

    assert correlation.detect_privilege_escalation(events, "acme-corp", "DESKTOP-042") is None


def test_privilege_escalation_does_not_trigger_without_a_prior_login():
    events = [_event("a1", "privilege", "permission_change", severity="critical")]

    assert correlation.detect_privilege_escalation(events, "acme-corp", "DESKTOP-042") is None


def test_data_exfiltration_triggers_on_high_volume_outbound_connections():
    events = [
        _event(f"a{i}", "network", "outbound_connection")
        for i in range(correlation.EXFILTRATION_MIN_CONNECTIONS)
    ]

    chain = correlation.detect_data_exfiltration(events, "acme-corp", "DESKTOP-042")

    assert chain is not None
    assert chain.pattern == CorrelationPattern.DATA_EXFILTRATION
    assert chain.mitre_technique_ids == ("T1041",)


def test_data_exfiltration_does_not_trigger_on_normal_outbound_volume():
    events = [
        _event(f"a{i}", "network", "outbound_connection")
        for i in range(correlation.EXFILTRATION_MIN_CONNECTIONS - 1)
    ]

    assert correlation.detect_data_exfiltration(events, "acme-corp", "DESKTOP-042") is None


def test_lateral_movement_triggers_on_login_then_internal_pivot():
    events = [
        _event("a1", "authentication", "login_success"),
        _event("a2", "network", "outbound_connection", destination_ip="10.0.0.55"),
    ]

    chain = correlation.detect_lateral_movement(events, "acme-corp", "DESKTOP-042")

    assert chain is not None
    assert chain.pattern == CorrelationPattern.LATERAL_MOVEMENT
    assert chain.mitre_technique_ids == ("T1021",)


def test_lateral_movement_does_not_trigger_on_external_destination():
    events = [
        _event("a1", "authentication", "login_success"),
        _event("a2", "network", "outbound_connection", destination_ip="45.33.32.156"),
    ]

    assert correlation.detect_lateral_movement(events, "acme-corp", "DESKTOP-042") is None


def test_lateral_movement_does_not_trigger_without_a_prior_login():
    events = [_event("a1", "network", "outbound_connection", destination_ip="10.0.0.55")]

    assert correlation.detect_lateral_movement(events, "acme-corp", "DESKTOP-042") is None


# ── SS-028: confidence vs. CORRELATION_CONFIDENCE_THRESHOLD ───────

def test_all_detectors_only_return_chains_at_or_above_the_confidence_threshold():
    triggering_fixtures = [
        (correlation.detect_credential_brute_force,
         [_event(f"a{i}", "authentication", "failed_login") for i in range(correlation.BRUTE_FORCE_MIN_ATTEMPTS)]),
        (correlation.detect_data_exfiltration,
         [_event(f"a{i}", "network", "outbound_connection") for i in range(correlation.EXFILTRATION_MIN_CONNECTIONS)]),
    ]

    for detector, events in triggering_fixtures:
        chain = detector(events, "acme-corp", "DESKTOP-042")
        assert chain.confidence >= settings.CORRELATION_CONFIDENCE_THRESHOLD


# ── SS-028: evaluate_host orchestration ───────────────────────────

@pytest.mark.asyncio
async def test_evaluate_host_runs_every_detector_against_the_current_window(fake_redis):
    now = 1_700_000_000.0
    for i in range(correlation.BRUTE_FORCE_MIN_ATTEMPTS):
        await correlation.add_event(
            "acme-corp", "DESKTOP-042", _event(f"a{i}", "authentication", "failed_login"), timestamp=now
        )

    chains = await correlation.evaluate_host("acme-corp", "DESKTOP-042", now=now)

    assert len(chains) == 1
    assert chains[0].pattern == CorrelationPattern.CREDENTIAL_BRUTE_FORCE


@pytest.mark.asyncio
async def test_evaluate_host_returns_no_chains_for_a_quiet_host(fake_redis):
    now = 1_700_000_000.0
    await correlation.add_event("acme-corp", "DESKTOP-042", _event("a1", "authentication", "login_success"), timestamp=now)

    chains = await correlation.evaluate_host("acme-corp", "DESKTOP-042", now=now)

    assert chains == []


# ── ADR-013: detector refinements for realistic telemetry ───────

def _process(alert_id, process_name, command_line):
    return {**_event(alert_id, "process", "process_start"), "process_name": process_name, "command_line": command_line}


def _file_create(alert_id, file_path):
    return {**_event(alert_id, "file", "file_create"), "file_path": file_path}


def _cloud(alert_id, action, user="svc-web-deploy"):
    return _event(alert_id, "cloud", action, user=user)


def test_recon_ignores_ordinary_web_requests():
    events = [_event(f"a{i}", "network", "web_request") for i in range(5)] + [_event("p", "process", "process_start")]

    assert correlation.detect_recon_to_exploitation(events, "acme-corp", "WEB01") is None


@pytest.mark.parametrize("action", ["outbound_connection", "inbound_connection"])
def test_recon_ignores_plain_connections(action):
    events = [_event(f"a{i}", "network", action) for i in range(5)] + [_event("p", "process", "process_start")]

    assert correlation.detect_recon_to_exploitation(events, "acme-corp", "WEB01") is None


def test_recon_detects_web_attacks_then_a_process():
    events = [_event(f"a{i}", "network", "web_attack") for i in range(3)] + [_event("p", "process", "process_start")]

    chain = correlation.detect_recon_to_exploitation(events, "acme-corp", "WEB01")

    assert chain is not None and chain.alert_ids == ("a0", "a1", "a2", "p")


def test_recon_still_detects_the_legacy_injector_port_scan():
    events = [_event(f"a{i}", "network", "port_scan") for i in range(4)] + [_event("p", "process", "process_start")]

    assert correlation.detect_recon_to_exploitation(events, "acme-corp", "DESKTOP-042") is not None


@pytest.mark.parametrize("action", ["ids_alert", "connection_blocked", "suspicious_network_connection"])
def test_recon_counts_every_recon_action(action):
    events = [_event(f"a{i}", "network", action) for i in range(3)] + [_event("p", "process", "process_start")]

    assert correlation.detect_recon_to_exploitation(events, "acme-corp", "WEB01") is not None


def test_recon_fires_on_a_later_process_when_an_early_benign_process_came_first():
    events = (
        [_event("benign", "process", "process_start")]
        + [_event(f"ids{i}", "network", "ids_alert") for i in range(3)]
        + [_event("exploit", "process", "process_start")]
    )

    chain = correlation.detect_recon_to_exploitation(events, "acme-corp", "WEB01")

    assert chain is not None
    assert chain.alert_ids == ("ids0", "ids1", "ids2", "exploit")


def test_recon_needs_the_minimum_before_the_process_not_after():
    events = (
        [_event(f"a{i}", "network", "web_attack") for i in range(2)]
        + [_event("p1", "process", "process_start")]
        + [_event("a2", "network", "web_attack")]
    )

    assert correlation.detect_recon_to_exploitation(events, "acme-corp", "WEB01") is None


def test_recon_does_not_count_process_events_of_other_log_types_as_exploitation():
    events = [_event(f"a{i}", "network", "web_attack") for i in range(3)] + [_event("f", "file", "file_create")]

    assert correlation.detect_recon_to_exploitation(events, "acme-corp", "WEB01") is None


def test_exfiltration_counts_cloud_object_reads():
    events = [_cloud(f"g{i}", "GetObject") for i in range(12)]

    chain = correlation.detect_data_exfiltration(events, "acme-corp", "svc-web-deploy")

    assert chain is not None
    assert chain.alert_ids == tuple(f"g{i}" for i in range(12))
    assert chain.mitre_technique_ids == ("T1041",)  # static per pattern; T1530 noted in ADR-013


def test_exfiltration_ignores_too_few_cloud_object_reads():
    events = [_cloud(f"g{i}", "GetObject") for i in range(9)]

    assert correlation.detect_data_exfiltration(events, "acme-corp", "svc-web-deploy") is None


def test_exfiltration_does_not_pool_cloud_reads_across_users():
    events = [_cloud(f"a{i}", "GetObject", user="svc-web-deploy") for i in range(6)] + [
        _cloud(f"b{i}", "GetObject", user="svc-reporting") for i in range(6)
    ]

    assert correlation.detect_data_exfiltration(events, "acme-corp", "123456789012") is None


def test_exfiltration_alert_ids_are_only_the_heavy_users_reads():
    events = [_cloud(f"b{i}", "GetObject", user="svc-reporting") for i in range(4)] + [
        _cloud(f"a{i}", "GetObject", user="svc-web-deploy") for i in range(12)
    ]

    chain = correlation.detect_data_exfiltration(events, "acme-corp", "123456789012")

    assert chain is not None
    assert chain.alert_ids == tuple(f"a{i}" for i in range(12))


def test_exfiltration_does_not_mix_cloud_reads_with_network_connections():
    events = [_cloud(f"g{i}", "GetObject") for i in range(6)] + [
        _event(f"o{i}", "network", "outbound_connection") for i in range(5)
    ]

    assert correlation.detect_data_exfiltration(events, "acme-corp", "HOST") is None


def test_exfiltration_network_connections_still_count_per_host_whoever_the_user():
    events = [
        _event(f"o{i}", "network", "outbound_connection", user=f"user{i % 3}") for i in range(10)
    ]

    chain = correlation.detect_data_exfiltration(events, "acme-corp", "HOST")

    assert chain is not None and len(chain.alert_ids) == 10


def test_exfiltration_ignores_other_cloud_api_calls():
    events = [_cloud(f"l{i}", "ListBuckets") for i in range(15)] + [_event("g", "network", "GetObject")]

    assert correlation.detect_data_exfiltration(events, "acme-corp", "svc-web-deploy") is None


def test_ransomware_shadow_copy_deletion_alone():
    events = [_process("v", "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet")]

    chain = correlation.detect_ransomware_precursor(events, "acme-corp", "EB-FS01")

    assert chain is not None
    assert chain.pattern == CorrelationPattern.RANSOMWARE_PRECURSOR
    assert chain.confidence == pytest.approx(0.8)
    assert chain.alert_ids == ("v",)
    assert chain.mitre_technique_ids == ("T1490", "T1486") and chain.mitre_tactic == "Impact"


def test_ransomware_mass_creation_of_an_unusual_extension_alone():
    events = [_file_create(f"f{i}", rf"C:\Shares\Finance\report-{i}.xlsx.akira") for i in range(25)]

    chain = correlation.detect_ransomware_precursor(events, "acme-corp", "EB-FS01")

    assert chain is not None
    assert chain.confidence == pytest.approx(0.75)
    assert len(chain.alert_ids) == 25


def test_ransomware_both_signals():
    events = [_process("v", "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet")] + [
        _file_create(f"f{i}", f"/srv/share/doc-{i}.akira") for i in range(25)
    ]

    chain = correlation.detect_ransomware_precursor(events, "acme-corp", "EB-FS01")

    assert chain is not None
    assert chain.confidence == pytest.approx(0.95)
    assert chain.alert_ids[0] == "v" and len(chain.alert_ids) == 26


def test_ransomware_ignores_a_burst_of_common_documents():
    events = [_file_create(f"f{i}", rf"C:\Users\neha\Documents\Budget-{i}.docx") for i in range(25)]

    assert correlation.detect_ransomware_precursor(events, "acme-corp", "EB-FIN-WS07") is None


def test_ransomware_ignores_listing_shadow_copies():
    events = [_process("v", "vssadmin.exe", "vssadmin.exe list shadows")]

    assert correlation.detect_ransomware_precursor(events, "acme-corp", "EB-FS01") is None


def test_ransomware_needs_the_minimum_creates_per_extension():
    events = [_file_create(f"f{i}", f"/srv/share/doc-{i}.akira") for i in range(19)] + [
        _file_create(f"g{i}", f"/srv/share/doc-{i}.lockbit") for i in range(19)
    ]

    assert correlation.detect_ransomware_precursor(events, "acme-corp", "EB-FS01") is None


@pytest.mark.parametrize("process_name, command_line", [
    (r"C:\Windows\System32\wbem\WMIC.exe", "wmic shadowcopy delete"),
    ("wbadmin.exe", "wbadmin DELETE CATALOG -quiet"),
    ("bcdedit.exe", "bcdedit /set {default} recoveryenabled No"),
    ("VSSADMIN.EXE", "vssadmin  Delete  Shadows /all"),
])
def test_ransomware_recognises_each_recovery_inhibiting_command(process_name, command_line):
    chain = correlation.detect_ransomware_precursor([_process("p", process_name, command_line)], "acme-corp", "H")

    assert chain is not None and chain.confidence == pytest.approx(0.8)


def test_ransomware_ignores_the_command_from_an_unrelated_process():
    events = [_process("p", "notepad.exe", "notepad.exe delete shadows.txt")]

    assert correlation.detect_ransomware_precursor(events, "acme-corp", "H") is None


def test_ransomware_detector_is_registered():
    assert correlation.detect_ransomware_precursor in correlation.DETECTORS
