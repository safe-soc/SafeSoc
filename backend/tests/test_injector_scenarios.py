"""
SafeSOC — Injector Attack Scenario Tests (SS-064)
The real proof a scenario is "correct" isn't that its events look
plausible — it's that feeding them through the actual correlation
detector (services/correlation.py, SS-028) produces a DetectedChain.
Every scenario test below does exactly that, not just shape-checking.
"""

import sys
import uuid
from pathlib import Path
from unittest.mock import Mock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from injector.injector import DEMO_EMAIL, DEMO_PASSWORD, DEMO_TENANT_ID, SCENARIOS, generate_log, main  # noqa: E402

from app.services import correlation  # noqa: E402


def _to_window_events(events: list[dict]) -> list[dict]:
    """
    Mimics what app.workers.correlation_worker.add_event actually
    stores per real alert: {alert_id, log_type, action, severity,
    destination_ip} — assigning a synthetic alert_id the way the real
    ingestion pipeline would (NormalizedLog generates one server-side;
    the injector's own generate_log() doesn't set one).
    """
    return [
        {
            "alert_id": str(uuid.uuid4()),
            "log_type": event["log_type"],
            "action": event["action"],
            "severity": event["severity"],
            "destination_ip": event.get("destination_ip"),
        }
        for event in events
    ]


def test_all_six_correlation_patterns_have_a_scenario():
    from app.core.enums import CorrelationPattern

    # Every detector in DETECTORS maps to exactly one CorrelationPattern
    # (see correlation.py) — the AC requires a scenario per pattern, so
    # this asserts a scenario name exists for each of the 6, not just
    # that *some* scenarios exist.
    assert len(SCENARIOS) == len(CorrelationPattern) == 6


def test_brute_force_scenario_triggers_the_real_detector():
    events = _to_window_events(SCENARIOS["brute_force"]("DESKTOP-042"))

    chain = correlation.detect_credential_brute_force(events, "acme-corp", "DESKTOP-042")

    assert chain is not None
    assert chain.pattern.value == "credential_brute_force"


def test_successful_compromise_scenario_triggers_the_real_detector():
    events = _to_window_events(SCENARIOS["successful_compromise"]("DESKTOP-042"))

    chain = correlation.detect_successful_compromise(events, "acme-corp", "DESKTOP-042")

    assert chain is not None
    assert chain.pattern.value == "successful_compromise"


def test_recon_to_exploitation_scenario_triggers_the_real_detector():
    events = _to_window_events(SCENARIOS["recon_to_exploitation"]("DESKTOP-042"))

    chain = correlation.detect_recon_to_exploitation(events, "acme-corp", "DESKTOP-042")

    assert chain is not None
    assert chain.pattern.value == "recon_to_exploitation"


def test_privilege_escalation_scenario_triggers_the_real_detector():
    events = _to_window_events(SCENARIOS["privilege_escalation"]("DESKTOP-042"))

    chain = correlation.detect_privilege_escalation(events, "acme-corp", "DESKTOP-042")

    assert chain is not None
    assert chain.pattern.value == "privilege_escalation"


def test_data_exfiltration_scenario_triggers_the_real_detector():
    events = _to_window_events(SCENARIOS["data_exfiltration"]("DESKTOP-042"))

    chain = correlation.detect_data_exfiltration(events, "acme-corp", "DESKTOP-042")

    assert chain is not None
    assert chain.pattern.value == "data_exfiltration"


def test_lateral_movement_scenario_triggers_the_real_detector():
    events = _to_window_events(SCENARIOS["lateral_movement"]("DESKTOP-042"))

    chain = correlation.detect_lateral_movement(events, "acme-corp", "DESKTOP-042")

    assert chain is not None
    assert chain.pattern.value == "lateral_movement"


def test_evaluate_host_style_full_sweep_detects_each_scenario():
    """
    Running *every* detector (not just the matching one) against each
    scenario's events — confirming the matching detector fires when run
    alongside all six (as evaluate_host() genuinely does in production)
    is a stronger proof than calling the one detector in isolation.
    """
    # SCENARIOS' short CLI names vs. CorrelationPattern's own values
    # (e.g. "brute_force" -> "credential_brute_force").
    expected_pattern = {
        "brute_force": "credential_brute_force",
        "successful_compromise": "successful_compromise",
        "recon_to_exploitation": "recon_to_exploitation",
        "privilege_escalation": "privilege_escalation",
        "data_exfiltration": "data_exfiltration",
        "lateral_movement": "lateral_movement",
    }
    assert expected_pattern.keys() == SCENARIOS.keys()

    for name, scenario_fn in SCENARIOS.items():
        events = _to_window_events(scenario_fn("DESKTOP-042"))
        chains = [d(events, "acme-corp", "DESKTOP-042") for d in correlation.DETECTORS]
        matched_patterns = {c.pattern.value for c in chains if c is not None}
        assert expected_pattern[name] in matched_patterns, f"scenario '{name}' did not trigger its own detector"


def test_scenario_events_use_the_requested_host():
    for scenario_fn in SCENARIOS.values():
        events = scenario_fn("DESKTOP-999")
        assert all(e["host_id"] == "DESKTOP-999" for e in events)


def test_scenario_defaults_to_a_random_host_when_none_given():
    from injector.injector import HOSTS

    events = SCENARIOS["brute_force"](None)
    assert events[0]["host_id"] in HOSTS


# ── CLI (argparse) ────────────────────────────────────────────────

@pytest.fixture
def _mock_login(monkeypatch):
    """
    BUG-001: main() now logs in before sending. Tests that only care
    about what gets sent to send_logs() don't want a real HTTP call
    here, so this fixture stands in for a successful login.
    """
    mock = Mock(return_value="fake-jwt")
    monkeypatch.setattr("injector.injector.login", mock)
    return mock


def test_cli_default_behavior_sends_random_logs_not_a_scenario(monkeypatch, capsys, _mock_login):
    captured_logs = {}

    def fake_send_logs(target_url, logs, token=None):
        captured_logs["logs"] = logs
        captured_logs["token"] = token
        return {"accepted": len(logs), "rejected": 0, "alert_ids": ["a1"] * len(logs)}

    monkeypatch.setattr("injector.injector.send_logs", fake_send_logs)
    monkeypatch.setattr(sys, "argv", ["injector.py", "http://example.test/ingest", "3"])

    main()

    assert len(captured_logs["logs"]) == 3
    # Random logs default to the authentication log_type/action pool, not
    # a scenario's fixed shape (generate_log()'s own default).
    assert all(log["log_type"] == "authentication" for log in captured_logs["logs"])
    assert captured_logs["token"] == "fake-jwt"


def test_cli_scenario_flag_sends_the_named_scenario(monkeypatch, _mock_login):
    captured_logs = {}

    def fake_send_logs(target_url, logs, token=None):
        captured_logs["logs"] = logs
        return {"accepted": len(logs), "rejected": 0, "alert_ids": ["a1"] * len(logs)}

    monkeypatch.setattr("injector.injector.send_logs", fake_send_logs)
    monkeypatch.setattr(
        sys, "argv", ["injector.py", "http://example.test/ingest", "--scenario", "brute_force", "--host", "DESKTOP-001"]
    )

    main()

    logs = captured_logs["logs"]
    assert len(logs) == 6
    assert all(log["host_id"] == "DESKTOP-001" for log in logs)
    assert all(log["action"] == "failed_login" for log in logs)


def test_cli_rejects_an_unknown_scenario_name(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["injector.py", "--scenario", "not-a-real-scenario"])

    with pytest.raises(SystemExit):
        main()


# ── CLI authentication (BUG-001) ─────────────────────────────────

def test_cli_logs_in_and_passes_the_token_to_send_logs(monkeypatch):
    login_calls = {}

    def fake_login(api_base, tenant_id, email, password):
        login_calls["args"] = (api_base, tenant_id, email, password)
        return "real-jwt"

    captured = {}

    def fake_send_logs(target_url, logs, token=None):
        captured["token"] = token
        return {"accepted": len(logs), "rejected": 0, "alert_ids": []}

    monkeypatch.setattr("injector.injector.login", fake_login)
    monkeypatch.setattr("injector.injector.send_logs", fake_send_logs)
    monkeypatch.setattr(sys, "argv", ["injector.py", "http://example.test/ingest", "1"])

    main()

    assert login_calls["args"] == ("http://localhost:8000", DEMO_TENANT_ID, DEMO_EMAIL, DEMO_PASSWORD)
    assert captured["token"] == "real-jwt"


def test_cli_no_auth_flag_skips_login_entirely(monkeypatch):
    login_mock = Mock()
    captured = {}

    def fake_send_logs(target_url, logs, token=None):
        captured["token"] = token
        return {"accepted": len(logs), "rejected": 0, "alert_ids": []}

    monkeypatch.setattr("injector.injector.login", login_mock)
    monkeypatch.setattr("injector.injector.send_logs", fake_send_logs)
    monkeypatch.setattr(sys, "argv", ["injector.py", "http://example.test/ingest", "1", "--no-auth"])

    main()

    login_mock.assert_not_called()
    assert captured["token"] is None


def test_cli_prints_a_clear_error_and_exits_cleanly_when_login_fails(monkeypatch, capsys):
    import requests

    def failing_login(api_base, tenant_id, email, password):
        response = Mock(status_code=401)
        raise requests.exceptions.HTTPError(response=response)

    send_logs_mock = Mock()

    monkeypatch.setattr("injector.injector.login", failing_login)
    monkeypatch.setattr("injector.injector.send_logs", send_logs_mock)
    monkeypatch.setattr(sys, "argv", ["injector.py"])

    main()  # must not raise

    send_logs_mock.assert_not_called()
    assert "Login failed" in capsys.readouterr().out


# ── send_logs (SS-065 regression) ────────────────────────────────

def test_send_logs_omits_tenant_id_when_authenticated(monkeypatch):
    """
    Regression test: send_logs() unconditionally including the
    module-level TENANT_ID ("acme-corp") in the payload broke every
    authenticated caller (e.g. demo.py) against a real tenant, since
    tenant_id is derived from the token server-side (SS-016) and any
    payload tenant_id must match exactly or the whole batch 403s.
    Caught live: demo.py's first real run failed with exactly that.
    """
    from injector.injector import send_logs

    captured = {}

    class _FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"accepted": 0, "rejected": 0, "alert_ids": []}

    def fake_post(url, json, headers=None, timeout=None):
        captured["json"] = json
        captured["headers"] = headers
        return _FakeResponse()

    monkeypatch.setattr("injector.injector.requests.post", fake_post)

    send_logs("http://example.test/ingest", [{"log_type": "authentication"}], token="real-jwt")

    assert "tenant_id" not in captured["json"]
    assert captured["headers"] == {"Authorization": "Bearer real-jwt"}


def test_send_logs_includes_tenant_id_when_unauthenticated(monkeypatch):
    """Existing unauthenticated behavior (no token) is unchanged."""
    from injector.injector import TENANT_ID, send_logs

    captured = {}

    class _FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"accepted": 0, "rejected": 0, "alert_ids": []}

    def fake_post(url, json, headers=None, timeout=None):
        captured["json"] = json
        captured["headers"] = headers
        return _FakeResponse()

    monkeypatch.setattr("injector.injector.requests.post", fake_post)

    send_logs("http://example.test/ingest", [{"log_type": "authentication"}])

    assert captured["json"]["tenant_id"] == TENANT_ID
    assert captured["headers"] is None
