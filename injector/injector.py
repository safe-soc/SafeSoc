"""
SafeSOC — Synthetic Log Injector
Generates realistic security logs and sends them to the ingestion endpoint.

Default behavior (no --scenario) is unchanged: uniformly randomized
authentication-type logs. --scenario NAME instead sends a fixed,
ordered event sequence engineered to trigger one specific attack-chain
pattern in services/correlation.py (SS-028) — useful for demoing or
testing the correlation engine against something other than random
noise (SS-064).

POST /api/v1/ingest has required a valid JWT since SS-016 (BUG-001):
running this script's CLI now logs in first, exactly like demo.py's
own _login(), and sends the resulting token as a Bearer header. With
no credentials given, it defaults to the same demo tenant/user
demo.py (SS-065) provisions, so a bare `python injector.py --scenario
brute_force` keeps working stand-alone as long as `python
injector/demo.py` has been run at least once. --no-auth restores the
exact pre-SS-016 unauthenticated payload shape, for whoever still
needs it against a backend with auth disabled.
"""

import argparse
import json
import random
import sys
from datetime import datetime, timezone
from typing import Callable, Optional

import requests

# Configuration
DEFAULT_API_BASE = "http://localhost:8000"
DEFAULT_TARGET = f"{DEFAULT_API_BASE}/api/v1/ingest"
TENANT_ID = "acme-corp"  # only used in --no-auth mode; see send_logs()

# The demo tenant/user demo.py (SS-065) provisions — reused here as
# injector.py's own zero-config login default (BUG-001), so the two
# scripts point at the same tenant unless the caller overrides them.
DEMO_TENANT_ID = "00000000-dead-beef-0000-000000000001"
DEMO_EMAIL = "demo@safesoc.example"
DEMO_PASSWORD = "SafeSOC-Demo-2026!"

# Demo data pools
HOSTS = [f"DESKTOP-{i:03d}" for i in range(1, 51)]
USERS = ["john.doe", "jane.smith", "bob.admin", "alice.it", "charlie.eng"]
ACTIONS = {
    "authentication": ["failed_login", "login_success", "logout", "password_change"],
    "network": ["outbound_connection", "inbound_connection", "dns_query"],
    "process": ["process_start", "process_stop", "service_install"],
    "file": ["file_create", "file_modify", "file_delete", "permission_change"],
}


def generate_log(
    log_type: str = "authentication",
    severity: str = "low",
    host_id: Optional[str] = None,
) -> dict:
    """Generate a single synthetic log in NormalizedLog format."""
    host = host_id or random.choice(HOSTS)
    action = random.choice(ACTIONS.get(log_type, ACTIONS["authentication"]))

    return {
        "tenant_id": TENANT_ID,
        "source": "synthetic",
        "log_type": log_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host_id": host,
        "host_ip": f"192.168.1.{random.randint(2, 254)}",
        "host_os": random.choice(["windows", "linux"]),
        "user": random.choice(USERS),
        "action": action,
        "description": f"Synthetic {action} event on {host}",
        "severity": severity,
        "raw_log": json.dumps({"synthetic": True, "action": action}),
    }


def send_logs(target_url: str, logs: list[dict], token: Optional[str] = None) -> dict:
    """
    POST a batch of logs to the ingestion endpoint. `token` is optional
    and omitted by default (unchanged existing behavior). The endpoint
    has required a valid JWT since SS-016 either way — callers running
    against a real deployment (e.g. demo.py, SS-065) need to pass one.

    tenant_id is only included when unauthenticated: once a token is
    present, tenant_id is derived from it server-side, and any payload
    tenant_id must match exactly (SS-016) or the whole batch is
    rejected (403) — the module-level TENANT_ID constant won't match a
    real caller's actual tenant, so it's omitted rather than sent wrong.
    """
    payload = {
        "source": "synthetic",
        "logs": logs,
    }
    if token:
        headers = {"Authorization": f"Bearer {token}"}
    else:
        payload["tenant_id"] = TENANT_ID
        headers = None
    response = requests.post(target_url, json=payload, headers=headers, timeout=10)
    response.raise_for_status()
    return response.json()


def login(api_base: str, tenant_id: str, email: str, password: str) -> str:
    """Authenticate and return a JWT access token — the same flow as demo.py's own _login() (BUG-001)."""
    response = requests.post(
        f"{api_base}/api/v1/auth/login",
        json={"tenant_id": tenant_id, "email": email, "password": password},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()["access_token"]


# ── Attack scenarios (SS-064) ────────────────────────────────────
#
# Each scenario produces an ordered event sequence for one target host,
# engineered to satisfy one of services/correlation.py's six detectors
# (SS-028) when ingested and evaluated in quick succession — thresholds
# match that module's own MIN_* constants exactly, with a small margin.


def _scenario_event(host_id: str, log_type: str, action: str, severity: str = "low", **overrides) -> dict:
    """A single scenario event, reusing generate_log()'s shape with an explicit (not random) action."""
    event = generate_log(log_type=log_type, severity=severity, host_id=host_id)
    event["action"] = action
    event["description"] = f"Scenario event: {action} on {host_id}"
    event.update(overrides)
    return event


def scenario_brute_force(host_id: Optional[str] = None) -> list[dict]:
    """Credential brute force: 6 failed logins (detector threshold: 5+)."""
    host = host_id or random.choice(HOSTS)
    return [_scenario_event(host, "authentication", "failed_login", severity="medium") for _ in range(6)]


def scenario_successful_compromise(host_id: Optional[str] = None) -> list[dict]:
    """Brute force that then succeeds: 6 failed logins, then a login_success."""
    host = host_id or random.choice(HOSTS)
    events = [_scenario_event(host, "authentication", "failed_login", severity="medium") for _ in range(6)]
    events.append(_scenario_event(host, "authentication", "login_success", severity="low"))
    return events


def scenario_recon_to_exploitation(host_id: Optional[str] = None) -> list[dict]:
    """Recon then exploitation: 4 network (scanning) events, then a process launch (detector threshold: 3+ network)."""
    host = host_id or random.choice(HOSTS)
    events = [_scenario_event(host, "network", "port_scan", severity="low") for _ in range(4)]
    events.append(_scenario_event(host, "process", "process_start", severity="high"))
    return events


def scenario_privilege_escalation(host_id: Optional[str] = None) -> list[dict]:
    """An authenticated session followed by a high/critical-severity privilege-context change."""
    host = host_id or random.choice(HOSTS)
    return [
        _scenario_event(host, "authentication", "login_success", severity="low"),
        _scenario_event(host, "privilege", "privilege_change", severity="critical"),
    ]


def scenario_data_exfiltration(host_id: Optional[str] = None) -> list[dict]:
    """A high volume of outbound connections to external IPs (detector threshold: 10+)."""
    host = host_id or random.choice(HOSTS)
    return [
        _scenario_event(
            host, "network", "outbound_connection", severity="medium", destination_ip=f"203.0.113.{i + 1}"
        )
        for i in range(12)
    ]


def scenario_lateral_movement(host_id: Optional[str] = None) -> list[dict]:
    """After authenticating, outbound connections to another *internal* host — this host used as a pivot."""
    host = host_id or random.choice(HOSTS)
    return [
        _scenario_event(host, "authentication", "login_success", severity="low"),
        _scenario_event(host, "network", "outbound_connection", severity="medium", destination_ip="192.168.1.55"),
        _scenario_event(host, "network", "outbound_connection", severity="medium", destination_ip="192.168.1.56"),
    ]


SCENARIOS: dict[str, Callable[[Optional[str]], list[dict]]] = {
    "brute_force": scenario_brute_force,
    "successful_compromise": scenario_successful_compromise,
    "recon_to_exploitation": scenario_recon_to_exploitation,
    "privilege_escalation": scenario_privilege_escalation,
    "data_exfiltration": scenario_data_exfiltration,
    "lateral_movement": scenario_lateral_movement,
}


def _print_result(result: dict) -> None:
    print(f"\nAccepted: {result['accepted']}")
    print(f"Rejected: {result['rejected']}")
    if result.get("alert_ids"):
        for aid in result["alert_ids"]:
            print(f"  Alert ID: {aid}")
    if result.get("errors"):
        print("Errors:")
        for err in result["errors"]:
            print(f"  [{err['index']}] {err['error'][:100]}")


def main():
    parser = argparse.ArgumentParser(description="SafeSOC synthetic log injector")
    parser.add_argument("target", nargs="?", default=DEFAULT_TARGET, help="Ingestion endpoint URL")
    parser.add_argument(
        "count", nargs="?", type=int, default=1, help="Number of random logs to send (ignored with --scenario)"
    )
    parser.add_argument(
        "--scenario", choices=sorted(SCENARIOS.keys()), help="Send a named attack scenario instead of random logs"
    )
    parser.add_argument("--host", help="Target host_id for the scenario (default: a random host)")
    parser.add_argument("--api-base", default=DEFAULT_API_BASE, help="Backend base URL, used to log in (default: http://localhost:8000)")
    parser.add_argument("--tenant-id", default=DEMO_TENANT_ID, help="Tenant UUID to authenticate as (default: the demo tenant created by demo.py)")
    parser.add_argument("--email", default=DEMO_EMAIL, help="User email to authenticate as (default: the demo user)")
    parser.add_argument("--password", default=DEMO_PASSWORD, help="Password for --email (default: the demo user's password)")
    parser.add_argument(
        "--no-auth", action="store_true",
        help="Skip login and send the legacy unauthenticated payload (only works against a backend with auth disabled)",
    )
    args = parser.parse_args()

    print(f"Target: {args.target}")

    token = None
    if not args.no_auth:
        print(f"Logging in as {args.email} (tenant {args.tenant_id})...")
        try:
            token = login(args.api_base, args.tenant_id, args.email, args.password)
        except requests.exceptions.ConnectionError:
            print(f"ERROR: Could not connect to SafeSOC backend at {args.api_base}.")
            print("Is 'docker compose up' running?")
            return
        except requests.exceptions.HTTPError as e:
            print(f"ERROR: Login failed ({e.response.status_code}).")
            print("Run 'python injector/demo.py' first to provision the demo tenant, "
                  "or pass --tenant-id/--email/--password for an existing user.")
            return

    if args.scenario:
        logs = SCENARIOS[args.scenario](args.host)
        print(f"Generating scenario '{args.scenario}' ({len(logs)} events) for host {logs[0]['host_id']}...")
    else:
        print(f"Generating {args.count} log(s)...")
        logs = [generate_log() for _ in range(args.count)]

    try:
        result = send_logs(args.target, logs, token=token)
        _print_result(result)
    except requests.exceptions.ConnectionError:
        print("ERROR: Could not connect to SafeSOC backend.")
        print("Is 'docker compose up' running?")
    except requests.exceptions.HTTPError as e:
        print(f"ERROR: Ingestion failed ({e.response.status_code}): {e.response.text[:300]}")


if __name__ == "__main__":
    main()
