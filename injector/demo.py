"""
SafeSOC — Demo Mode (SS-065)
One command (`python injector/demo.py`) provisions a demo tenant with
a realistic alert history, at least one in-progress attack chain, and
at least one resolved incident — for live demos/reviews (SRS §3.3's
"comprehensive demo mode").

No API exists to create a *tenant* (only users, via
POST /api/v1/auth/register, which itself needs an existing tenant_id)
— this is the one place this script writes to Postgres directly,
reusing backend's own models/session factory (sys.path trick, the
same convention ml/train.py already established) rather than
duplicating a second Postgres connection story. Everything else —
user registration, login, log ingestion, incident transitions — goes
through the real running backend's own API, same as a real analyst
would. Needs backend's own dependencies and Postgres reachable at
its configured settings.postgres_url (e.g. run inside the backend
container, or with the same env vars docker-compose gives it).
"""

import argparse
import asyncio
import importlib.util
import random
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import requests


def _load_sibling_module(name: str, filename: str):
    """
    Load injector.py by its file path rather than `import injector.injector`
    — this script's own directory is *also* named `injector`, which Python's
    import system resolves ambiguously depending on how demo.py is invoked
    (`python injector/demo.py` vs. imported as `injector.demo`). Loading by
    path sidesteps that entirely, working the same way either way.
    """
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parent / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_injector = _load_sibling_module("safesoc_injector_core", "injector.py")
SCENARIOS = _injector.SCENARIOS
generate_log = _injector.generate_log
send_logs = _injector.send_logs

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from sqlalchemy import select  # noqa: E402

from app.db.postgresql import async_session_factory  # noqa: E402
from app.models.tenant import Tenant  # noqa: E402

# Fixed, well-known ID so re-running this script is idempotent — reuses
# the same demo tenant/user rather than creating duplicates each time.
DEMO_TENANT_ID = uuid.UUID("00000000-dead-beef-0000-000000000001")
DEMO_TENANT_NAME = "SafeSOC Demo Co"
DEMO_EMAIL = "demo@safesoc.example"
DEMO_PASSWORD = "SafeSOC-Demo-2026!"

HISTORY_DAYS = 14
HISTORY_EVENT_COUNT = 150
# Weighted toward authentication, like real telemetry. No "privilege":
# generate_log has no privilege actions (it would fall back to auth ones).
HISTORY_LOG_TYPES = ["authentication", "authentication", "network", "process", "file"]

IN_PROGRESS_HOST = "WIN10-FIN-07"
RESOLVED_HOST = "UBUNTU-WEB-01"


async def _ensure_demo_tenant() -> None:
    """Idempotently create the demo Tenant row — the one thing here with no API to go through instead."""
    async with async_session_factory() as db:
        result = await db.execute(select(Tenant).where(Tenant.id == DEMO_TENANT_ID))
        if result.scalar_one_or_none() is not None:
            return
        db.add(Tenant(id=DEMO_TENANT_ID, name=DEMO_TENANT_NAME))
        await db.commit()


def _register_demo_user(api_base: str) -> None:
    """A 409 (duplicate email) means the demo user already exists from a previous run — expected, not an error."""
    response = requests.post(
        f"{api_base}/api/v1/auth/register",
        json={"tenant_id": str(DEMO_TENANT_ID), "email": DEMO_EMAIL, "password": DEMO_PASSWORD, "role": "analyst"},
        timeout=10,
    )
    if response.status_code not in (201, 409):
        response.raise_for_status()


def _login(api_base: str) -> str:
    response = requests.post(
        f"{api_base}/api/v1/auth/login",
        json={"tenant_id": str(DEMO_TENANT_ID), "email": DEMO_EMAIL, "password": DEMO_PASSWORD},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def _send_history(ingest_url: str, token: str) -> int:
    """
    Realistic-looking alert history spread across the trailing HISTORY_DAYS,
    mostly low/medium severity, with a mix of log types.

    No per-host caps are needed to stop these random events from forming
    spurious attack chains: correlation windows are ordered by event time
    (commit 6cd8e9e), and these events are backdated across HISTORY_DAYS,
    so they fall outside the 60-minute correlation window of each other
    and of the live chains sent afterwards.
    """
    logs = []
    now = datetime.now(timezone.utc)
    for _ in range(HISTORY_EVENT_COUNT):
        log = generate_log(
            log_type=random.choice(HISTORY_LOG_TYPES),
            severity=random.choice(["low", "low", "low", "medium", "high"]),
        )
        log["timestamp"] = (now - timedelta(minutes=random.randint(0, HISTORY_DAYS * 24 * 60))).isoformat()
        logs.append(log)

    result = send_logs(ingest_url, logs, token=token)
    return result["accepted"]


def _list_incidents(api_base: str, token: str) -> list[dict]:
    response = requests.get(
        f"{api_base}/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
        params={"size": 500},  # the router's own max; see _wait_for_incident_with_alert's docstring
        timeout=10,
    )
    response.raise_for_status()
    return response.json()["incidents"]


def _wait_for_incident_with_alert(
    api_base: str, token: str, alert_ids: list[str], *, timeout_seconds: float = 60.0
) -> Optional[str]:
    """
    Correlation runs asynchronously (a Celery task per ingested alert) —
    poll until some incident's alert_ids overlaps with the ones just sent.

    BUG-002: this used to capture the incident-id set *before* sending,
    then poll for any id not in that set. That broke specifically for
    IN_PROGRESS_HOST, whose incident is deliberately left open (SS-065)
    so it's still "active" the next time demo.py runs against this same
    idempotent tenant. create_or_merge_incident (SS-031) correctly
    *merges* a re-detected chain into that still-open incident rather
    than minting a new one — exactly right behavior — but "any id not
    already known" treats a correct merge as "nothing happened" and
    waits out the full timeout for an ID that was never going to appear,
    producing the reported "no incident detected within the timeout"
    warning. Checking for alert_id overlap instead is correct either
    way: a fresh incident or a merge into an existing one both contain
    the alert_ids this call just sent.
    """
    wanted = set(alert_ids)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        for incident in _list_incidents(api_base, token):
            if wanted & set(incident["alert_ids"]):
                return incident["id"]
        time.sleep(1)
    return None


def _transition(api_base: str, token: str, incident_id: str, to_status: str) -> None:
    response = requests.post(
        f"{api_base}/api/v1/incidents/{incident_id}/transitions",
        json={"to_status": to_status},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    response.raise_for_status()


def main():
    parser = argparse.ArgumentParser(description="SafeSOC demo mode — one command loads a demo tenant (SS-065)")
    parser.add_argument("--api-base", default="http://localhost:8000", help="Backend base URL")
    args = parser.parse_args()

    ingest_url = f"{args.api_base}/api/v1/ingest"

    print("Provisioning demo tenant...")
    asyncio.run(_ensure_demo_tenant())

    print("Registering demo user (idempotent)...")
    _register_demo_user(args.api_base)

    print("Logging in...")
    token = _login(args.api_base)

    print(f"Sending {HISTORY_EVENT_COUNT} historical events across the last {HISTORY_DAYS} days...")
    accepted = _send_history(ingest_url, token)
    print(f"  {accepted} accepted")

    print(f"Sending an in-progress attack chain (host: {IN_PROGRESS_HOST})...")
    sent = send_logs(ingest_url, SCENARIOS["brute_force"](IN_PROGRESS_HOST), token=token)
    in_progress_id = _wait_for_incident_with_alert(args.api_base, token, sent["alert_ids"])
    if in_progress_id:
        print(f"  Incident {in_progress_id} created — left open (in progress)")
    else:
        print(
            "  WARNING: no incident detected within 60s — is the correlation worker running? "
            "(check `docker compose logs worker`)"
        )

    print(f"Sending a resolved attack chain (host: {RESOLVED_HOST})...")
    sent = send_logs(ingest_url, SCENARIOS["successful_compromise"](RESOLVED_HOST), token=token)
    resolved_id = _wait_for_incident_with_alert(args.api_base, token, sent["alert_ids"])
    if resolved_id:
        _transition(args.api_base, token, resolved_id, "investigating")
        _transition(args.api_base, token, resolved_id, "resolved")
        print(f"  Incident {resolved_id} created and resolved")
    else:
        print(
            "  WARNING: no incident detected within 60s — is the correlation worker running? "
            "(check `docker compose logs worker`)"
        )

    print("\nDemo tenant ready.")
    print(f"  Tenant ID: {DEMO_TENANT_ID}")
    print(f"  Login:     {DEMO_EMAIL} / {DEMO_PASSWORD}")


if __name__ == "__main__":
    main()
