"""
SafeSOC — Benchmark API Client
A thin HTTP client over the same public API the frontend uses, so the
benchmark exercises the real request path (auth, tenant scoping,
routers, services) rather than reaching into the database. Nothing here
inserts incidents, runs, or actions directly — every measured artifact
has to be produced by the pipeline itself.

Tenant provisioning is the one exception, and only because there is no
API for it: creating a Tenant row is the same gap injector/demo.py
documents. It runs inside the backend container via `docker exec`, so
no database credentials are ever needed (or guessed) on the host — see
provision_tenant().
"""

from __future__ import annotations

import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import requests

DEFAULT_API_BASE = "http://localhost:8000"
DEFAULT_BACKEND_CONTAINER = "safe-soc-backend-1"
DEFAULT_WORKER_CONTAINER = "safe-soc-worker-1"


def parse_ts(value: Optional[str]) -> Optional[datetime]:
    """Parse an API timestamp into an aware UTC datetime. Returns None for null/unparseable rather than raising."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class BenchmarkApiError(RuntimeError):
    pass


@dataclass
class TenantCredentials:
    tenant_id: uuid.UUID
    email: str
    password: str
    name: str
    token: Optional[str] = None


class SafeSocClient:
    """One authenticated tenant's view of the API. A separate instance per tenant keeps isolation checks honest."""

    def __init__(self, api_base: str = DEFAULT_API_BASE, timeout: int = 30):
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout
        self._token: Optional[str] = None
        self.tenant_id: Optional[uuid.UUID] = None

    # ── auth ────────────────────────────────────────────────────────

    def login(self, credentials: TenantCredentials) -> str:
        response = requests.post(
            f"{self.api_base}/api/v1/auth/login",
            json={"tenant_id": str(credentials.tenant_id), "email": credentials.email, "password": credentials.password},
            timeout=self.timeout,
        )
        if response.status_code != 200:
            raise BenchmarkApiError(f"login failed for {credentials.email}: {response.status_code} {response.text[:200]}")
        self._token = response.json()["access_token"]
        self.tenant_id = credentials.tenant_id
        credentials.token = self._token
        return self._token

    def use_token(self, token: str, tenant_id: Optional[uuid.UUID] = None) -> None:
        """Adopt a token minted elsewhere — used by the security probes to act as a viewer or another tenant."""
        self._token = token
        self.tenant_id = tenant_id

    @property
    def headers(self) -> dict:
        if not self._token:
            raise BenchmarkApiError("client is not authenticated")
        return {"Authorization": f"Bearer {self._token}"}

    # ── raw verbs (status returned, never raised on, so probes can assert on codes) ──

    def get(self, path: str, **kwargs) -> requests.Response:
        return requests.get(f"{self.api_base}{path}", headers=self.headers, timeout=self.timeout, **kwargs)

    def post(self, path: str, json: Any = None, **kwargs) -> requests.Response:
        return requests.post(f"{self.api_base}{path}", headers=self.headers, json=json, timeout=self.timeout, **kwargs)

    def _json(self, response: requests.Response, what: str) -> Any:
        if response.status_code >= 400:
            raise BenchmarkApiError(f"{what} failed: {response.status_code} {response.text[:300]}")
        return response.json()

    # ── pipeline entry ──────────────────────────────────────────────

    def ingest(self, logs: list[dict]) -> dict:
        """Push telemetry through the real ingestion endpoint. tenant_id is derived server-side from the JWT."""
        return self._json(self.post("/api/v1/ingest", json={"source": "synthetic", "logs": logs}), "ingest")

    # ── reads ───────────────────────────────────────────────────────

    def list_incidents(self, size: int = 100) -> list[dict]:
        return self._json(self.get("/api/v1/incidents", params={"size": size}), "list incidents")["incidents"]

    def get_incident(self, incident_id: str) -> dict:
        return self._json(self.get(f"/api/v1/incidents/{incident_id}"), "get incident")

    def incident_evidence(self, incident_id: str) -> dict:
        return self._json(self.get(f"/api/v1/incidents/{incident_id}/evidence"), "incident evidence")

    def incident_timeline(self, incident_id: str) -> list[dict]:
        return self._json(self.get(f"/api/v1/incidents/{incident_id}/timeline"), "incident timeline")["entries"]

    def soar_runs_for_incident(self, incident_id: str) -> list[dict]:
        return self._json(self.get(f"/api/v1/incidents/{incident_id}/soar/runs"), "soar runs")

    def soar_run_detail(self, incident_id: str, run_id: str) -> dict:
        return self._json(self.get(f"/api/v1/incidents/{incident_id}/soar/runs/{run_id}"), "soar run detail")

    def soar_runs_with_actions(self, incident_id: str) -> list[dict]:
        return [self.soar_run_detail(incident_id, run["id"]) for run in self.soar_runs_for_incident(incident_id)]

    def all_soar_runs(self) -> list[dict]:
        """Tenant-wide runs with actions — the /soar operations page's own endpoint."""
        return self._json(self.get("/api/v1/soar/runs"), "all soar runs")

    # ── SOAR decisions ──────────────────────────────────────────────

    def approve_action(self, incident_id: str, run_id: str, action_id: str, reason: Optional[str] = None) -> requests.Response:
        return self.post(
            f"/api/v1/incidents/{incident_id}/soar/runs/{run_id}/actions/{action_id}/approve",
            json={"reason": reason} if reason else {},
        )

    def reject_action(self, incident_id: str, run_id: str, action_id: str, reason: Optional[str] = None) -> requests.Response:
        return self.post(
            f"/api/v1/incidents/{incident_id}/soar/runs/{run_id}/actions/{action_id}/reject",
            json={"reason": reason} if reason else {},
        )

    # ── investigation (AI) ──────────────────────────────────────────

    def create_investigation_session(self, incident_id: str) -> dict:
        return self._json(
            self.post(f"/api/v1/incidents/{incident_id}/investigation/sessions"), "create investigation session"
        )

    def ask(self, incident_id: str, session_id: str, question: str, timeout: Optional[int] = None) -> dict:
        response = requests.post(
            f"{self.api_base}/api/v1/incidents/{incident_id}/investigation/sessions/{session_id}/ask",
            headers=self.headers,
            json={"question": question},
            timeout=timeout or 120,
        )
        return self._json(response, "ask")["turn"]

    def create_finding(self, incident_id: str, session_id: str, text: str, category: str) -> dict:
        return self._json(
            self.post(
                f"/api/v1/incidents/{incident_id}/investigation/sessions/{session_id}/findings",
                json={"text": text, "category": category},
            ),
            "create finding",
        )

    def get_investigation_session(self, incident_id: str, session_id: str) -> dict:
        return self._json(
            self.get(f"/api/v1/incidents/{incident_id}/investigation/sessions/{session_id}"), "get investigation session"
        )


# ── Tenant provisioning ─────────────────────────────────────────────


def _docker_exec_python(container: str, snippet: str) -> str:
    result = subprocess.run(
        ["docker", "exec", container, "python", "-c", snippet],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise BenchmarkApiError(f"provisioning snippet failed in {container}: {result.stderr[-500:]}")
    return result.stdout.strip()


def provision_tenant(
    credentials: TenantCredentials,
    api_base: str = DEFAULT_API_BASE,
    container: str = DEFAULT_BACKEND_CONTAINER,
    role: str = "analyst",
) -> TenantCredentials:
    """
    Idempotently create an isolated benchmark tenant and a user in it.

    The Tenant row goes in through the backend container (the same "no
    API for this" gap injector/demo.py works around), so the host needs
    no database credentials — which matters here because this repo's
    .env is currently corrupted and must not be guessed at. The user is
    then registered over the real HTTP API like any other.
    """
    snippet = (
        "import asyncio, uuid\n"
        "from sqlalchemy import select\n"
        "from app.db.postgresql import async_session_factory, engine\n"
        "from app.models.tenant import Tenant\n"
        f"TID = uuid.UUID('{credentials.tenant_id}')\n"
        "async def main():\n"
        "    async with async_session_factory() as db:\n"
        "        r = await db.execute(select(Tenant).where(Tenant.id == TID))\n"
        "        if r.scalar_one_or_none() is None:\n"
        f"            db.add(Tenant(id=TID, name={credentials.name!r}))\n"
        "            await db.commit()\n"
        "            print('created')\n"
        "        else:\n"
        "            print('exists')\n"
        "    await engine.dispose()\n"
        "asyncio.run(main())\n"
    )
    _docker_exec_python(container, snippet)

    response = requests.post(
        f"{api_base}/api/v1/auth/register",
        json={
            "tenant_id": str(credentials.tenant_id),
            "email": credentials.email,
            "password": credentials.password,
            "role": role,
        },
        timeout=30,
    )
    if response.status_code not in (200, 201, 409):
        raise BenchmarkApiError(f"register failed: {response.status_code} {response.text[:300]}")
    return credentials


def worker_task_counts(container: str = DEFAULT_WORKER_CONTAINER, since: str = "10m") -> dict:
    """
    Celery task outcomes straight from the worker's own log — the
    reliability numbers reported are the worker's, not the benchmark's
    guess at them. Returns {} if the log can't be read, so a missing
    container degrades to "unmeasured" rather than a fabricated zero.
    """
    try:
        result = subprocess.run(
            ["docker", "logs", container, "--since", since],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except Exception:
        return {}
    if result.returncode != 0:
        return {}

    log = result.stdout + result.stderr
    counts = {"correlation_succeeded": 0, "correlation_failed": 0, "soar_succeeded": 0, "soar_failed": 0}
    for line in log.splitlines():
        if "evaluate_correlation[" in line:
            if " succeeded in " in line:
                counts["correlation_succeeded"] += 1
            elif "raised unexpected" in line:
                counts["correlation_failed"] += 1
        elif "execute_soar_action[" in line:
            if " succeeded in " in line:
                counts["soar_succeeded"] += 1
            elif "raised unexpected" in line:
                counts["soar_failed"] += 1
    return counts
