"""
SafeSOC — Synthetic SOC Simulation / Demo Data Generator
Populates the ENTIRE SafeSOC application (dashboard, alerts, endpoints,
incidents, investigate, threat analytics) with a coherent, deterministic
synthetic environment — extending demo.py's single-tenant/two-scenario
"comprehensive demo mode" (SS-065) into a full simulation, without
replacing it: demo.py's own quick 150-event demo is untouched and still
works standalone.

============================================================================
THIS DATA IS 100% SYNTHETIC. It is never to be presented, logged, or
described as telemetry actually observed on real machines, a real
organization, or a real security incident. Every host, user, IP, and
vulnerability identifier below is either a placeholder invented for this
simulation or a well-known, publicly-documented historical CVE attached
to an explicitly old/vulnerable software version for realism — never a
claim that SafeSOC "discovered" it. See VULNERABILITY_CATALOG below for
exactly which vulnerability ids are real CVEs (sourced from public,
widely-documented disclosures) vs. clearly-labeled DEMO-VULN-#### ids.
============================================================================

Determinism: every random decision in this module is drawn from a single
`random.Random(SIMULATION_SEED)` instance (never the global `random`
module) — the same seed always produces the same hosts, users, event
sequence, scenario placements, and software/vulnerability assignments.
Absolute timestamps are still anchored to "now" at run time (this seeds
a *live* demo environment, not a frozen-clock fixture), so re-running
days apart won't byte-for-byte match — but the relative structure
(who/what/how much/how severe) is identical every time.

Usage:
    python injector/simulate.py --seed              # populate (idempotent — safe to re-run)
    python injector/simulate.py --reset              # wipe this simulation's data
    python injector/simulate.py --reset --seed        # reseed from a clean slate
    python injector/simulate.py --seed --api-base http://localhost:8000

Needs the real backend (+ Celery worker, for correlation/incidents) and
Postgres reachable, same as demo.py — run from the repo root with the
Docker stack up, or inside the backend container.
"""

import argparse
import random
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Reuses demo.py's own already-resolved `send_logs` reference (demo.py
# loads injector.py via importlib-by-path specifically to sidestep the
# `injector/` directory vs. `injector.py` file name collision — see its
# _load_sibling_module docstring) rather than importing injector.py a
# second time here and re-risking that same ambiguity.
from demo import (  # noqa: E402
    DEMO_EMAIL,
    DEMO_PASSWORD,
    DEMO_TENANT_ID,
    _ensure_demo_tenant,
    _login,
    _register_demo_user,
    _transition,
    _wait_for_incident_with_alert,
    send_logs,
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

import asyncio  # noqa: E402

from sqlalchemy import delete, select  # noqa: E402

from app.core.enums import SoftwareCategory  # noqa: E402
from app.db.opensearch import get_client as get_opensearch_client  # noqa: E402
from app.db.postgresql import async_session_factory, engine  # noqa: E402
from app.db.redis import get_client as get_redis_client  # noqa: E402
from app.models.alert_annotation import AlertAnnotation  # noqa: E402
from app.models.audit_log import AuditLog  # noqa: E402
from app.models.endpoint import Endpoint  # noqa: E402
from app.models.endpoint_software import EndpointSoftware  # noqa: E402
from app.models.incident import Incident, IncidentNote, IncidentStateTransition  # noqa: E402
from app.services.software_inventory import upsert_software  # noqa: E402
from app.tasks.scoring import _recalculate_all_risk_scores_async  # noqa: E402

# ══════════════════════════════════════════════════════════════════════
# Determinism
# ══════════════════════════════════════════════════════════════════════

SIMULATION_SEED = 20260826  # fixed — do not derive from the current date/time
RNG = random.Random(SIMULATION_SEED)

WINDOW_DAYS = 21
BACKGROUND_EVENT_COUNT = 900
INGEST_BATCH_SIZE = 500  # matches settings.INGEST_BATCH_SIZE

# ══════════════════════════════════════════════════════════════════════
# Organization: departments, users, endpoints
# ══════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class Department:
    name: str
    host_prefix: str  # e.g. "WS-FIN" for finance workstations
    user_first_names: tuple


DEPARTMENTS = [
    Department("IT", "WS-IT", ("alice", "raj", "mei", "tom")),
    Department("Finance", "WS-FIN", ("grace", "victor", "priya", "sam")),
    Department("Engineering", "WS-ENG", ("dan", "yuki", "leo", "nadia", "omar")),
    Department("Sales", "WS-SALES", ("carla", "ben", "fatima", "jake")),
    Department("HR", "WS-HR", ("lena", "marcus")),
    Department("Executive", "WS-EXEC", ("william", "sophia")),
]

_LAST_NAMES = ("thompson", "garcia", "chen", "patel", "kim", "nguyen", "brown", "silva", "novak", "khan", "rossi", "muller")


def _build_users() -> list[str]:
    """~30 realistic 'firstname.lastname' usernames, deterministically generated."""
    users = []
    for dept in DEPARTMENTS:
        for first in dept.user_first_names:
            last = RNG.choice(_LAST_NAMES)
            users.append(f"{first}.{last}")
    # A few shared service/admin accounts, distinct from person-shaped names.
    users += ["svc.backup", "svc.monitoring", "admin.helpdesk"]
    return users


USERS = _build_users()  # ~30 usernames total, matching the task's 20-40 target


@dataclass
class SimHost:
    host_id: str
    department: str
    os: str
    host_ip: str
    role: str  # "workstation" | "laptop" | "server"


def _build_hosts() -> list[SimHost]:
    """~40 regular hosts spread across departments, plus 4 named showcase hosts (added separately)."""
    hosts: list[SimHost] = []
    subnet = 10
    desktop_n = 1
    laptop_n = 1

    for dept in DEPARTMENTS:
        # 5-7 regular endpoints per department -> ~34 total across 6 departments.
        count = RNG.randint(5, 7)
        for _ in range(count):
            kind = RNG.choice(["desktop", "desktop", "laptop"])  # desktops more common than laptops
            if kind == "laptop":
                host_id = f"LAPTOP-{laptop_n:03d}"
                laptop_n += 1
                role = "laptop"
            else:
                host_id = f"DESKTOP-{desktop_n:03d}"
                desktop_n += 1
                role = "workstation"
            os_choice = RNG.choices(["windows", "linux", "macos"], weights=[70, 20, 10])[0]
            hosts.append(SimHost(host_id, dept.name, os_choice, f"192.168.{subnet}.{RNG.randint(10, 250)}", role))
        subnet += 1

    # A handful of servers — always Linux/Windows-Server-flavored, never laptops.
    for name, os_choice in [
        ("SRV-DB-01", "linux"), ("SRV-DB-02", "linux"), ("SRV-WEB-01", "linux"), ("SRV-WEB-02", "linux"),
        ("SRV-FILE-01", "windows"), ("SRV-AUTH-01", "windows"),
    ]:
        hosts.append(SimHost(name, "IT", os_choice, f"192.168.99.{RNG.randint(10, 250)}", "server"))

    return hosts


REGULAR_HOSTS = _build_hosts()

# Named showcase hosts (task item 15) — same naming convention as the
# rest of the fleet's "role-coded" names, just with an explicit,
# unmissable label for the presentation walkthrough.
SHOWCASE_HOSTS = {
    "critical": SimHost("DEMO-CRITICAL-01", "Engineering", "windows", "192.168.50.10", "workstation"),
    "high": SimHost("DEMO-HIGH-01", "Finance", "windows", "192.168.50.11", "workstation"),
    "medium": SimHost("DEMO-MEDIUM-01", "Sales", "windows", "192.168.50.12", "laptop"),
    "low": SimHost("DEMO-LOW-01", "IT", "linux", "192.168.50.13", "server"),
}

ALL_HOSTS = REGULAR_HOSTS + list(SHOWCASE_HOSTS.values())


def _users_for_department(dept_name: str) -> list[str]:
    dept = next(d for d in DEPARTMENTS if d.name == dept_name)
    return [u for u in USERS if u.split(".")[0] in dept.user_first_names] or USERS


def _user_for_host(host: SimHost) -> str:
    """80% same-department user, 20% cross-department (an IT admin touching another team's box, etc.)."""
    if RNG.random() < 0.8:
        return RNG.choice(_users_for_department(host.department))
    return RNG.choice(USERS)


# ══════════════════════════════════════════════════════════════════════
# Event construction
# ══════════════════════════════════════════════════════════════════════

# log_type -> [(action, is_benign)] — every action here is a plain string
# field on NormalizedLog (no enum constraint beyond log_type/severity/source),
# matching this repo's existing convention (injector.py's own ACTIONS dict).
BENIGN_ACTIONS = {
    "authentication": ["login_success", "logout", "password_change"],
    "network": ["outbound_connection", "inbound_connection", "dns_query"],
    "process": ["process_start", "process_stop", "scheduled_task_run"],
    "file": ["file_create", "file_modify", "permission_change"],
    "system": ["service_restart", "policy_check_passed", "backup_completed"],
}

# Suspicious/attack-relevant single-event actions used for occasional
# non-scenario "noise" alerts (medium/high severity mixed into the
# background, without necessarily forming a full correlated chain) —
# from the task's own example vocabulary. Deliberately excludes
# failed_login and suspicious_network_connection even though the task
# lists both as example event types: those two are the exact triggering
# conditions services/correlation.py's brute-force and
# recon-to-exploitation detectors match on, and background noise sends
# enough events per host, all in the same real-time correlation window
# (the detector scores by real send-time, not this generator's own
# backdated `timestamp` field — see make_event's docstring), that a few
# random hits are enough to occasionally satisfy a threshold by
# coincidence — observed live as unplanned incidents with no coherent
# scenario behind them. unusual_authentication/policy_violation don't
# match any detector's log_type/action condition, so they stay safe
# "noise that looks suspicious but isn't part of a chain."
SUSPICIOUS_STANDALONE_ACTIONS = [
    ("authentication", "unusual_authentication"),
    ("system", "policy_violation"),
]

def make_event(
    host: SimHost,
    user: str,
    log_type: str,
    action: str,
    severity: str,
    description: str,
    *,
    timestamp: Optional[datetime] = None,
    mitre_technique: Optional[str] = None,
    mitre_tactic: Optional[str] = None,
    destination_ip: Optional[str] = None,
) -> dict:
    """
    One NormalizedLog-shaped dict. Deliberately never sets source_ip or
    file_hash: both are real threat-intel enrichment triggers
    (services/enrichment.py checks exactly these two fields) that would
    otherwise fire live VirusTotal/AbuseIPDB calls for fabricated demo
    indicators on every ingested event — this generator stays fully
    self-contained and fast instead. destination_ip is fine to set
    (enrichment never reads it) and is used by the lateral-movement/
    exfiltration-shaped scenarios below, matching injector.py's own
    existing scenario functions.

    `timestamp` defaults to real "now", NOT a randomly-backdated value:
    scenario events (this function's main caller) need to land inside
    settings.RISK_RECALC_LOOKBACK_HOURS (24h by default) to actually
    influence the endpoint's computed risk score — a scenario meant to
    make a host look critical *right now* would otherwise have only a
    ~5% chance (24h / (WINDOW_DAYS*24h)) of any given event landing in
    that window if backdated across the full simulation history like
    background noise correctly is (generate_background_events passes
    its own explicit backdated timestamp instead of relying on this
    default).
    """
    ts = timestamp or datetime.now(timezone.utc)
    event = {
        "source": "synthetic",
        "log_type": log_type,
        "timestamp": ts.isoformat(),
        "host_id": host.host_id,
        "host_ip": host.host_ip,
        "host_os": host.os,
        "user": user,
        "action": action,
        "description": description,
        "severity": severity,
        "raw_log": '{"synthetic": true, "generator": "safesoc-simulation"}',
    }
    if mitre_technique:
        event["mitre_technique"] = mitre_technique
    if mitre_tactic:
        event["mitre_tactic"] = mitre_tactic
    if destination_ip:
        event["destination_ip"] = destination_ip
    return event


# ══════════════════════════════════════════════════════════════════════
# Background / benign telemetry (task item 3, 4)
# ══════════════════════════════════════════════════════════════════════

# Weighted so the environment-wide severity distribution naturally comes
# out LOW >> MEDIUM >> HIGH >> CRITICAL (task item 4) once scenario
# events (mostly medium/high/critical) are layered on top of this.
BACKGROUND_SEVERITY_WEIGHTS = {"low": 82, "medium": 15, "high": 2.7, "critical": 0.3}


def generate_background_events(hosts: list[SimHost], count: int) -> list[dict]:
    """
    Spread across the full WINDOW_DAYS-day history (for a realistic
    "Alerts Over Time" trend), but weighted so only ~10% of events land
    within the last 24h — the window settings.RISK_RECALC_LOOKBACK_HOURS
    actually scores against. Kept deliberately small: risk_scoring.py
    sums severity points per in-window alert with no averaging/dampening,
    so even "routine" 24h volume adds up fast — 10% still leaves a "low"
    host a couple of genuine recent alerts behind its (small, nonzero)
    score, without swamping it into medium/high territory on volume
    alone (measured live before settling on this fraction).
    """
    events = []
    severities = list(BACKGROUND_SEVERITY_WEIGHTS.keys())
    weights = list(BACKGROUND_SEVERITY_WEIGHTS.values())
    now = datetime.now(timezone.utc)

    for _ in range(count):
        host = RNG.choice(hosts)
        user = _user_for_host(host)
        # 92% routine/benign activity, 8% a standalone suspicious event
        # (not part of a designed scenario — isolated noise, the kind of
        # thing that shows up in a real environment without becoming an
        # incident on its own).
        if RNG.random() < 0.92:
            log_type = RNG.choice(list(BENIGN_ACTIONS.keys()))
            action = RNG.choice(BENIGN_ACTIONS[log_type])
            severity = RNG.choices(severities, weights=weights)[0]
        else:
            log_type, action = RNG.choice(SUSPICIOUS_STANDALONE_ACTIONS)
            severity = RNG.choices(["medium", "high"], weights=[70, 30])[0]

        if RNG.random() < 0.10:
            minutes_ago = RNG.randint(0, 24 * 60)
        else:
            minutes_ago = RNG.randint(24 * 60, WINDOW_DAYS * 24 * 60)
        timestamp = now - timedelta(minutes=minutes_ago)

        events.append(
            make_event(host, user, log_type, action, severity, f"{action.replace('_', ' ').capitalize()} on {host.host_id}",
                       timestamp=timestamp)
        )

    return events


# ══════════════════════════════════════════════════════════════════════
# MITRE-tagged attack scenarios (task items 5, 6)
# ══════════════════════════════════════════════════════════════════════
# Each scenario is engineered to satisfy at least one of
# services/correlation.py's six real detector thresholds, so the
# resulting incident is created by the ACTUAL correlation engine acting
# on this synthetic data — never inserted directly. Every technique id
# below is a real, well-documented MITRE ATT&CK technique.


def credential_attack_scenario(host: SimHost, user: str, include_escalation: bool = False) -> list[dict]:
    """
    Failed logins -> successful login -> (optionally) privilege
    escalation. Triggers SUCCESSFUL_COMPROMISE (6 failed_login +
    login_success) and, with `include_escalation`, PRIVILEGE_ESCALATION
    too (login_success + a privilege event) — they share the
    login_success alert, so create_or_merge_incident merges both
    detections into ONE incident (services/incidents.py's own
    shared-alert-id merge rule).

    Severity/MITRE tagging is deliberately light: services/risk_scoring.py
    sums severity + MITRE-bonus points per alert with no per-event
    dampening and caps the total at 100, so tagging every event of a
    6+-event scenario pushes the host to 100/critical regardless of how
    "severe" the scenario is meant to look — measured live before
    settling on this budget. Only the two narratively-key events
    (login_success, and the escalation event when included) carry a
    MITRE tag; the failed_login volume stays untagged, low-severity
    "attempt" noise, which is also realistic (most brute-force attempts
    in a real log are unremarkable individually).
    """
    events = [
        make_event(host, user, "authentication", "failed_login", "low",
                   f"Failed login attempt for {user} on {host.host_id}")
        for _ in range(6)
    ]
    events.append(make_event(host, user, "authentication", "login_success", "low",
                              f"{user} authenticated successfully on {host.host_id} after repeated failures",
                              mitre_technique="T1078", mitre_tactic="Initial Access"))
    if include_escalation:
        # critical, not high: this event only fires for a host this
        # generator is deliberately pushing to the critical tier (see
        # build_simulation_plan), and detect_privilege_escalation's own
        # confidence mapping treats "critical" as the stronger signal
        # (0.95 vs. "high"'s 0.75) — matching that instead of
        # understating it also means the environment has at least a
        # handful of genuinely critical-*severity* alerts, not just
        # critical-*risk-level* endpoints derived from point volume.
        events.append(make_event(host, user, "privilege", "privilege_escalation", "critical",
                                  f"Privilege escalation detected for {user} on {host.host_id}",
                                  mitre_technique="T1068", mitre_tactic="Privilege Escalation"))
    return events


def malware_scenario(host: SimHost, user: str) -> list[dict]:
    """
    Suspicious download/staging -> process execution -> malware
    detection -> persistence. Triggers RECON_TO_EXPLOITATION (3+
    network-type events, then a process-type event). See
    credential_attack_scenario's docstring on why MITRE tagging here is
    limited to the single headline (process_execution) event.
    """
    events = [
        make_event(host, user, "network", "suspicious_network_connection", "low",
                   f"Outbound connection to an uncategorized host from {host.host_id}")
        for _ in range(3)
    ]
    events.append(make_event(host, user, "process", "process_execution", "high",
                              f"Unrecognized executable launched on {host.host_id}",
                              mitre_technique="T1204", mitre_tactic="Execution"))
    events.append(make_event(host, user, "file", "malware_detected", "medium",
                              f"Malware signature match on {host.host_id}"))
    events.append(make_event(host, user, "system", "persistence", "low",
                              f"Unexpected autostart entry created on {host.host_id}"))
    return events


def lateral_movement_scenario(primary: SimHost, secondary: SimHost, user: str) -> list[dict]:
    """
    Compromised endpoint -> remote authentication -> second endpoint ->
    lateral movement. Triggers LATERAL_MOVEMENT (login_success then an
    outbound connection to a private destination). See
    credential_attack_scenario's docstring on the light MITRE-tagging
    budget this follows.
    """
    events = [
        make_event(primary, user, "authentication", "login_success", "low",
                   f"{user} authenticated on {primary.host_id}"),
        make_event(primary, user, "network", "remote_login", "high",
                   f"Remote authentication from {primary.host_id} toward {secondary.host_id}",
                   destination_ip=secondary.host_ip, mitre_technique="T1021", mitre_tactic="Lateral Movement"),
        make_event(primary, user, "network", "outbound_connection", "low",
                   f"Internal connection from {primary.host_id} to {secondary.host_id}",
                   destination_ip=secondary.host_ip),
    ]
    # A corresponding sign-in on the second endpoint — real relationship
    # evidence (both hosts show up in evidence/graph data), even though
    # the detector itself only needs the primary host's window.
    events.append(make_event(secondary, user, "authentication", "login_success", "low",
                              f"{user} authenticated on {secondary.host_id} shortly after activity on {primary.host_id}"))
    return events


def powershell_scenario(host: SimHost, user: str) -> list[dict]:
    """
    Authentication -> PowerShell execution -> suspicious process ->
    network connection. Triggers RECON_TO_EXPLOITATION via 3 network
    events followed by a process event, framed around a PowerShell
    execution chain specifically (distinct narrative from malware_scenario
    even though it shares a detector). See credential_attack_scenario's
    docstring on the light MITRE-tagging budget this follows.
    """
    events = [make_event(host, user, "authentication", "login_success", "low", f"{user} authenticated on {host.host_id}")]
    events += [
        make_event(host, user, "network", "suspicious_network_connection", "low",
                   f"Network beacon-like activity from {host.host_id} during a PowerShell session")
        for _ in range(3)
    ]
    events.append(make_event(host, user, "process", "powershell_execution", "high",
                              f"Obfuscated PowerShell command executed on {host.host_id}",
                              mitre_technique="T1059.001", mitre_tactic="Execution"))
    return events


def benign_scenario(host: SimHost, user: str) -> list[dict]:
    """Normal authentication -> normal activity -> no incident. Deliberately below every detector's threshold."""
    return [
        make_event(host, user, "authentication", "login_success", "low", f"{user} signed in on {host.host_id}"),
        make_event(host, user, "file", "file_modify", "low", f"{user} updated a document on {host.host_id}"),
        make_event(host, user, "authentication", "logout", "low", f"{user} signed out of {host.host_id}"),
    ]


SCENARIO_STATUS_PLAN: list[str] = [
    "resolved", "resolved", "investigating", "investigating", "open", "open", "open",
]  # cycled across however many scenario incidents actually get created — a realistic status mix (task item 7)


# ══════════════════════════════════════════════════════════════════════
# Software & vulnerability inventory (task items 9, 10)
# ══════════════════════════════════════════════════════════════════════
# real=True entries are genuine, publicly-documented CVEs, each attached
# only to the specific old/vulnerable software+version they actually
# affect — never invented. Every other vulnerability uses a clearly
# synthetic "DEMO-VULN-####" id with is_synthetic=True. Most software
# rows carry NO vulnerability at all (the realistic common case).

REAL_VULNERABILITIES = {
    # (software name, version) -> vulnerability dict. Sourced from public,
    # widely-documented historical disclosures (kept intentionally to a
    # small set of extremely well-known cases this generator is
    # confident about, per the task's "only when genuinely known" rule).
    ("Apache Log4j", "2.14.1"): {
        "id": "CVE-2021-44228", "severity": "critical", "is_synthetic": False,
        "title": "Log4Shell — remote code execution via unsanitized JNDI lookups",
    },
    ("OpenSSL", "1.0.1f"): {
        "id": "CVE-2014-0160", "severity": "critical", "is_synthetic": False,
        "title": "Heartbleed — out-of-bounds read discloses process memory",
    },
    ("Windows SMBv1 Protocol", "1.0"): {
        "id": "CVE-2017-0144", "severity": "critical", "is_synthetic": False,
        "title": "EternalBlue — remote code execution via crafted SMBv1 packets",
    },
    ("Windows Print Spooler Service", "10.0.19041"): {
        "id": "CVE-2021-34527", "severity": "high", "is_synthetic": False,
        "title": "PrintNightmare — remote code execution in the Windows Print Spooler",
    },
    ("Apache Struts", "2.3.31"): {
        "id": "CVE-2017-5638", "severity": "critical", "is_synthetic": False,
        "title": "Remote code execution via a crafted Content-Type header",
    },
    ("Adobe Flash Player", "32.0.0.371"): {
        "id": "CVE-2018-4878", "severity": "high", "is_synthetic": False,
        "title": "Use-after-free vulnerability enabling remote code execution",
    },
}

_DEMO_VULN_POOL = [
    {"id": "DEMO-VULN-1001", "severity": "low", "is_synthetic": True, "title": "Outdated TLS cipher configuration (demo-only finding)"},
    {"id": "DEMO-VULN-1002", "severity": "medium", "is_synthetic": True, "title": "Weak local password policy detected (demo-only finding)"},
    {"id": "DEMO-VULN-1003", "severity": "medium", "is_synthetic": True, "title": "Unpatched third-party plugin (demo-only finding)"},
    {"id": "DEMO-VULN-1004", "severity": "high", "is_synthetic": True, "title": "End-of-life software version, no longer receiving updates (demo-only finding)"},
    {"id": "DEMO-VULN-1005", "severity": "critical", "is_synthetic": True, "title": "Default administrative credentials still enabled (demo-only finding)"},
]

# (name, category, [candidate versions]) — the common, mostly-unremarkable
# baseline every host draws its software from. `vulnerable_version` (if
# present) is a version deliberately matching REAL_VULNERABILITIES above,
# only assigned to higher-risk-tier hosts (see assign_software below).
# 4th element is an os_family filter ("windows"/"linux"/"macos"/None for
# any) — checked against the host's own host.os so, e.g., a Windows-only
# component never lands on a Linux/macOS host (task item 18: no
# internally-inconsistent demo data).
_SOFTWARE_POOL = {
    "operating_system": [
        ("Windows 11", ["23H2", "22H2"], None, "windows"),
        ("Windows 10", ["22H2"], None, "windows"),
        ("Ubuntu Linux", ["22.04 LTS", "20.04 LTS"], None, "linux"),
        ("macOS Sonoma", ["14.2", "14.1"], None, "macos"),
        ("Windows Server 2022", ["21H2"], None, "windows"),
    ],
    "browser": [
        ("Google Chrome", ["118.0.5993.70", "117.0.5938.92"], None, None),
        ("Mozilla Firefox", ["119.0", "118.0.2"], None, None),
        ("Microsoft Edge", ["118.0.2088.46"], None, None),
    ],
    "productivity": [
        ("Microsoft 365 Apps", ["2309", "2308"], None, None),
        ("Slack", ["4.35.126"], None, None),
        ("Zoom", ["5.16.2"], None, None),
        ("Notepad++", ["8.5.8"], None, "windows"),
    ],
    "runtime": [
        ("Python", ["3.11.5", "3.10.12"], None, None),
        ("Node.js", ["18.17.1"], None, None),
        ("Java Runtime Environment", ["17.0.8"], None, None),
        (".NET Runtime", ["7.0.10"], None, "windows"),
        ("Apache Log4j", ["2.20.0"], "2.14.1", None),
        ("OpenSSL", ["3.0.10"], "1.0.1f", None),
        ("Apache Struts", ["6.3.0"], "2.3.31", None),
    ],
    "remote_admin": [
        ("TeamViewer", ["15.48.4"], None, None),
        ("AnyDesk", ["8.0.8"], None, None),
    ],
    "security": [
        ("Windows Defender", ["4.18.23090"], None, "windows"),
        ("CrowdStrike Falcon Sensor", ["7.05"], None, None),
        ("Malwarebytes", ["4.6"], None, None),
    ],
    "other": [
        ("Adobe Flash Player", [], "32.0.0.371", None),  # legacy-only entry — no "current" version, vulnerable variant or nothing
        ("Windows SMBv1 Protocol", [], "1.0", "windows"),
        ("Windows Print Spooler Service", [], "10.0.19041", "windows"),
    ],
}

# Probability (per software row) of attaching a vulnerability, and the
# pool it's drawn from, by intended risk tier.
_VULN_PROFILE = {
    "critical": {"real_chance": 0.5, "demo_chance": 0.6, "demo_weights": [10, 15, 15, 30, 30]},
    "high": {"real_chance": 0.3, "demo_chance": 0.45, "demo_weights": [15, 25, 25, 25, 10]},
    "medium": {"real_chance": 0.05, "demo_chance": 0.35, "demo_weights": [30, 35, 25, 10, 0]},
    "low": {"real_chance": 0.0, "demo_chance": 0.12, "demo_weights": [60, 30, 10, 0, 0]},
}


def assign_software(host: SimHost, tier: str) -> list[dict]:
    """
    Deterministically generate this host's software inventory + any
    vulnerabilities, biased by `tier` (the risk tier this generator is
    deliberately steering the host toward via its assigned alert
    scenario — not a claim about the eventual computed risk_score,
    which the real risk-scoring engine still derives independently from
    the alerts actually sent).
    """
    profile = _VULN_PROFILE[tier]
    rows = []

    categories = ["operating_system", "browser", "browser", "productivity", "productivity", "runtime", "security"]
    if RNG.random() < 0.3:
        categories.append("remote_admin")
    if tier in ("critical", "high") and RNG.random() < 0.6:
        categories.append("other")  # legacy/vulnerable-only entries mostly show up on riskier hosts

    seen_names: set[str] = set()
    for category in categories:
        # os_family None means "any OS" — always a candidate; otherwise it
        # must match this host's actual OS (no Windows-only component on
        # a Linux/macOS host, etc.).
        candidates = [c for c in _SOFTWARE_POOL[category] if c[3] is None or c[3] == host.os]
        if not candidates:
            continue
        name, versions, vulnerable_version, _os_family = RNG.choice(candidates)
        if name in seen_names:
            continue
        seen_names.add(name)

        use_vulnerable = vulnerable_version is not None and (not versions or RNG.random() < profile["real_chance"])
        version = vulnerable_version if use_vulnerable else (RNG.choice(versions) if versions else vulnerable_version)
        if version is None:
            continue

        vulnerabilities = []
        real_vuln = REAL_VULNERABILITIES.get((name, version))
        if real_vuln is not None:
            vulnerabilities.append(real_vuln)
        elif RNG.random() < profile["demo_chance"]:
            vulnerabilities.append(RNG.choices(_DEMO_VULN_POOL, weights=profile["demo_weights"])[0])

        rows.append({"name": name, "version": version, "category": category, "vulnerabilities": vulnerabilities})

    return rows


# ══════════════════════════════════════════════════════════════════════
# Host -> scenario assignment plan (deterministic)
# ══════════════════════════════════════════════════════════════════════


@dataclass
class HostPlan:
    host: SimHost
    tier: str
    scenarios: list = field(default_factory=list)  # list of (name, event_builder_result)


def build_simulation_plan() -> list[HostPlan]:
    plans: dict[str, HostPlan] = {h.host_id: HostPlan(h, "low") for h in ALL_HOSTS}
    pool = list(REGULAR_HOSTS)
    RNG.shuffle(pool)

    def take(n: int) -> list[SimHost]:
        chosen, remaining = pool[:n], pool[n:]
        pool[:] = remaining
        return chosen

    for host in take(3):
        plans[host.host_id].tier = "high"
        plans[host.host_id].scenarios.append(("credential_attack", credential_attack_scenario(host, _user_for_host(host))))

    for host in take(3):
        plans[host.host_id].tier = "high"
        plans[host.host_id].scenarios.append(("malware", malware_scenario(host, _user_for_host(host))))

    for _ in range(2):
        pair = take(2)
        if len(pair) < 2:
            break
        primary, secondary = pair
        user = _user_for_host(primary)
        plans[primary.host_id].tier = "high"
        plans[secondary.host_id].tier = "medium"
        plans[primary.host_id].scenarios.append(("lateral_movement", lateral_movement_scenario(primary, secondary, user)))

    for host in take(3):
        plans[host.host_id].tier = "high"
        plans[host.host_id].scenarios.append(("powershell", powershell_scenario(host, _user_for_host(host))))

    for host in take(6):
        plans[host.host_id].tier = "low"
        plans[host.host_id].scenarios.append(("benign", benign_scenario(host, _user_for_host(host))))

    # Named showcase hosts — guaranteed composition per tier (task item 15).
    critical_host = SHOWCASE_HOSTS["critical"]
    critical_user = _user_for_host(critical_host)
    plans[critical_host.host_id] = HostPlan(critical_host, "critical", [
        ("credential_attack", credential_attack_scenario(critical_host, critical_user, include_escalation=True)),
        ("lateral_movement", lateral_movement_scenario(critical_host, REGULAR_HOSTS[0], critical_user)),
    ])

    high_host = SHOWCASE_HOSTS["high"]
    high_user = _user_for_host(high_host)
    # A single scenario, not stacked: powershell_scenario and
    # malware_scenario both satisfy RECON_TO_EXPLOITATION (3+ network
    # events then a process event) — sending both back-to-back on the
    # same host risks the second detection matching against the first
    # scenario's still-in-window network events instead of its own
    # (observed live), which would still merge into a real incident but
    # wouldn't match this run's own alert_ids in the wait-for-incident
    # poll below. One scenario reliably reaches "high" tier on its own
    # (its powershell_execution event is already high-severity).
    plans[high_host.host_id] = HostPlan(high_host, "high", [
        ("powershell", powershell_scenario(high_host, high_user)),
    ])

    medium_host = SHOWCASE_HOSTS["medium"]
    medium_user = _user_for_host(medium_host)
    # A brute-force attempt that does NOT succeed — enough failed logins to
    # register as suspicious activity (and, at 6 attempts, to itself cross
    # BRUTE_FORCE_MIN_ATTEMPTS, so it still produces one real incident) but
    # without the escalation chain that would push this host to high/critical.
    plans[medium_host.host_id] = HostPlan(medium_host, "medium", [
        ("credential_attack", [
            make_event(medium_host, medium_user, "authentication", "failed_login", "low",
                       f"Failed login attempt for {medium_user} on {medium_host.host_id}")
            for _ in range(6)
        ]),
    ])

    low_host = SHOWCASE_HOSTS["low"]
    plans[low_host.host_id] = HostPlan(low_host, "low", [
        ("benign", benign_scenario(low_host, _user_for_host(low_host))),
    ])

    return list(plans.values())


# ══════════════════════════════════════════════════════════════════════
# Ingestion helpers
# ══════════════════════════════════════════════════════════════════════


def _send_in_batches(ingest_url: str, token: str, logs: list[dict], label: str) -> list[str]:
    all_alert_ids: list[str] = []
    for i in range(0, len(logs), INGEST_BATCH_SIZE):
        batch = logs[i:i + INGEST_BATCH_SIZE]
        result = send_logs(ingest_url, batch, token=token)
        all_alert_ids += result.get("alert_ids", [])
        print(f"  [{label}] batch {i // INGEST_BATCH_SIZE + 1}: {result['accepted']} accepted, {result['rejected']} rejected")
    return all_alert_ids


# ══════════════════════════════════════════════════════════════════════
# Reset
# ══════════════════════════════════════════════════════════════════════


async def _reset_async() -> None:
    # asyncpg connections in the shared engine's pool (app.db.postgresql)
    # are bound to the event loop that created them — each top-level
    # asyncio.run() call in this script (and demo.py's own
    # _ensure_demo_tenant() before it) gets a fresh loop, so a
    # connection left in the pool from an earlier asyncio.run() call is
    # unusable here (observed live: "Event loop is closed" /
    # AttributeError deep in asyncpg). Disposing before first use is the
    # same fix tasks/scoring.py and workers/correlation_worker.py
    # already apply for this exact reason.
    await engine.dispose()

    print("Deleting OpenSearch documents for the demo tenant...")
    client = get_opensearch_client()
    try:
        response = client.delete_by_query(
            index="safesoc-alerts-*",
            body={"query": {"term": {"tenant_id": str(DEMO_TENANT_ID)}}},
            conflicts="proceed",
        )
        print(f"  Deleted {response.get('deleted', 0)} alert document(s)")
    except Exception as e:
        print(f"  WARNING: OpenSearch cleanup failed ({type(e).__name__}: {e}) — continuing")

    print("Deleting Postgres rows for the demo tenant...")
    async with async_session_factory() as db:
        incident_ids = (await db.execute(select(Incident.id).where(Incident.tenant_id == DEMO_TENANT_ID))).scalars().all()
        if incident_ids:
            await db.execute(delete(IncidentStateTransition).where(IncidentStateTransition.incident_id.in_(incident_ids)))
            await db.execute(delete(IncidentNote).where(IncidentNote.incident_id.in_(incident_ids)))
        await db.execute(delete(Incident).where(Incident.tenant_id == DEMO_TENANT_ID))
        await db.execute(delete(Endpoint).where(Endpoint.tenant_id == DEMO_TENANT_ID))
        await db.execute(delete(EndpointSoftware).where(EndpointSoftware.tenant_id == DEMO_TENANT_ID))
        await db.execute(delete(AlertAnnotation).where(AlertAnnotation.tenant_id == DEMO_TENANT_ID))
        await db.execute(delete(AuditLog).where(AuditLog.tenant_id == DEMO_TENANT_ID))
        await db.commit()
    print("  Postgres rows deleted (tenant/user rows kept, so login still works).")

    # Correlation windows (services/correlation.py) are per-(tenant,host)
    # Redis sorted sets with up to a CORRELATION_WINDOW_TTL-second lifetime
    # (1h by default) — NOT touched by the OpenSearch/Postgres cleanup
    # above. Left alone, a stale window from a previous seed run mixes
    # old alert_ids into the next run's pattern detection (observed live:
    # a detector matched against a stale event from an earlier run,
    # producing a chain whose alert_ids didn't overlap the alerts this
    # run had just sent, so incident-detection polling reported a false
    # "not detected" even though the detector logic itself was fine).
    print("Clearing correlation-engine sliding windows for the demo tenant...")
    redis_client = get_redis_client()
    cursor = 0
    deleted = 0
    pattern = f"correlation:window:{DEMO_TENANT_ID}:*"
    while True:
        cursor, keys = await redis_client.scan(cursor=cursor, match=pattern, count=500)
        if keys:
            deleted += await redis_client.delete(*keys)
        if cursor == 0:
            break
    print(f"  Deleted {deleted} correlation window key(s)")


def reset() -> None:
    asyncio.run(_reset_async())


# ══════════════════════════════════════════════════════════════════════
# Seed
# ══════════════════════════════════════════════════════════════════════


async def _seed_software_async(plans: list[HostPlan]) -> None:
    await engine.dispose()  # see _reset_async's comment on why this precedes first use
    print(f"Generating software/vulnerability inventory for {len(plans)} hosts...")
    async with async_session_factory() as db:
        for plan in plans:
            for row in assign_software(plan.host, plan.tier):
                await upsert_software(
                    db, DEMO_TENANT_ID, plan.host.host_id, row["name"], row["version"],
                    SoftwareCategory(row["category"]), row["vulnerabilities"],
                )


def seed(api_base: str) -> None:
    ingest_url = f"{api_base}/api/v1/ingest"

    print("Provisioning demo tenant...")
    asyncio.run(_ensure_demo_tenant())
    print("Registering demo user (idempotent)...")
    _register_demo_user(api_base)
    print("Logging in...")
    token = _login(api_base)

    plans = build_simulation_plan()
    print(f"\nSimulation plan: {len(ALL_HOSTS)} hosts ({len(REGULAR_HOSTS)} regular + {len(SHOWCASE_HOSTS)} showcase), "
          f"{len(USERS)} users, {sum(len(p.scenarios) for p in plans)} scenario instance(s).")

    # Scenario events go FIRST, deliberately, and each is waited-on before
    # the next is sent: this is the correlation-sensitive part (a
    # detected chain -> incident requires the Celery worker to evaluate
    # this exact alert batch promptly). Sending the much larger
    # background-noise batch first was tried and measured live: it
    # queues thousands of enrichment/correlation/notification tasks
    # ahead of the scenario events in the same Celery queue, so a
    # scenario's own correlation task can sit behind that entire backlog
    # and miss a short poll window even though nothing is actually wrong
    # — the background noise below is fire-and-forget precisely because
    # it doesn't need a prompt answer, so it's sent last instead.
    print("\nSending scenario events and waiting for the correlation engine...")
    created_incident_ids: list[str] = []
    for plan in plans:
        for name, events in plan.scenarios:
            sent = send_logs(ingest_url, events, token=token)
            print(f"  [{plan.host.host_id}] {name}: {sent['accepted']} accepted")
            if name == "benign":
                continue  # deliberately below every detector's threshold — no incident expected
            incident_id = _wait_for_incident_with_alert(api_base, token, sent["alert_ids"], timeout_seconds=30.0)
            if incident_id and incident_id not in created_incident_ids:
                created_incident_ids.append(incident_id)
                print(f"    -> incident {incident_id}")
            elif not incident_id:
                print(f"    WARNING: no incident detected for {plan.host.host_id}/{name} within the timeout")

    print(f"\n{len(created_incident_ids)} incident(s) detected. Applying a realistic status mix...")
    for i, incident_id in enumerate(created_incident_ids):
        target_status = SCENARIO_STATUS_PLAN[i % len(SCENARIO_STATUS_PLAN)]
        try:
            if target_status in ("investigating", "resolved"):
                _transition(api_base, token, incident_id, "investigating")
            if target_status == "resolved":
                _transition(api_base, token, incident_id, "resolved")
            print(f"  {incident_id} -> {target_status}")
        except requests.exceptions.HTTPError as e:
            print(f"  WARNING: transition failed for {incident_id}: {e}")

    asyncio.run(_seed_software_async(plans))

    print(f"\nSending {BACKGROUND_EVENT_COUNT} background events across the last {WINDOW_DAYS} days "
          "(fire-and-forget — no incident expected from this pool)...")
    background = generate_background_events(ALL_HOSTS, BACKGROUND_EVENT_COUNT)
    _send_in_batches(ingest_url, token, background, "background")

    # Risk scores are normally only (re)computed by a scheduled Celery
    # beat task (tasks/scoring.py, every settings.RISK_RECALC_INTERVAL_MINUTES
    # — 15 by default), which a one-shot seed script can't reasonably wait
    # on. Calling the same task's async implementation directly, in-process,
    # runs the identical scoring logic against the data just ingested
    # (bulk_index_logs writes with refresh=True, so it's already
    # searchable) without waiting on — or duplicating — that schedule.
    print("\nComputing endpoint risk scores from the generated telemetry...")
    time.sleep(3)  # brief buffer for OpenSearch/Postgres to fully settle
    asyncio.run(_recalculate_all_risk_scores_async())

    print("\nSimulation seed complete.")
    print(f"  Tenant ID: {DEMO_TENANT_ID}")
    print(f"  Login:     {DEMO_EMAIL} / {DEMO_PASSWORD}")
    print(f"  Hosts:     {len(ALL_HOSTS)}   Users: {len(USERS)}   Incidents: {len(created_incident_ids)}")
    print("  All data above is 100% synthetic — see this file's module docstring.")


def main() -> None:
    parser = argparse.ArgumentParser(description="SafeSOC synthetic SOC simulation / demo data generator")
    parser.add_argument("--api-base", default="http://localhost:8000", help="Backend base URL")
    parser.add_argument("--reset", action="store_true", help="Delete this simulation's OpenSearch/Postgres data")
    parser.add_argument("--seed", action="store_true", help="Populate the simulation (default action if neither flag is given)")
    args = parser.parse_args()

    if not args.reset and not args.seed:
        args.seed = True  # `python injector/simulate.py` alone still seeds, matching demo.py's own zero-flag convention

    if args.reset:
        print("=== RESET ===")
        reset()
    if args.seed:
        print("\n=== SEED ===" if args.reset else "=== SEED ===")
        seed(args.api_base)


if __name__ == "__main__":
    main()
