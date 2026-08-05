"""
SafeSOC — Synthetic Log Injector
Generates realistic security logs and sends them to the ingestion endpoint.
"""

import json
import random
import sys
from datetime import datetime, timezone
from typing import Optional

import requests

# Configuration
DEFAULT_TARGET = "http://localhost:8000/api/v1/ingest"
TENANT_ID = "acme-corp"

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


def send_logs(target_url: str, logs: list[dict]) -> dict:
    """POST a batch of logs to the ingestion endpoint."""
    payload = {
        "tenant_id": TENANT_ID,
        "source": "synthetic",
        "logs": logs,
    }
    response = requests.post(target_url, json=payload, timeout=10)
    response.raise_for_status()
    return response.json()


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1

    print(f"Target: {target}")
    print(f"Generating {count} log(s)...")

    logs = [generate_log() for _ in range(count)]

    try:
        result = send_logs(target, logs)
        print(f"\nAccepted: {result['accepted']}")
        print(f"Rejected: {result['rejected']}")
        if result.get("alert_ids"):
            for aid in result["alert_ids"]:
                print(f"  Alert ID: {aid}")
        if result.get("errors"):
            print("Errors:")
            for err in result["errors"]:
                print(f"  [{err['index']}] {err['error'][:100]}")
    except requests.exceptions.ConnectionError:
        print("ERROR: Could not connect to SafeSOC backend.")
        print("Is 'docker compose up' running?")


if __name__ == "__main__":
    main()