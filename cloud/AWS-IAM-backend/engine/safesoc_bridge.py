import os
import requests
from dotenv import load_dotenv

load_dotenv()


def sync_findings_to_safesoc(scan_obj):
    """
    Push a completed scan's findings to SafeSOC's ingestion pipeline
    (POST /api/v1/cloud/findings), so they appear in SafeSOC's alert
    queue without a human re-entering them (SS-039).

    Fire-and-forget: any failure here must never break the scan itself,
    the same resilience contract as notifier.send_telegram_report.
    """
    base_url = os.getenv('SAFESOC_API_URL')
    service_token = os.getenv('SAFESOC_SERVICE_TOKEN')
    tenant_id = os.getenv('SAFESOC_TENANT_ID')

    if not base_url or not service_token or not tenant_id:
        print("SafeSOC sync configuration missing. Skipping sync.")
        return

    findings = list(scan_obj.findings.all())
    if not findings:
        return

    payload = {
        "tenant_id": tenant_id,
        "findings": [
            {
                "id": f.id,
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "affected_resource": f.affected_resource,
                "remediation": f.remediation,
            }
            for f in findings
        ],
    }

    try:
        response = requests.post(
            f"{base_url.rstrip('/')}/api/v1/cloud/findings",
            json=payload,
            headers={"X-Service-Token": service_token},
            timeout=8,
        )
        if response.status_code != 200:
            print(f"SafeSOC sync error: {response.text}")
    except Exception as e:
        print(f"Failed to reach SafeSOC: {e}")
