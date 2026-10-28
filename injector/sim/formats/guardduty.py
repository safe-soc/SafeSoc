"""
SafeSOC — Simulator AWS GuardDuty Builders
GuardDuty findings (SchemaVersion 2.0) in the GetFindings API shape
(PascalCase keys), ingested with source "aws_guardduty".

Country and Organization for the remote IP are caller-supplied: real
attacker IPs must never get hard-coded geo/ASN data here. Pass what
live threat intel returned, or leave the "Unknown" defaults.
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Optional

from injector.sim.formats.wazuh_common import iso_z, stable_hex
from injector.sim.org import Org

__all__ = ["finding", "instance_credential_exfiltration_outside_aws"]

UNKNOWN = "Unknown"


def remote_ip_details(
    ip: str, *, country: str = UNKNOWN, asn: str = UNKNOWN, asn_org: str = UNKNOWN, isp: str = UNKNOWN,
    org_name: str = UNKNOWN,
) -> dict:
    return {
        "IpAddressV4": ip,
        "Country": {"CountryName": country},
        "Organization": {"Asn": asn, "AsnOrg": asn_org, "Isp": isp, "Org": org_name},
    }


def finding(
    org: Org, timestamp: datetime, *, finding_type: str, title: str, description: str, severity: float,
    access_key_id: str, principal_id: str, user_name: str, user_type: str, api: str, service_name: str,
    remote_ip: dict, caller_type: str = "Remote IP", count: int = 1, first_seen: Optional[datetime] = None,
    simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """
    A finding on an access key whose action is an AWS API call. `remote_ip`
    comes from remote_ip_details(). `timestamp` is when GuardDuty created
    the finding and saw the activity last; `first_seen` defaults to it.
    """
    cloud = org.cloud
    finding_id = (stable_hex("finding", finding_type, access_key_id, iso_z(timestamp, digits=6))
                  if rng is None else f"{rng.getrandbits(128):032x}")
    created = iso_z(timestamp)
    payload = {
        "SchemaVersion": "2.0",
        "AccountId": cloud.account_id,
        "Region": cloud.region,
        "Partition": "aws",
        "Id": finding_id,
        "Arn": f"arn:aws:guardduty:{cloud.region}:{cloud.account_id}:detector/{cloud.guardduty_detector_id}/finding/{finding_id}",
        "Type": finding_type,
        "Resource": {
            "ResourceType": "AccessKey",
            "AccessKeyDetails": {
                "AccessKeyId": access_key_id,
                "PrincipalId": principal_id,
                "UserName": user_name,
                "UserType": user_type,
            },
        },
        "Service": {
            "ServiceName": "guardduty",
            "DetectorId": cloud.guardduty_detector_id,
            "Action": {
                "ActionType": "AWS_API_CALL",
                "AwsApiCallAction": {
                    "Api": api,
                    "CallerType": caller_type,
                    "ServiceName": service_name,
                    "RemoteIpDetails": remote_ip,
                    "AffectedResources": {},
                },
            },
            "Archived": False,
            "Count": count,
            "EventFirstSeen": iso_z(first_seen or timestamp),
            "EventLastSeen": created,
            "ResourceRole": "TARGET",
            "AdditionalInfo": {"Value": "{}", "Type": "default"},
        },
        "Severity": severity,
        "CreatedAt": created,
        "UpdatedAt": created,
        "Title": title,
        "Description": description,
    }
    if simulation is not None:
        payload["simulation"] = simulation
    return payload


def instance_credential_exfiltration_outside_aws(
    org: Org, timestamp: datetime, *, role_name: str, access_key_id: str, principal_id: str, user_name: str,
    remote_ip: dict, api: str = "GetCallerIdentity", service_name: str = "sts.amazonaws.com", user_type: str = "AssumedRole",
    count: int = 1, first_seen: Optional[datetime] = None, simulation: Optional[dict] = None,
    rng: Optional[random.Random] = None,
) -> dict:
    """
    UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
    (High, 8.0): credentials created for an EC2 instance role were used
    from an IP outside AWS. GuardDuty raises this for instance-role
    (AssumedRole) credentials: role_name is the instance role, user_name
    the role session's name (usually the instance ID).
    """
    ip = remote_ip.get("IpAddressV4", "")
    return finding(
        org, timestamp,
        finding_type="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        title=f"Credentials for instance role {role_name} used from external IP address.",
        description=(
            f"Credentials created exclusively for an EC2 instance using instance role {role_name} "
            f"have been used from external IP address {ip}."
        ),
        severity=8.0, access_key_id=access_key_id, principal_id=principal_id, user_name=user_name,
        user_type=user_type, api=api, service_name=service_name, remote_ip=remote_ip, count=count,
        first_seen=first_seen, simulation=simulation, rng=rng,
    )
