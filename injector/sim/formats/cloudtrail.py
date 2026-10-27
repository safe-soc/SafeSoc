"""
SafeSOC — Simulator AWS CloudTrail Builders
CloudTrail event records (eventVersion 1.08) for the EmberBay AWS
account, in the shape CloudTrail delivers them to S3 / EventBridge
`detail`. Ingested with source "aws_cloudtrail".
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime
from typing import Any, Optional

from injector.sim.formats.wazuh_common import iso_z, stable_hex
from injector.sim.org import IamUser, Org

__all__ = ["get_caller_identity", "list_buckets", "get_object", "console_login"]

DEFAULT_CLI_USER_AGENT = (
    "aws-cli/2.17.20 md/awscrt#0.20.11 ua/2.0 os/linux#5.15.0-119-generic md/arch#x86_64 lang/python#3.11.9 "
    "md/pyimpl#CPython cfg/retry-mode#standard md/installer#exe md/distrib#ubuntu.22 md/prompt#off"
)
DEFAULT_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)


def _event_id(rng: Optional[random.Random], *seed) -> str:
    if rng is not None:
        return str(uuid.UUID(int=rng.getrandbits(128), version=4))
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "|".join(str(s) for s in seed)))


def _identity(iam_user: IamUser, *, with_key: bool = True) -> dict:
    identity = {
        "type": "IAMUser",
        "principalId": iam_user.principal_id,
        "arn": iam_user.arn,
        "accountId": iam_user.account_id,
    }
    if with_key and iam_user.access_key_id:
        identity["accessKeyId"] = iam_user.access_key_id
    identity["userName"] = iam_user.name
    return identity


def _record(
    org: Org, iam_user: IamUser, ts: datetime, *, event_source: str, event_name: str, source_ip: str, user_agent: str,
    request_parameters: Optional[dict], response_elements: Optional[dict], read_only: bool,
    event_type: str = "AwsApiCall", event_category: str = "Management", management_event: bool = True,
    resources: Optional[list[dict]] = None, error_code: Optional[str] = None, error_message: Optional[str] = None,
    region: Optional[str] = None, with_key: bool = True, extra: Optional[dict] = None,
    simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    seed = (iam_user.arn, event_name, iso_z(ts, digits=6), source_ip)
    record: dict[str, Any] = {
        "eventVersion": "1.08",
        "userIdentity": _identity(iam_user, with_key=with_key),
        "eventTime": iso_z(ts, digits=0),
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region or org.cloud.region,
        "sourceIPAddress": source_ip,
        "userAgent": user_agent,
    }
    if error_code:
        record["errorCode"] = error_code
    if error_code or error_message:
        # A failed ConsoleLogin has errorMessage but no errorCode.
        record["errorMessage"] = error_message or ""
    record["requestParameters"] = request_parameters
    record["responseElements"] = response_elements
    if extra:
        record.update(extra)
    record["requestID"] = stable_hex("req", *seed, length=16).upper() if rng is None else f"{rng.getrandbits(64):016X}"
    record["eventID"] = _event_id(rng, "event", *seed)
    record["readOnly"] = read_only
    if resources is not None:
        record["resources"] = resources
    record["eventType"] = event_type
    record["managementEvent"] = management_event
    record["recipientAccountId"] = org.cloud.account_id
    record["eventCategory"] = event_category
    if simulation is not None:
        record["simulation"] = simulation
    return record


def get_caller_identity(
    org: Org, iam_user: IamUser, timestamp: datetime, *, source_ip: str, user_agent: str = DEFAULT_CLI_USER_AGENT,
    simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """sts:GetCallerIdentity, the usual first call made with a newly obtained key."""
    return _record(
        org, iam_user, timestamp, event_source="sts.amazonaws.com", event_name="GetCallerIdentity",
        source_ip=source_ip, user_agent=user_agent, request_parameters=None, response_elements=None, read_only=True,
        extra={"tlsDetails": {"tlsVersion": "TLSv1.3", "cipherSuite": "TLS_AES_128_GCM_SHA256",
                              "clientProvidedHostHeader": f"sts.{org.cloud.region}.amazonaws.com"}},
        simulation=simulation, rng=rng,
    )


def list_buckets(
    org: Org, iam_user: IamUser, timestamp: datetime, *, source_ip: str, user_agent: str = DEFAULT_CLI_USER_AGENT,
    error_code: Optional[str] = None, error_message: Optional[str] = None, simulation: Optional[dict] = None,
    rng: Optional[random.Random] = None,
) -> dict:
    """s3:ListBuckets (a management event). Pass error_code='AccessDenied' for a denied call."""
    host = "s3.amazonaws.com"
    return _record(
        org, iam_user, timestamp, event_source="s3.amazonaws.com", event_name="ListBuckets", source_ip=source_ip,
        user_agent=user_agent, request_parameters={"Host": host}, response_elements=None, read_only=True,
        error_code=error_code, error_message=error_message,
        extra={"additionalEventData": {"SignatureVersion": "SigV4", "CipherSuite": "TLS_AES_128_GCM_SHA256",
                                       "bytesTransferredIn": 0, "AuthenticationMethod": "AuthHeader",
                                       "x-amz-id-2": stable_hex("id2", iam_user.arn, iso_z(timestamp, digits=6), length=56),
                                       "bytesTransferredOut": 0 if error_code else 512},
               "tlsDetails": {"tlsVersion": "TLSv1.3", "cipherSuite": "TLS_AES_128_GCM_SHA256",
                              "clientProvidedHostHeader": host}},
        simulation=simulation, rng=rng,
    )


def get_object(
    org: Org, iam_user: IamUser, timestamp: datetime, *, source_ip: str, bucket: str, key: str,
    bytes_transferred_out: int, user_agent: str = DEFAULT_CLI_USER_AGENT, simulation: Optional[dict] = None,
    rng: Optional[random.Random] = None,
) -> dict:
    """s3:GetObject: a data event, with the object and bucket ARNs in resources."""
    bucket_arn = org.cloud.bucket(bucket).arn
    host = f"{bucket}.s3.{org.cloud.region}.amazonaws.com"
    return _record(
        org, iam_user, timestamp, event_source="s3.amazonaws.com", event_name="GetObject", source_ip=source_ip,
        user_agent=user_agent, request_parameters={"bucketName": bucket, "Host": host, "key": key},
        response_elements=None, read_only=True, event_category="Data", management_event=False,
        resources=[
            {"type": "AWS::S3::Object", "ARN": f"{bucket_arn}/{key}"},
            {"accountId": org.cloud.account_id, "type": "AWS::S3::Bucket", "ARN": bucket_arn},
        ],
        extra={"additionalEventData": {"SignatureVersion": "SigV4", "CipherSuite": "TLS_AES_128_GCM_SHA256",
                                       "bytesTransferredIn": 0, "AuthenticationMethod": "AuthHeader",
                                       "x-amz-id-2": stable_hex("id2", bucket, key, iso_z(timestamp, digits=6), length=56),
                                       "bytesTransferredOut": bytes_transferred_out},
               "tlsDetails": {"tlsVersion": "TLSv1.3", "cipherSuite": "TLS_AES_128_GCM_SHA256",
                              "clientProvidedHostHeader": host}},
        simulation=simulation, rng=rng,
    )


def console_login(
    org: Org, iam_user: IamUser, timestamp: datetime, *, source_ip: str, success: bool = True, mfa_used: bool = False,
    user_agent: str = DEFAULT_BROWSER_USER_AGENT, simulation: Optional[dict] = None,
    rng: Optional[random.Random] = None,
) -> dict:
    """signin:ConsoleLogin (eventType AwsConsoleSignIn); a failure carries errorMessage 'Failed authentication'."""
    return _record(
        org, iam_user, timestamp, event_source="signin.amazonaws.com", event_name="ConsoleLogin",
        source_ip=source_ip, user_agent=user_agent, request_parameters=None,
        response_elements={"ConsoleLogin": "Success" if success else "Failure"}, read_only=False,
        event_type="AwsConsoleSignIn", with_key=False,
        error_message=None if success else "Failed authentication",
        extra={"additionalEventData": {
            "LoginTo": f"https://console.aws.amazon.com/console/home?region={org.cloud.region}&state=hashArgs%23&isauthcode=true",
            "MobileVersion": "No",
            "MFAUsed": "Yes" if mfa_used else "No",
        }},
        simulation=simulation, rng=rng,
    )
