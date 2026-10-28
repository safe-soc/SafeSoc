"""
SafeSOC — Simulator Organisation Model
Loads a company definition (injector/sim/org/*.yaml) into dataclasses
and validates it, so every later scenario can rely on the hosts, users
and addresses it names being consistent.

The company is fictional; only the attacker IPs are real (publicly
reported addresses whose reputation can change). Nothing here records
a country, ASN or owner for those IPs: that comes from live threat
intel when the events are ingested.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

DEFAULT_ORG_PATH = Path(__file__).resolve().parent / "org" / "emberbay.yaml"


class OrgValidationError(ValueError):
    """The YAML loaded but describes an inconsistent company. `problems` lists every issue found."""

    def __init__(self, source: str, problems: list[str]):
        self.problems = problems
        lines = "\n".join(f"  - {p}" for p in problems)
        super().__init__(f"Invalid organisation definition ({source}):\n{lines}")


@dataclass(frozen=True)
class Zone:
    name: str
    vlan: Optional[int]
    subnet: Optional[str]
    purpose: str
    monitored: bool

    @property
    def network(self) -> Optional[ipaddress.IPv4Network]:
        return ipaddress.ip_network(self.subnet) if self.subnet else None

    @property
    def targetable(self) -> bool:
        # Unmonitored zones hold the collectors; scenarios never aim at them.
        return self.monitored


@dataclass(frozen=True)
class Asset:
    hostname: str
    zone: str
    ip: str
    os: str
    os_version: str
    role: str
    services: tuple[str, ...] = ()
    wazuh_agent_id: Optional[str] = None
    primary_user: Optional[str] = None
    owner: Optional[str] = None
    public_ip: Optional[str] = None
    shares: tuple[str, ...] = ()
    databases: tuple[str, ...] = ()
    web_paths: tuple[str, ...] = ()
    vpn_pool: Optional[str] = None

    @property
    def is_windows(self) -> bool:
        return self.os.lower().startswith("windows")


@dataclass(frozen=True)
class User:
    username: str
    display_name: str
    department: str
    title: str
    primary_host: str
    rid: int
    groups: tuple[str, ...] = ()
    vpn_access: bool = False
    aws_access: bool = False
    service_account: bool = False


@dataclass(frozen=True)
class S3Bucket:
    name: str
    sensitivity: str
    note: str = ""

    @property
    def arn(self) -> str:
        return f"arn:aws:s3:::{self.name}"


@dataclass(frozen=True)
class IamUser:
    name: str
    account_id: str
    access_key_id: Optional[str] = None
    key_location: Optional[str] = None
    console_access: bool = False

    @property
    def arn(self) -> str:
        return f"arn:aws:iam::{self.account_id}:user/{self.name}"

    @property
    def principal_id(self) -> str:
        """A stable, IAM-shaped unique ID ("AIDA" + 17 chars) derived from the ARN: fictional but consistent across events."""
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        digest = hashlib.sha256(self.arn.encode()).digest()
        return "AIDA" + "".join(alphabet[b % len(alphabet)] for b in digest[:17])


@dataclass(frozen=True)
class Cloud:
    provider: str
    account_id: str
    region: str
    guardduty_detector_id: str
    s3_buckets: tuple[S3Bucket, ...]
    iam_users: tuple[IamUser, ...]
    services: dict[str, str]

    def bucket(self, name: str) -> S3Bucket:
        for bucket in self.s3_buckets:
            if bucket.name == name:
                return bucket
        raise KeyError(f"Unknown S3 bucket '{name}'")

    def iam_user(self, name: str) -> IamUser:
        for user in self.iam_users:
            if user.name == name:
                return user
        raise KeyError(f"Unknown IAM user '{name}'")


@dataclass(frozen=True)
class Attacker:
    key: str
    role: str
    ip: str
    note: str
    targets: tuple[str, ...] = ()
    secondary_ips: tuple[str, ...] = ()
    label_group: Optional[str] = None

    @property
    def all_ips(self) -> tuple[str, ...]:
        return (self.ip, *self.secondary_ips)


@dataclass(frozen=True)
class PoolIP:
    ip: str
    note: str


@dataclass(frozen=True)
class Org:
    name: str
    domain: str
    netbios_domain: str
    domain_sid: str
    timezone: str
    public_ips: dict[str, str]
    zones: tuple[Zone, ...]
    assets: tuple[Asset, ...]
    users: tuple[User, ...]
    cloud: Cloud
    attackers: tuple[Attacker, ...]
    attacker_pool: tuple[PoolIP, ...]
    source_path: str = field(default="", compare=False)

    # ── Lookups ──────────────────────────────────
    def zone(self, name: str) -> Zone:
        for zone in self.zones:
            if zone.name == name:
                return zone
        raise KeyError(f"Unknown zone '{name}'")

    def asset(self, hostname: str) -> Asset:
        for asset in self.assets:
            if asset.hostname == hostname:
                return asset
        raise KeyError(f"Unknown host '{hostname}'")

    def user(self, username: str) -> User:
        for user in self.users:
            if user.username == username:
                return user
        raise KeyError(f"Unknown user '{username}'")

    def attacker(self, key: str) -> Attacker:
        for attacker in self.attackers:
            if attacker.key == key:
                return attacker
        raise KeyError(f"Unknown attacker '{key}'")

    def fqdn(self, asset: Asset) -> str:
        return f"{asset.hostname}.{self.domain}"

    def user_sid(self, user: User) -> str:
        return f"{self.domain_sid}-{user.rid}"

    def email(self, user: User) -> str:
        return f"{user.username}@{self.domain}"

    def target(self, hostname: str) -> Asset:
        """The asset a scenario may attack; raises for collectors / unmonitored zones."""
        asset = self.asset(hostname)
        if not self.zone(asset.zone).targetable:
            raise ValueError(f"{hostname} is in the '{asset.zone}' zone (collectors), which is never an attack target")
        return asset

    @property
    def manager(self) -> Asset:
        """The Wazuh manager (agent 000) every on-prem alert is reported through."""
        for asset in self.assets:
            if asset.wazuh_agent_id == "000":
                return asset
        raise KeyError("No Wazuh manager (wazuh_agent_id '000') defined")


# ── Loading ──────────────────────────────────────

def _require(record: dict, keys: tuple[str, ...], where: str, problems: list[str]) -> bool:
    missing = [k for k in keys if record.get(k) in (None, "")]
    if missing:
        problems.append(f"{where}: missing {', '.join(repr(k) for k in missing)}")
        return False
    return True


def _tuple(value: Any) -> tuple:
    return tuple(value or ())


def _build(raw: dict, source: str) -> Org:
    problems: list[str] = []
    if not isinstance(raw, dict):
        raise OrgValidationError(source, ["top level must be a mapping"])

    company = raw.get("company") or {}
    _require(company, ("name", "domain", "netbios_domain", "domain_sid", "timezone"), "company", problems)

    zones = []
    for i, z in enumerate(raw.get("zones") or []):
        if _require(z, ("name", "purpose"), f"zones[{i}]", problems):
            zones.append(Zone(z["name"], z.get("vlan"), z.get("subnet"), z["purpose"], bool(z.get("monitored", True))))

    assets = []
    for i, a in enumerate(raw.get("assets") or []):
        where = f"assets[{i}] ({a.get('hostname', '?')})"
        if _require(a, ("hostname", "zone", "ip", "os", "os_version", "role"), where, problems):
            assets.append(Asset(
                hostname=a["hostname"], zone=a["zone"], ip=str(a["ip"]), os=a["os"], os_version=str(a["os_version"]),
                role=a["role"], services=_tuple(a.get("services")), wazuh_agent_id=a.get("wazuh_agent_id"),
                primary_user=a.get("primary_user"), owner=a.get("owner"), public_ip=a.get("public_ip"),
                shares=_tuple(a.get("shares")), databases=_tuple(a.get("databases")),
                web_paths=_tuple(a.get("web_paths")), vpn_pool=a.get("vpn_pool"),
            ))

    users = []
    for i, u in enumerate(raw.get("users") or []):
        where = f"users[{i}] ({u.get('username', '?')})"
        if _require(u, ("username", "display_name", "department", "title", "primary_host", "rid"), where, problems):
            users.append(User(
                username=u["username"], display_name=u["display_name"], department=u["department"], title=u["title"],
                primary_host=u["primary_host"], rid=int(u["rid"]), groups=_tuple(u.get("groups")),
                vpn_access=bool(u.get("vpn_access")), aws_access=bool(u.get("aws_access")),
                service_account=bool(u.get("service_account")),
            ))

    c = raw.get("cloud") or {}
    _require(c, ("provider", "account_id", "region", "guardduty_detector_id"), "cloud", problems)
    account_id = str(c.get("account_id", ""))
    cloud = Cloud(
        provider=c.get("provider", ""), account_id=account_id, region=c.get("region", ""),
        guardduty_detector_id=c.get("guardduty_detector_id", ""),
        s3_buckets=tuple(S3Bucket(b["name"], b.get("sensitivity", ""), b.get("note", "")) for b in c.get("s3_buckets") or []),
        iam_users=tuple(
            IamUser(u["name"], account_id, u.get("access_key_id"), u.get("key_location"), bool(u.get("console_access")))
            for u in c.get("iam_users") or []
        ),
        services=dict(c.get("services") or {}),
    )

    attackers = []
    for key, a in (raw.get("attackers") or {}).items():
        if _require(a or {}, ("role", "ip", "note"), f"attackers.{key}", problems):
            attackers.append(Attacker(
                key=key, role=a["role"], ip=str(a["ip"]), note=a["note"], targets=_tuple(a.get("targets")),
                secondary_ips=tuple(str(ip) for ip in a.get("secondary_ips") or []), label_group=a.get("label_group"),
            ))

    pool = []
    for i, p in enumerate(raw.get("attacker_pool") or []):
        if _require(p, ("ip", "note"), f"attacker_pool[{i}]", problems):
            pool.append(PoolIP(str(p["ip"]), p["note"]))

    if problems:
        raise OrgValidationError(source, problems)

    return Org(
        name=company["name"], domain=company["domain"], netbios_domain=company["netbios_domain"],
        domain_sid=company["domain_sid"], timezone=company["timezone"],
        public_ips={k: str(v) for k, v in (raw.get("public_ips") or {}).items()},
        zones=tuple(zones), assets=tuple(assets), users=tuple(users), cloud=cloud,
        attackers=tuple(attackers), attacker_pool=tuple(pool), source_path=source,
    )


# ── Validation ───────────────────────────────────

def _parse_ip(value: str, where: str, problems: list[str]) -> Optional[ipaddress.IPv4Address]:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        problems.append(f"{where}: '{value}' is not a valid IP address")
        return None


def validate(org: Org) -> None:
    """Raise OrgValidationError listing every consistency problem; return None when the org is sound."""
    problems: list[str] = []
    zones = {z.name: z for z in org.zones}
    if len(zones) != len(org.zones):
        problems.append("zones: duplicate zone names")
    for zone in org.zones:
        if zone.subnet:
            try:
                ipaddress.ip_network(zone.subnet)
            except ValueError:
                problems.append(f"zone '{zone.name}': subnet '{zone.subnet}' is not a valid network")

    # Hostnames and IPs are unique across assets and the company's public addresses.
    seen_hosts: set[str] = set()
    ip_owner: dict[str, str] = {}

    def claim_ip(ip: str, owner: str) -> None:
        if ip in ip_owner:
            problems.append(f"duplicate IP {ip}: used by {ip_owner[ip]} and {owner}")
        else:
            ip_owner[ip] = owner

    for name, ip in org.public_ips.items():
        if _parse_ip(ip, f"public_ips.{name}", problems):
            claim_ip(ip, f"public_ips.{name}")

    for asset in org.assets:
        where = f"asset {asset.hostname}"
        if asset.hostname in seen_hosts:
            problems.append(f"duplicate hostname {asset.hostname}")
        seen_hosts.add(asset.hostname)

        zone = zones.get(asset.zone)
        if zone is None:
            problems.append(f"{where}: unknown zone '{asset.zone}'")
        address = _parse_ip(asset.ip, where, problems)
        if address is not None:
            claim_ip(asset.ip, asset.hostname)
            if zone is not None and zone.network is not None and address not in zone.network:
                problems.append(f"{where}: IP {asset.ip} is outside the {zone.name} subnet {zone.subnet}")
        if asset.public_ip and asset.public_ip not in org.public_ips.values():
            problems.append(f"{where}: public_ip {asset.public_ip} is not listed under public_ips")

    usernames: set[str] = set()
    for user in org.users:
        if user.username in usernames:
            problems.append(f"duplicate username {user.username}")
        usernames.add(user.username)
        if user.primary_host not in seen_hosts:
            problems.append(f"user {user.username}: primary host '{user.primary_host}' does not exist")
    for asset in org.assets:
        for field_name in ("primary_user", "owner"):
            value = getattr(asset, field_name)
            if value and value not in usernames:
                problems.append(f"asset {asset.hostname}: {field_name} '{value}' is not a known user")

    # Attacker and pool IPs must be real public addresses, each used once.
    attacker_ip_owner: dict[str, str] = {}
    entries = [(f"attackers.{a.key}", ip) for a in org.attackers for ip in a.all_ips]
    entries += [(f"attacker_pool[{i}]", p.ip) for i, p in enumerate(org.attacker_pool)]
    for where, ip in entries:
        address = _parse_ip(ip, where, problems)
        if address is None:
            continue
        if not address.is_global:
            problems.append(f"{where}: {ip} is not a public (globally routable) address")
        if ip in attacker_ip_owner:
            problems.append(f"duplicate attacker IP {ip}: {attacker_ip_owner[ip]} and {where}")
        else:
            attacker_ip_owner[ip] = where
        if ip in ip_owner:
            problems.append(f"{where}: {ip} is also a company address ({ip_owner[ip]})")

    # Scenario targets must exist and sit in a targetable (monitored) zone.
    for attacker in org.attackers:
        for hostname in attacker.targets:
            asset = next((a for a in org.assets if a.hostname == hostname), None)
            if asset is None:
                problems.append(f"attackers.{attacker.key}: target '{hostname}' does not exist")
            elif asset.zone in zones and not zones[asset.zone].targetable:
                problems.append(
                    f"attackers.{attacker.key}: target '{hostname}' is in the '{asset.zone}' zone "
                    "(collectors), which is never an attack target"
                )

    if not any(a.wazuh_agent_id == "000" for a in org.assets):
        problems.append("no Wazuh manager: one asset needs wazuh_agent_id '000'")

    if problems:
        raise OrgValidationError(org.source_path or "<org>", problems)


def load_org(path: Optional[Path | str] = None) -> Org:
    """Load and validate a company YAML (default: the bundled EmberBay definition)."""
    path = Path(path) if path else DEFAULT_ORG_PATH
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise OrgValidationError(str(path), ["file not found"]) from None
    except yaml.YAMLError as exc:
        raise OrgValidationError(str(path), [f"YAML syntax error: {exc}"]) from None
    return org_from_dict(raw, str(path))


def org_from_dict(raw: dict, source: str = "<dict>") -> Org:
    """Build and validate an Org from an already-parsed mapping (used by tests to check broken copies)."""
    org = _build(raw, source)
    validate(org)
    return org
