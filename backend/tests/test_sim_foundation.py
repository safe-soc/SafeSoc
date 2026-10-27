"""
SafeSOC — Network Simulator Foundation Tests
The simulator's company model must be internally consistent, and every
log builder's output must survive the REAL backend adapter for its
source (app.adapters registry) and validate as a NormalizedLog, exactly
as services/ingestion.py processes it. Imports injector.sim with the
repo root on sys.path, like test_injector_scenarios.py.
"""

import copy
import json
import random
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from injector.sim import engine  # noqa: E402
from injector.sim.diagram import mermaid  # noqa: E402
from injector.sim.formats.wazuh_common import RULES  # noqa: E402
from injector.sim.org import DEFAULT_ORG_PATH, OrgValidationError, load_org, org_from_dict  # noqa: E402
from injector.sim.samples import SOURCES, generate_samples, sample_builders  # noqa: E402

import app.adapters  # noqa: E402,F401  (registers the built-in adapters)
from app.adapters.sdk import registry  # noqa: E402
from app.schemas.log import NormalizedLog  # noqa: E402

TS = datetime(2026, 10, 27, 10, 15, 30, 250000, tzinfo=timezone.utc)
SIMULATION = {"run_id": "test-run", "simulator": "samples", "scenario": None, "step": "x"}


@pytest.fixture(scope="module")
def org():
    return load_org()


@pytest.fixture
def raw_org() -> dict:
    return yaml.safe_load(DEFAULT_ORG_PATH.read_text(encoding="utf-8"))


def _ingest_like(source: str, payload: dict) -> NormalizedLog:
    """What process_ingest_batch does to one log: adapter, tenant_id/source injection, NormalizedLog validation."""
    transform = registry.get(source)
    assert transform is not None, f"no adapter registered for {source}"
    log = transform(copy.deepcopy(payload))
    log["tenant_id"] = str(uuid.uuid4())
    if not log.get("source"):
        log["source"] = source
    return NormalizedLog(**log)


_EVENT_TIME_FIELD = {"wazuh": "timestamp", "aws_cloudtrail": "eventTime", "aws_guardduty": "CreatedAt"}


def _event_time(source: str, payload: dict) -> str:
    return payload[_EVENT_TIME_FIELD[source]]


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# ── Organisation model ───────────────────────────

def test_bundled_org_loads_and_validates(org):
    assert org.name == "EmberBay Financial Services"
    assert org.asset("EB-DC01").ip == "10.10.20.10"
    assert org.user("neha.sharma").primary_host == "EB-FIN-WS07"
    assert org.manager.hostname == "EB-WAZUH01"
    assert org.attacker("ransomware_c2").all_ips == ("216.150.16.129", "216.150.1.193")
    assert [p.ip for p in org.attacker_pool] == ["61.245.11.87", "92.27.101.99", "103.49.238.251", "120.48.154.88"]
    assert org.cloud.iam_user("svc-web-deploy").access_key_id == "AKIAIOSFODNN7EXAMPLE"


def test_attacker_ips_are_exactly_the_reported_ones(org):
    assert {a.key: a.ip for a in org.attackers} == {
        "vpn_bruteforcer": "2.57.121.25",
        "phishing_c2": "140.246.61.93",
        "web_exploiter": "45.148.10.121",
        "vpn_intruder": "101.36.104.242",
        "cloud_key_abuser": "93.174.95.106",
        "ransomware_c2": "216.150.16.129",
    }


def test_org_yaml_records_no_geo_for_attacker_ips(raw_org):
    for attacker in raw_org["attackers"].values():
        assert not {"country", "asn", "org", "isp", "as_owner"} & set(attacker)


def test_security_zone_is_never_a_target(org):
    with pytest.raises(ValueError, match="never an attack target"):
        org.target("EB-WAZUH01")
    assert org.target("EB-WEB01").hostname == "EB-WEB01"


def _asset(raw, hostname):
    return next(a for a in raw["assets"] if a["hostname"] == hostname)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda r: _asset(r, "EB-FS01").update(ip="10.10.20.10"), "duplicate IP 10.10.20.10"),
        (lambda r: _asset(r, "EB-DC01").update(ip="10.10.99.10"), "outside the servers subnet"),
        (lambda r: r["users"][0].update(primary_host="EB-NOPE01"), "primary host 'EB-NOPE01' does not exist"),
        (lambda r: r["attackers"]["vpn_bruteforcer"].update(ip="10.1.2.3"), "not a public"),
        (lambda r: r["attacker_pool"][0].update(ip="45.148.10.121"), "duplicate attacker IP 45.148.10.121"),
        (lambda r: r["attackers"]["ransomware_c2"].update(secondary_ips=["2.57.121.25"]), "duplicate attacker IP 2.57.121.25"),
        (lambda r: r["attackers"]["web_exploiter"].update(targets=["EB-WAZUH01"]), "never an attack target"),
        (lambda r: r["assets"].append(dict(_asset(r, "EB-DB01"), ip="10.10.20.99")), "duplicate hostname EB-DB01"),
        (lambda r: _asset(r, "EB-DB01").pop("ip"), "missing 'ip'"),
    ],
    ids=["duplicate-ip", "ip-outside-subnet", "unknown-primary-host", "private-attacker-ip", "pool-duplicates-attacker",
         "secondary-duplicates-attacker", "targets-security-zone", "duplicate-hostname", "missing-field"],
)
def test_validation_rejects_a_broken_copy(raw_org, mutate, message):
    broken = copy.deepcopy(raw_org)
    mutate(broken)
    with pytest.raises(OrgValidationError) as excinfo:
        org_from_dict(broken)
    assert message in str(excinfo.value)


def test_validation_reports_every_problem_at_once(raw_org):
    broken = copy.deepcopy(raw_org)
    _asset(broken, "EB-DC01")["ip"] = "10.10.99.10"
    broken["users"][0]["primary_host"] = "EB-NOPE01"
    with pytest.raises(OrgValidationError) as excinfo:
        org_from_dict(broken)
    assert len(excinfo.value.problems) == 2


# ── Builders through the real adapters ───────────

def _samples(org):
    return [(name, source, make(TS, SIMULATION)) for name, source, make in sample_builders(org)]


def test_samples_cover_every_builder(org):
    names = {name for name, _, _ in sample_builders(org)}
    expected = {f"{m.__name__.rsplit('.', 1)[-1]}.{fn}" for m in SOURCES for fn in m.__all__}
    assert names == expected


def test_every_builder_output_validates_through_its_adapter(org):
    for name, source, payload in _samples(org):
        normalized = _ingest_like(source, payload)

        assert normalized.source.value == source, name
        assert json.loads(normalized.raw_log) == payload, name
        assert normalized.timestamp == _parse(_event_time(source, payload)), name

        if source == "wazuh":
            assert normalized.host_id == payload["agent"]["name"], name
            assert normalized.host_ip == payload["agent"]["ip"], name
            assert normalized.rule_id == payload["rule"]["id"], name
            assert normalized.source_ip == payload.get("data", {}).get("srcip"), name
        elif source == "aws_cloudtrail":
            assert normalized.host_id == org.cloud.account_id, name
            assert normalized.source_ip == payload["sourceIPAddress"], name
            assert normalized.action == payload["eventName"], name
        else:
            assert normalized.host_id == org.cloud.account_id, name
            assert normalized.rule_id == payload["Id"], name
            assert normalized.user == payload["Resource"]["AccessKeyDetails"]["UserName"], name


def test_wazuh_samples_map_hosts_and_source_ips(org):
    by_name = {name: payload for name, _, payload in _samples(org)}
    ssh = _ingest_like("wazuh", by_name["linux.ssh_failed_password"])
    assert (ssh.host_id, ssh.host_ip, ssh.source_ip, ssh.user) == ("EB-WEB01", "10.10.30.10", "45.148.10.121", "svc-webapp")
    assert ssh.log_type.value == "authentication" and ssh.severity.value == "medium"
    fw = _ingest_like("wazuh", by_name["firewall.filterlog"])
    assert (fw.host_id, fw.source_ip, fw.destination_ip, fw.destination_port) == ("EB-FW01", "2.57.121.25", "203.0.113.10", 3389)
    domain_admins = _ingest_like("wazuh", by_name["windows.member_added_global_group"])
    assert domain_admins.rule_id == "60159" and domain_admins.severity.value == "critical"


def test_builders_are_deterministic(org):
    first = _samples(org)
    second = _samples(org)
    assert first == second
    seeded = [make(TS, None) for _, _, make in sample_builders(org)]
    assert seeded == [make(TS, None) for _, _, make in sample_builders(org)]


def test_rng_is_used_for_ids_when_passed(org):
    from injector.sim.formats import linux

    web01 = org.asset("EB-WEB01")
    a = linux.ssh_invalid_user(org, web01, TS, username="admin", src_ip="45.148.10.121", rng=random.Random(7))
    b = linux.ssh_invalid_user(org, web01, TS, username="admin", src_ip="45.148.10.121", rng=random.Random(7))
    c = linux.ssh_invalid_user(org, web01, TS, username="admin", src_ip="45.148.10.121", rng=random.Random(8))
    assert a == b
    assert a["id"] != c["id"]


def test_timestamps_are_utc_with_z(org):
    for name, source, payload in _samples(org):
        if source == "wazuh":
            stamps = [payload["timestamp"]]
            win = payload.get("data", {}).get("win")
            if win:
                stamps.append(win["system"]["systemTime"])
        elif source == "aws_cloudtrail":
            stamps = [payload["eventTime"]]
        else:
            service = payload["Service"]
            stamps = [payload["CreatedAt"], payload["UpdatedAt"], service["EventFirstSeen"], service["EventLastSeen"]]
        for stamp in stamps:
            assert stamp.endswith("Z"), (name, stamp)
            assert _parse(stamp).replace(microsecond=0) == TS.replace(microsecond=0), (name, stamp)


def test_simulation_block_present_only_when_passed(org):
    for name, _, make in sample_builders(org):
        assert make(TS, SIMULATION)["simulation"] == SIMULATION, name
        assert "simulation" not in make(TS, None), name


def test_syslog_lines_use_company_local_time_with_hostname_and_pid(org):
    by_name = {name: payload for name, _, payload in _samples(org)}
    line = by_name["linux.ssh_failed_password"]["full_log"]
    # 10:15:30 UTC is 15:45:30 in Asia/Kolkata.
    assert line.startswith("Oct 27 15:45:30 EB-WEB01 sshd[")
    assert line.endswith("Failed password for svc-webapp from 45.148.10.121 port 44512 ssh2")


def test_rule_catalogue_ids_are_unique_and_custom_ids_in_local_range():
    ids = [rule.id for rule in RULES.values()]
    assert len(ids) == len(set(ids))
    for rule in RULES.values():
        if rule.custom:
            assert 100000 <= rule.id <= 100999, rule
        else:
            assert rule.stock_file and rule.stock_file.endswith(".xml") and rule.id < 100000, rule


def test_generate_samples_labels_each_step(org):
    events = generate_samples(org, run_id="r1", start=TS)
    assert len(events) == len(sample_builders(org))
    assert {e["payload"]["simulation"]["run_id"] for e in events} == {"r1"}
    assert all(e["payload"]["simulation"]["step"] == e["builder"] for e in events)


# ── Diagram ──────────────────────────────────────

def test_mermaid_names_every_host_and_subnet(org):
    diagram = mermaid(org)
    assert diagram.startswith("flowchart TB")
    for asset in org.assets:
        assert asset.hostname in diagram and asset.ip in diagram
    for zone in org.zones:
        if zone.subnet:
            assert zone.subnet in diagram
    assert "collectors" in diagram


# ── Engine ───────────────────────────────────────

class _FakeResponse:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self._body


class _FakeSession:
    def __init__(self):
        self.posts = []

    def post(self, url, json=None, headers=None, timeout=None):
        self.posts.append((url, json, headers))
        n = len(json["logs"])
        errors = [{"index": 0, "error": "bad"}] if json["source"] == "wazuh" and len(self.posts) == 2 else None
        return _FakeResponse({"accepted": n - (1 if errors else 0), "rejected": 1 if errors else 0,
                              "alert_ids": [f"a{i}" for i in range(n)], "errors": errors})


def test_engine_groups_by_source_and_batches():
    events = [("wazuh", {"n": i}) for i in range(5)] + [("aws_cloudtrail", {"n": 0})] + [("wazuh", {"n": 5})]
    session = _FakeSession()

    results = engine.send_events(events, api_base="http://x", token="t", batch_size=4, session=session)

    assert [(p[1]["source"], len(p[1]["logs"])) for p in session.posts] == [("wazuh", 4), ("wazuh", 2), ("aws_cloudtrail", 1)]
    assert session.posts[1][1]["logs"] == [{"n": 4}, {"n": 5}]
    assert session.posts[0][0] == "http://x/api/v1/ingest" and session.posts[0][2] == {"Authorization": "Bearer t"}
    assert (results["wazuh"].accepted, results["wazuh"].rejected) == (5, 1)
    assert results["wazuh"].errors[0]["index"] == 4  # index within the source's whole list, not the batch
    assert results["aws_cloudtrail"].accepted == 1


def test_engine_reads_backend_batch_size(tmp_path):
    config = tmp_path / "config.py"
    config.write_text("    INGEST_BATCH_SIZE: int = 250\n", encoding="utf-8")
    assert engine.backend_batch_size(config) == 250
    assert engine.backend_batch_size(tmp_path / "missing.py") == engine.FALLBACK_BATCH_SIZE
