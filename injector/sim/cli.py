"""
SafeSOC — Simulator CLI
`python -m injector.sim <command>` from the repository root:

    org                    summary of the company model + validation result
    org --diagram          Mermaid network diagram (--out FILE to write it)
    samples --out FILE     one sample event per log builder, as JSONL
    samples --send         send those samples to the ingest API
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Optional, Sequence

import requests

from injector.injector import DEFAULT_API_BASE, DEMO_EMAIL, DEMO_PASSWORD, DEMO_TENANT_ID
from injector.sim import engine
from injector.sim.diagram import mermaid
from injector.sim.org import DEFAULT_ORG_PATH, Org, OrgValidationError, load_org
from injector.sim.samples import generate_samples


def _table(rows: list[Sequence[str]], headers: Sequence[str]) -> str:
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows)]
    line = lambda r: "  ".join(str(v).ljust(w) for v, w in zip(r, widths)).rstrip()  # noqa: E731
    return "\n".join([line(headers), line(["-" * w for w in widths]), *(line(r) for r in rows)])


def summary(org: Org) -> str:
    parts = [
        f"{org.name} (fictional) | {org.domain} | {org.netbios_domain} | {org.timezone}",
        "Public IPs: " + ", ".join(f"{k} {v}" for k, v in org.public_ips.items()),
        "",
        "Zones",
        _table([(z.name, z.vlan or "-", z.subnet or "-", "yes" if z.monitored else "no (collectors)", z.purpose)
                for z in org.zones], ("zone", "vlan", "subnet", "monitored", "purpose")),
        "",
        f"Assets ({len(org.assets)})",
        _table([(a.hostname, a.zone, a.ip, a.public_ip or "", f"{a.os} {a.os_version}", a.role,
                 a.wazuh_agent_id or "-", a.primary_user or a.owner or "")
                for a in org.assets], ("host", "zone", "ip", "nat", "os", "role", "agent", "user/owner")),
        "",
        f"Users ({len(org.users)})",
        _table([(u.username, u.display_name, u.department, u.title, u.primary_host,
                 ",".join(x for x, on in (("vpn", u.vpn_access), ("aws", u.aws_access), ("svc", u.service_account)) if on),
                 ", ".join(u.groups)) for u in org.users],
               ("user", "name", "dept", "title", "host", "access", "groups")),
        "",
        f"Cloud: {org.cloud.provider} account {org.cloud.account_id} | {org.cloud.region} | "
        + ", ".join(f"{k} {v}" for k, v in org.cloud.services.items()),
        _table([("s3", b.name, b.sensitivity) for b in org.cloud.s3_buckets]
               + [("iam", u.name, f"key {u.access_key_id} at {u.key_location}" if u.access_key_id else "console")
                  for u in org.cloud.iam_users], ("kind", "name", "detail")),
        "",
        "Attackers (real, publicly reported IPs; reputation can change)",
        _table([(x.key, ", ".join(x.all_ips), x.label_group or "", ", ".join(x.targets) or "(cloud)", x.role)
                for x in org.attackers], ("key", "ip", "group", "targets", "role")),
        "Attacker pool: " + ", ".join(p.ip for p in org.attacker_pool),
    ]
    return "\n".join(parts)


def _common(parser: argparse.ArgumentParser, suppress: bool) -> None:
    default = (lambda v: argparse.SUPPRESS) if suppress else (lambda v: v)
    parser.add_argument("--org", type=Path, default=default(DEFAULT_ORG_PATH), help="company YAML (default: bundled EmberBay)")
    parser.add_argument("--api-base", default=default(DEFAULT_API_BASE), help=f"backend base URL (default: {DEFAULT_API_BASE})")
    parser.add_argument("--tenant-id", default=default(DEMO_TENANT_ID), help="tenant to log in as (default: the demo tenant)")
    parser.add_argument("--email", default=default(DEMO_EMAIL), help="user email (default: the demo user)")
    parser.add_argument("--password", default=default(DEMO_PASSWORD), help="password (default: the demo user's)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m injector.sim", description="SafeSOC network simulator")
    _common(parser, suppress=False)
    # Global flags work before or after the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    _common(common, suppress=True)
    sub = parser.add_subparsers(dest="command", required=True)

    org_p = sub.add_parser("org", parents=[common], help="summarise and validate the company model")
    org_p.add_argument("--diagram", action="store_true", help="print a Mermaid network diagram instead")
    org_p.add_argument("--out", type=Path, help="with --diagram: write it to this file (e.g. docs/simulator-network.mmd)")

    samples_p = sub.add_parser("samples", parents=[common], help="one sample event per log builder")
    samples_p.add_argument("--out", type=Path, help="write the samples as JSONL ({source, payload} per line)")
    samples_p.add_argument("--send", action="store_true", help="send the samples to the ingest API")
    samples_p.add_argument("--run-id", default=None, help="simulation run_id (default: a new random id)")
    samples_p.add_argument("--batch-size", type=int, default=None, help="events per request (default: backend INGEST_BATCH_SIZE)")
    return parser


def _cmd_org(args, org: Org) -> int:
    if args.diagram:
        diagram = mermaid(org)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            with args.out.open("w", encoding="utf-8", newline="\n") as fh:
                fh.write(diagram)
            print(f"Wrote Mermaid diagram to {args.out}")
        else:
            print(diagram, end="")
        return 0
    print(summary(org))
    print(f"\nValidation: OK ({org.source_path})")
    return 0


def _cmd_samples(args, org: Org) -> int:
    if not args.out and not args.send:
        print("samples: pass --out FILE and/or --send", file=sys.stderr)
        return 2
    run_id = args.run_id or f"samples-{uuid.uuid4().hex[:12]}"
    events = generate_samples(org, run_id=run_id)
    if args.out:
        with args.out.open("w", encoding="utf-8", newline="\n") as fh:
            for event in events:
                fh.write(json.dumps({"source": event["source"], "payload": event["payload"]}) + "\n")
        print(f"Wrote {len(events)} sample events to {args.out} (run_id {run_id})")
    if args.send:
        try:
            token = engine.authenticate(args.api_base, args.tenant_id, args.email, args.password)
        except requests.exceptions.ConnectionError:
            print(f"ERROR: could not connect to SafeSOC at {args.api_base}. Is 'docker compose up' running?", file=sys.stderr)
            return 1
        except requests.exceptions.HTTPError as exc:
            print(f"ERROR: login failed ({exc.response.status_code}). Run 'python injector/demo.py' first to "
                  "provision the demo tenant, or pass --tenant-id/--email/--password.", file=sys.stderr)
            return 1
        try:
            results = engine.send_events(((e["source"], e["payload"]) for e in events), api_base=args.api_base,
                                         token=token, batch_size=args.batch_size)
        except requests.exceptions.HTTPError as exc:
            print(f"ERROR: ingest failed ({exc.response.status_code}): {exc.response.text[:300]}", file=sys.stderr)
            return 1
        print(f"Sent run {run_id}:")
        for source, result in results.items():
            print(f"  {source:<15} accepted {result.accepted:>3}  rejected {result.rejected:>3}")
            for error in result.errors:
                print(f"    [{error['index']}] {str(error.get('error'))[:160]}")
        if any(r.rejected for r in results.values()):
            return 1
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        org = load_org(args.org)
    except OrgValidationError as exc:
        print(exc, file=sys.stderr)
        return 1
    if args.command == "org":
        return _cmd_org(args, org)
    return _cmd_samples(args, org)
