"""
SafeSOC — Simulator Format Samples
One sample event from every log builder, on a host where that event
would really occur. Used by `python -m injector.sim samples` and by
the tests, which check each one against its real backend adapter.
"""

from __future__ import annotations

import hashlib
import sys
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from injector.sim.formats import cloudtrail, database, firewall, guardduty, linux, mail, vpn, web, windows
from injector.sim.org import Org

# Ingest `source` for each builder module.
SOURCES = {
    windows: "wazuh", linux: "wazuh", web: "wazuh", vpn: "wazuh", firewall: "wazuh", mail: "wazuh",
    database: "wazuh", cloudtrail: "aws_cloudtrail", guardduty: "aws_guardduty",
}

# A benign remote address (RFC 5737 TEST-NET-2) for staff working from home.
HOME_IP = "198.51.100.23"


def _hashes(image: str) -> str:
    """A well-formed but synthetic Sysmon hashes string, derived from the image path (not a real file's hashes)."""
    seed = image.lower().encode()
    return ",".join([
        f"SHA1={hashlib.sha1(seed).hexdigest().upper()}",
        f"MD5={hashlib.md5(seed).hexdigest().upper()}",
        f"SHA256={hashlib.sha256(seed).hexdigest().upper()}",
        f"IMPHASH={hashlib.md5(seed[::-1]).hexdigest().upper()}",
    ])


def sample_builders(org: Org) -> list[tuple[str, str, Callable[[datetime, Optional[dict]], dict]]]:
    """[(builder name 'module.function', ingest source, make(ts, simulation) -> payload), ...]."""
    a, u, c = org.asset, org.user, org.cloud
    ws, neha, dc, rahul = a("EB-FIN-WS07"), u("neha.sharma"), a("EB-DC01"), u("adm.rahul")
    dev, karthik, fw = a("EB-DEV-LX01"), u("karthik.reddy"), a("EB-FW01")
    web01, vpn01, mail01, db01 = a("EB-WEB01"), a("EB-VPN01"), a("EB-MAIL01"), a("EB-DB01")
    attackers = {x.key: x.ip for x in org.attackers}
    key_user = c.iam_user("svc-web-deploy")
    word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
    queue = mail.queue_id("sample-invoice")

    samples: list[tuple[object, Callable]] = [
        # Windows Security
        (windows.logon_success, lambda ts, s: windows.logon_success(org, ws, neha, ts, logon_type=2, simulation=s)),
        (windows.logon_failure, lambda ts, s: windows.logon_failure(
            org, a("EB-FS01"), ts, target_user_name="administrator", sub_status="0xc000006a",
            ip_address="10.8.0.14", ip_port="52113", workstation_name="KALI", simulation=s)),
        (windows.special_privileges, lambda ts, s: windows.special_privileges(org, dc, rahul, ts, simulation=s)),
        (windows.process_created, lambda ts, s: windows.process_created(
            org, ws, neha, ts, new_process_name=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -NoProfile -Command Get-Date", parent_process_name=r"C:\Windows\explorer.exe",
            simulation=s)),
        (windows.user_created, lambda ts, s: windows.user_created(
            org, dc, rahul, ts, new_user_name="intern.tmp", new_user_rid=1130, simulation=s)),
        (windows.member_added_global_group, lambda ts, s: windows.member_added_global_group(
            org, dc, rahul, ts, member_name="Sneha Kulkarni", member_sid=org.user_sid(u("sneha.kulkarni")),
            group="Domain Admins", simulation=s)),
        (windows.member_added_local_group, lambda ts, s: windows.member_added_local_group(
            org, ws, rahul, ts, member_name="Neha Sharma", member_sid=org.user_sid(neha), group="Administrators",
            simulation=s)),
        (windows.audit_log_cleared, lambda ts, s: windows.audit_log_cleared(org, a("EB-FS01"), rahul, ts, simulation=s)),
        (windows.usb_device_recognized, lambda ts, s: windows.usb_device_recognized(org, ws, ts, simulation=s)),
        # Sysmon
        (windows.sysmon_process_create, lambda ts, s: windows.sysmon_process_create(
            org, ws, neha, ts, image=word, command_line=f'"{word}" /n "C:\\Users\\neha.sharma\\Documents\\Budget.docx"',
            parent_image=r"C:\Windows\explorer.exe", parent_command_line=r"C:\Windows\Explorer.EXE",
            hashes=_hashes(word), simulation=s)),
        (windows.sysmon_network_connect, lambda ts, s: windows.sysmon_network_connect(
            org, ws, neha, ts, image=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            destination_ip="10.10.30.10", destination_port=443, destination_port_name="https", simulation=s)),
        (windows.sysmon_file_create, lambda ts, s: windows.sysmon_file_create(
            org, ws, neha, ts, image=word, target_filename=r"C:\Users\neha.sharma\Documents\Budget-Q3.docx",
            simulation=s)),
        (windows.sysmon_file_delete, lambda ts, s: windows.sysmon_file_delete(
            org, ws, neha, ts, image=r"C:\Windows\explorer.exe",
            target_filename=r"C:\Users\neha.sharma\Downloads\old-notes.txt",
            hashes=_hashes("old-notes.txt"), simulation=s)),
        # Linux
        (linux.ssh_failed_password, lambda ts, s: linux.ssh_failed_password(
            org, web01, ts, username="svc-webapp", src_ip=attackers["web_exploiter"], src_port=44512, simulation=s)),
        (linux.ssh_invalid_user, lambda ts, s: linux.ssh_invalid_user(
            org, web01, ts, username="admin", src_ip=attackers["web_exploiter"], src_port=44530, simulation=s)),
        (linux.ssh_accepted_password, lambda ts, s: linux.ssh_accepted_password(
            org, dev, karthik, ts, src_ip="10.8.0.6", src_port=51544, simulation=s)),
        (linux.sudo_command, lambda ts, s: linux.sudo_command(
            org, dev, karthik, ts, command="/usr/bin/apt-get update", simulation=s)),
        # Web
        (web.access_log, lambda ts, s: web.access_log(
            org, web01, ts, src_ip=attackers["web_exploiter"], url="/login?user=admin%27%20OR%201%3D1--",
            status=403, body_bytes=153, attack="sql_injection", user_agent="sqlmap/1.8.4#stable (https://sqlmap.org)",
            simulation=s)),
        # VPN
        (vpn.auth_failed, lambda ts, s: vpn.auth_failed(
            org, vpn01, ts, src_ip=attackers["vpn_bruteforcer"], src_port=40211, simulation=s)),
        (vpn.peer_connection_initiated, lambda ts, s: vpn.peer_connection_initiated(
            org, vpn01, neha, ts, src_ip=HOME_IP, src_port=50122, simulation=s)),
        (vpn.client_address_assigned, lambda ts, s: vpn.client_address_assigned(
            org, vpn01, neha, ts, src_ip=HOME_IP, src_port=50122, virtual_ip="10.8.0.6", simulation=s)),
        (vpn.client_disconnected, lambda ts, s: vpn.client_disconnected(
            org, vpn01, neha, ts, src_ip=HOME_IP, src_port=50122, simulation=s)),
        # Firewall / IDS
        (firewall.filterlog, lambda ts, s: firewall.filterlog(
            org, fw, ts, action="block", src_ip=attackers["vpn_bruteforcer"], dst_ip=org.public_ips["edge_wan"],
            proto="tcp", src_port=51234, dst_port=3389, simulation=s)),
        (firewall.suricata_alert, lambda ts, s: firewall.suricata_alert(
            org, fw, ts, src_ip=attackers["web_exploiter"], src_port=44512, dest_ip=web01.ip, dest_port=80,
            signature="ET SCAN Sqlmap SQL Injection Scan", signature_id=2008538, rev=8,
            category="Attempted Information Leak", severity=2, app_proto="http", simulation=s)),
        # Mail
        (mail.attachment_warning, lambda ts, s: mail.attachment_warning(
            org, mail01, ts, client_ip=attackers["phishing_c2"], client_helo="mail.invoice-portal.example",
            sender="billing@invoice-portal.example", recipient=org.email(neha), attachment_name="Invoice_4471.docm",
            mime_type="application/vnd.ms-word.document.macroEnabled.12", queue=queue, simulation=s)),
        (mail.content_filter_verdict, lambda ts, s: mail.content_filter_verdict(
            org, mail01, ts, client_ip=attackers["phishing_c2"], client_port=41234,
            sender="billing@invoice-portal.example", recipient=org.email(neha), subject="Overdue invoice 4471",
            verdict="CLEAN", queue=queue, message_id="20261027.4471@invoice-portal.example", size=48213, hits=1.2,
            simulation=s)),
        # Database
        (database.connection_authorized, lambda ts, s: database.connection_authorized(
            org, db01, ts, client_ip=web01.ip, db_user="svc-sql", database="finance_core",
            application_name="portal", simulation=s)),
        (database.password_authentication_failed, lambda ts, s: database.password_authentication_failed(
            org, db01, ts, client_ip="10.10.10.41", db_user="postgres", database="finance_core", simulation=s)),
        (database.copy_to_stdout, lambda ts, s: database.copy_to_stdout(
            org, db01, ts, client_ip=web01.ip, db_user="svc-sql", database="finance_core",
            table="public.customer_accounts", simulation=s)),
        # AWS
        (cloudtrail.get_caller_identity, lambda ts, s: cloudtrail.get_caller_identity(
            org, key_user, ts, source_ip=org.public_ips["web01_nat"], simulation=s)),
        (cloudtrail.list_buckets, lambda ts, s: cloudtrail.list_buckets(
            org, key_user, ts, source_ip=org.public_ips["web01_nat"], simulation=s)),
        (cloudtrail.get_object, lambda ts, s: cloudtrail.get_object(
            org, key_user, ts, source_ip=org.public_ips["web01_nat"], bucket="eb-web-assets", key="css/portal.css",
            bytes_transferred_out=18342, simulation=s)),
        (cloudtrail.console_login, lambda ts, s: cloudtrail.console_login(
            org, c.iam_user("adm.rahul"), ts, source_ip=org.public_ips["edge_wan"], mfa_used=True, simulation=s)),
        (guardduty.finding, lambda ts, s: guardduty.finding(
            org, ts, finding_type="Recon:IAMUser/MaliciousIPCaller", title="Reconnaissance API GetCallerIdentity "
            "was invoked from a known malicious IP address.", description="Sample finding.", severity=5.0,
            access_key_id=key_user.access_key_id, principal_id=key_user.principal_id, user_name=key_user.name,
            user_type="IAMUser", api="GetCallerIdentity", service_name="sts.amazonaws.com",
            remote_ip=guardduty.remote_ip_details(attackers["cloud_key_abuser"]), simulation=s)),
        (guardduty.instance_credential_exfiltration_outside_aws, lambda ts, s: (
            guardduty.instance_credential_exfiltration_outside_aws(
                org, ts, role_name="example-instance-role", access_key_id="ASIAIOSFODNN7EXAMPLE", principal_id="AROAEXAMPLEROLEID12345:i-0abc123def4567890",
                user_name="i-0abc123def4567890", remote_ip=guardduty.remote_ip_details(attackers["cloud_key_abuser"]),
                simulation=s))),
    ]
    out = []
    for builder, make in samples:
        module = sys.modules[builder.__module__]
        out.append((f"{module.__name__.rsplit('.', 1)[-1]}.{builder.__name__}", SOURCES[module], make))
    return out


def generate_samples(org: Org, *, run_id: str, start: Optional[datetime] = None) -> list[dict]:
    """[{"source", "builder", "payload"}, ...]: one event per builder, a second apart, starting at `start` (UTC)."""
    start = start or datetime.now(timezone.utc).replace(microsecond=0)
    events = []
    for i, (name, source, make) in enumerate(sample_builders(org)):
        simulation = {"run_id": run_id, "simulator": "samples", "scenario": None, "step": name}
        events.append({"source": source, "builder": name, "payload": make(start + timedelta(seconds=i), simulation)})
    return events
