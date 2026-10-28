# SafeSOC — Network Simulator

A simulated company network for SafeSOC: a fictional organisation, **EmberBay Financial Services**, and a library of builders that produce the logs its systems would really emit, each in the source's native format (Wazuh alert JSON, CloudTrail records, GuardDuty findings). The output goes through `POST /api/v1/ingest` and the real backend adapters, exactly like data from a real deployment.

Status legend: **Implemented** (working code in this repo) · **Partial** (works, with a stated gap) · **Planned** (designed, no code yet).

| Part | Status | Where |
|---|---|---|
| Company model + validation | **Implemented** | `injector/sim/org/emberbay.yaml`, `injector/sim/org.py` |
| Source-native log builders | **Implemented** | `injector/sim/formats/` (Windows/Sysmon, Linux, nginx, OpenVPN, pfSense/Suricata, mail, PostgreSQL, CloudTrail, GuardDuty) |
| Ingest engine (login, per-source batching) | **Implemented** | `injector/sim/engine.py` |
| CLI (`org`, `org --diagram`, `samples`) | **Implemented** | `injector/sim/cli.py`, `python -m injector.sim` |
| Generated network diagram | **Implemented** | `docs/simulator-network.mmd` (embedded below) |
| Adapter field mapping for these sources | **Implemented** | `backend/app/adapters/mapping.py` maps every builder's output to a canonical `EventAction` (`failed_login`, `login_success`, `outbound_connection`, …) plus Windows `eventdata` users/IPs, Sysmon process/file/hash fields, Suricata `src_ip`/`dest_ip`, CloudTrail ConsoleLogin results and GuardDuty's `AwsApiCallAction` remote IP. It lives in the backend, so real Wazuh data gets it too (see `docs/decisions.md` ADR-012). Expected output per builder: `backend/tests/test_adapter_mapping.py`. One sample keeps the fallback on purpose: OpenVPN rule 100401 (address assigned) has no canonical action, so its action is the decoder name `openvpn`. |
| Attack scenarios, default / random / story simulators | **Planned** | Not built yet (see [Planned](#planned)) |

!!! note "Honesty note"
    The company, its hosts, users, addresses, AWS account and every event are **100% synthetic**. Company public addresses use the RFC 5737 documentation range (203.0.113.0/24); the AWS access key is AWS's own documentation example (`AKIAIOSFODNN7EXAMPLE`). The only real data is the **attacker IPs**. They are real addresses that were publicly reported on AbuseIPDB as of 2026-10-27. Their reputation can change, and the simulator never records a country, ASN or owner for them: that comes from live threat intel when SafeSOC enriches the alerts. SafeSOC only looks up globally routable IPs, so the company's documentation-range and private addresses are never sent to VirusTotal/AbuseIPDB and show as "not enriched".

## Architecture

```
injector/sim/
  __init__.py, __main__.py   python -m injector.sim ...   (run from the repo root)
  org/emberbay.yaml          company definition (data only)
  org.py                     YAML -> dataclasses (Org, Zone, Asset, User, Cloud, Attacker) + validation
  formats/
    wazuh_common.py          Wazuh 4.x alert envelope + the rule catalogue (stock vs custom)
    windows.py linux.py web.py vpn.py firewall.py mail.py database.py   -> source "wazuh"
    cloudtrail.py            -> source "aws_cloudtrail"
    guardduty.py             -> source "aws_guardduty"
  samples.py                 one sample per builder (CLI `samples`, and the tests)
  diagram.py                 Mermaid flowchart generated from the YAML
  engine.py                  login (injector.injector.login), group by source, batch, POST /api/v1/ingest
  cli.py                     argparse subcommands
```

Builders are pure functions: `(org, host/user objects, timestamp: datetime in UTC, **fields) -> dict`. They use no randomness. IDs, PIDs and ports come from a stable hash of the inputs, or from a `random.Random` when the caller passes `rng=`. So the same inputs always give the same payload. Every builder accepts `simulation={"run_id", "simulator", "scenario", "step"}` and adds it as a top-level `simulation` block. Without it the block is omitted. All emitted timestamps are ISO-8601 UTC with a trailing `Z`. Lines that are syslog text in reality (`full_log`) keep the host's local time (Asia/Kolkata), as the real files would.

The engine posts `{"source": <source>, "logs": [...]}` per source, in batches no larger than the backend's `INGEST_BATCH_SIZE`. It reads that default from `backend/app/core/config.py` and falls back to 100 when the file isn't available. It reports accepted/rejected per source.

## The company

EmberBay Financial Services (fictional) · `emberbay.local` (NetBIOS `EMBERBAY`) · timezone Asia/Kolkata.
Public IPs: edge WAN `203.0.113.10`; EB-WEB01 NAT `203.0.113.20`; EB-VPN01 NAT `203.0.113.21`.

### Zones

| Zone | VLAN | Subnet | Purpose | Monitored |
|---|---|---|---|---|
| edge | — | — | pfSense EB-FW01 (firewall + Suricata IDS + NAT) | yes |
| users | 10 | 10.10.10.0/24 | Staff workstations and developer machines | yes |
| servers | 20 | 10.10.20.0/24 | AD, file shares, database | yes |
| dmz | 30 | 10.10.30.0/24 | Web portal, VPN, mail | yes |
| security | 40 | 10.10.40.0/24 | Collectors; **never an attack target** | no |

### Assets

| Host | Zone | IP | OS | Role | Wazuh agent | User / owner |
|---|---|---|---|---|---|---|
| EB-FW01 | edge | 10.10.40.1 (LAN) | pfSense 2.7 | firewall/ids (filterlog, Suricata, NAT) | 007 | — |
| EB-FIN-WS05 / 06 / 07 | users | 10.10.10.21 / .22 / .23 | Windows 11 23H2 | workstation | 010 / 011 / 012 | arjun.mehta / priya.nair / neha.sharma |
| EB-HR-WS01 / 02 | users | 10.10.10.24 / .25 | Windows 11 23H2 | workstation | 013 / 014 | kavya.rao / rohan.das |
| EB-IT-WS01 / 02 | users | 10.10.10.26 / .27 | Windows 11 23H2 | workstation | 015 / 016 | adm.rahul / sneha.kulkarni |
| EB-SAL-WS01 / 02 | users | 10.10.10.28 / .29 | Windows 11 23H2 | workstation | 017 / 018 | vikram.singh / ananya.iyer |
| EB-DEV-LX01 / 02 | users | 10.10.10.41 / .42 | Ubuntu 22.04 | developer workstation | 020 / 021 | karthik.reddy / meera.joshi |
| EB-DC01 | servers | 10.10.20.10 | Windows Server 2022 | AD DS + DNS | 001 | adm.rahul |
| EB-FS01 | servers | 10.10.20.20 | Windows Server 2022 | file server (`\\EB-FS01\Finance`, `\HR`, `\Shared`) | 002 | adm.rahul |
| EB-DB01 | servers | 10.10.20.30 | Ubuntu 22.04 | PostgreSQL 15 (`finance_core`) | 003 | adm.rahul |
| EB-WEB01 | dmz | 10.10.30.10 (NAT .20) | Ubuntu 22.04 | nginx 1.24 + customer portal (`/`, `/login`, `/admin`, `/api/*`, `/uploads/`) | 004 | karthik.reddy |
| EB-VPN01 | dmz | 10.10.30.20 (NAT .21) | Ubuntu 22.04 | OpenVPN 2.6 udp/1194, pool 10.8.0.0/24 | 005 | adm.rahul |
| EB-MAIL01 | dmz | 10.10.30.30 | Ubuntu 22.04 | Postfix + content filter | 006 | adm.rahul |
| EB-WAZUH01 | security | 10.10.40.10 | Ubuntu 22.04 | Wazuh manager 4.x | 000 | — |

EB-FW01 is modelled with a Wazuh agent (FreeBSD package) reading `filter.log` and `eve.json`, so its alerts carry `agent.name = EB-FW01`.

### Users

| User | Name | Department | Title | Primary host | VPN | AWS | Groups |
|---|---|---|---|---|---|---|---|
| neha.sharma | Neha Sharma | Finance | Senior Accountant | EB-FIN-WS07 | ✓ | | Finance, VPN-Users |
| arjun.mehta | Arjun Mehta | Finance | Accounts Payable Analyst | EB-FIN-WS05 | | | Finance |
| priya.nair | Priya Nair | Finance | Financial Analyst | EB-FIN-WS06 | | | Finance |
| kavya.rao | Kavya Rao | HR | HR Manager | EB-HR-WS01 | | | HR |
| rohan.das | Rohan Das | HR | HR Executive | EB-HR-WS02 | | | HR |
| vikram.singh | Vikram Singh | Sales | Regional Sales Manager | EB-SAL-WS01 | ✓ | | Sales, VPN-Users |
| ananya.iyer | Ananya Iyer | Sales | Account Executive | EB-SAL-WS02 | ✓ | | Sales, VPN-Users |
| adm.rahul | Rahul Menon (admin) | IT | IT Systems Administrator | EB-IT-WS01 | ✓ | ✓ (console) | **Domain Admins**, IT, VPN-Users |
| sneha.kulkarni | Sneha Kulkarni | IT | IT Helpdesk Technician | EB-IT-WS02 | | | IT, IT Helpdesk |
| karthik.reddy | Karthik Reddy | Engineering | Senior Software Engineer | EB-DEV-LX01 | ✓ | ✓ (console) | Developers, VPN-Users |
| meera.joshi | Meera Joshi | Engineering | Software Engineer | EB-DEV-LX02 | | | Developers |
| svc-backup | (service) | IT | Service account | EB-FS01 | | | Backup Operators |
| svc-webapp | (service) | Engineering | Portal app user | EB-WEB01 | | | — |
| svc-sql | (service) | Finance | Finance DB service | EB-DB01 | | | — |

Every user is also in Domain Users. User SIDs are `<domain_sid>-<rid>` (the fictional domain SID and RIDs are in the YAML).

### Cloud

AWS account `111122223333`, region `ap-south-1`; CloudTrail on in all regions; GuardDuty enabled.

| Kind | Name | Detail |
|---|---|---|
| S3 | eb-finance-backups | sensitive (finance_core and file-share backups) |
| S3 | eb-web-assets | public read (portal static assets) |
| IAM user | svc-web-deploy | access key `AKIAIOSFODNN7EXAMPLE`, stored on EB-WEB01 at `/var/www/portal/.env` |
| IAM user | karthik.reddy | console |
| IAM user | adm.rahul | console |

### Attackers

Real, publicly reported IPs. Each carries the note *"publicly reported on AbuseIPDB as of 2026-10-27; reputation can change"*.

| Key | IP | Role | Planned targets |
|---|---|---|---|
| vpn_bruteforcer | 2.57.121.25 | Brute force / spraying against the VPN | EB-VPN01 |
| phishing_c2 | 140.246.61.93 | Phishing sender + C2 for the payload | EB-MAIL01, EB-FIN-WS07 |
| web_exploiter | 45.148.10.121 | Scans and exploits the portal | EB-WEB01 |
| vpn_intruder | 101.36.104.242 | VPN login with stolen credentials | EB-VPN01, EB-FS01, EB-DC01 |
| cloud_key_abuser | 93.174.95.106 | Uses the leaked svc-web-deploy key | (AWS) |
| ransomware_c2 | 216.150.16.129 (+ 216.150.1.193) | Ransomware infrastructure, group label "Akira (reported)" | EB-FS01, EB-DC01, EB-FIN-WS07 |

Spare pool for the random simulator: 61.245.11.87, 92.27.101.99, 103.49.238.251, 120.48.154.88.

### Validation

`org.py` rejects the YAML with a message listing **every** problem found:

- duplicate hostnames or IPs (including the company's public IPs);
- an asset IP outside its zone's subnet (the edge zone has no subnet);
- a user's primary host, or an asset's primary user/owner, that doesn't exist;
- an attacker or pool IP that isn't a valid, globally routable address, or that appears twice;
- an attacker target in an unmonitored zone (security: collectors are never targets). `Org.target(host)` enforces the same rule for scenario code.

### Network diagram

Generated by `python -m injector.sim org --diagram --out docs/simulator-network.mmd`:

```mermaid
flowchart TB
    %% Generated by `python -m injector.sim org --diagram` from EmberBay Financial Services (fictional).
    internet(("Internet<br/>WAN 203.0.113.10"))
    EB_FW01["EB-FW01<br/>pfSense 2.7 | firewall/ids<br/>LAN 10.10.40.1"]
    internet --> EB_FW01
    core{{"Core switch<br/>VLAN trunk"}}
    EB_FW01 --> core
    subgraph zone_users["users | VLAN 10 | 10.10.10.0/24"]
        EB_FIN_WS05["EB-FIN-WS05<br/>10.10.10.21<br/>workstation"]
        EB_FIN_WS06["EB-FIN-WS06<br/>10.10.10.22<br/>workstation"]
        EB_FIN_WS07["EB-FIN-WS07<br/>10.10.10.23<br/>workstation"]
        EB_HR_WS01["EB-HR-WS01<br/>10.10.10.24<br/>workstation"]
        EB_HR_WS02["EB-HR-WS02<br/>10.10.10.25<br/>workstation"]
        EB_IT_WS01["EB-IT-WS01<br/>10.10.10.26<br/>workstation"]
        EB_IT_WS02["EB-IT-WS02<br/>10.10.10.27<br/>workstation"]
        EB_SAL_WS01["EB-SAL-WS01<br/>10.10.10.28<br/>workstation"]
        EB_SAL_WS02["EB-SAL-WS02<br/>10.10.10.29<br/>workstation"]
        EB_DEV_LX01["EB-DEV-LX01<br/>10.10.10.41<br/>developer workstation"]
        EB_DEV_LX02["EB-DEV-LX02<br/>10.10.10.42<br/>developer workstation"]
    end
    core --- zone_users
    subgraph zone_servers["servers | VLAN 20 | 10.10.20.0/24"]
        EB_DC01["EB-DC01<br/>10.10.20.10<br/>domain controller"]
        EB_FS01["EB-FS01<br/>10.10.20.20<br/>file server"]
        EB_DB01["EB-DB01<br/>10.10.20.30<br/>database server"]
    end
    core --- zone_servers
    subgraph zone_dmz["dmz | VLAN 30 | 10.10.30.0/24"]
        EB_WEB01["EB-WEB01<br/>10.10.30.10<br/>customer portal web server<br/>NAT 203.0.113.20"]
        EB_VPN01["EB-VPN01<br/>10.10.30.20<br/>remote-access VPN<br/>NAT 203.0.113.21"]
        EB_MAIL01["EB-MAIL01<br/>10.10.30.30<br/>mail gateway"]
    end
    core --- zone_dmz
    subgraph zone_security["security | VLAN 40 | 10.10.40.0/24 | collectors"]
        EB_WAZUH01["EB-WAZUH01<br/>10.10.40.10<br/>Wazuh manager 4.x"]
    end
    core --- zone_security
    subgraph cloud["AWS account 111122223333 | ap-south-1"]
        s3_eb_finance_backups["S3 eb-finance-backups<br/>sensitive"]
        s3_eb_web_assets["S3 eb-web-assets<br/>public-read"]
        iam_svc_web_deploy["IAM svc-web-deploy"]
        iam_karthik_reddy["IAM karthik.reddy"]
        iam_adm_rahul["IAM adm.rahul"]
        aws_services["cloudtrail: all regions, guardduty: enabled"]
    end
    internet -.-> cloud
```

## Log formats

All on-prem sources are **Wazuh 4.x alerts** as the manager writes them to `alerts.json`: `timestamp`, `rule{id, level, description, groups, mitre{id, tactic, technique}, firedtimes}`, `agent{id, name, ip}`, `manager{name: EB-WAZUH01}`, `id`, `decoder`, `location`, `full_log` (when the source is a text line), `predecoder` (syslog sources) and `data{...}` as Wazuh's decoder extracts it (values are strings, as in real alerts). Examples below were produced by the builders at 2026-10-27 10:15:30 UTC and trimmed (`…`).

### Windows Security + Sysmon (`windows.py`)

Decoder `windows_eventchannel`, location `EventChannel`, `data.win.system` + `data.win.eventdata` with Windows' real field names. Builders: `logon_success` (4624; type 2/3/10), `logon_failure` (4625; subStatus `0xc000006a` bad password, `0xc0000064` no such user, `0xc0000234` locked out), `special_privileges` (4672), `process_created` (4688), `user_created` (4720), `member_added_global_group` (4728), `member_added_local_group` (4732), `audit_log_cleared` (1102; subject under `data.win.logFileCleared`), `usb_device_recognized` (6416). Sysmon: `sysmon_process_create` (1), `sysmon_network_connect` (3), `sysmon_file_create` (11), `sysmon_file_delete` (23).

```json
{
  "timestamp": "2026-10-27T10:15:30.000Z",
  "rule": {"level": 5, "description": "Logon Failure - Unknown user or bad password", "id": "60122",
           "groups": ["windows", "windows_security", "authentication_failed"],
           "mitre": {"id": ["T1531"], "tactic": ["Impact"], "technique": ["Account Access Removal"]}, …},
  "agent": {"id": "002", "name": "EB-FS01", "ip": "10.10.20.20"},
  "decoder": {"name": "windows_eventchannel"},
  "data": {"win": {
    "system": {"eventID": "4625", "channel": "Security", "computer": "EB-FS01.emberbay.local",
               "providerName": "Microsoft-Windows-Security-Auditing", "systemTime": "2026-10-27T10:15:30.0000000Z",
               "eventRecordID": "2221744", "severityValue": "AUDIT_FAILURE", …},
    "eventdata": {"targetUserName": "administrator", "targetDomainName": "EMBERBAY", "status": "0xc000006d",
                  "subStatus": "0xc000006a", "logonType": "3", "authenticationPackageName": "NTLM",
                  "workstationName": "KALI", "ipAddress": "10.8.0.14", "ipPort": "52113", …}}},
  "location": "EventChannel"
}
```

### Linux sshd / sudo (`linux.py`)

`full_log` is the real `/var/log/auth.log` line (host-local time, hostname, `sshd[pid]`). sudo logs without a PID on Ubuntu 22.04, so its line has none. Builders: `ssh_failed_password` (data `srcip`, `srcport`, `dstuser`), `ssh_invalid_user` (`srcuser`), `ssh_accepted_password`, `sudo_command` (`srcuser`, `tty`, `pwd`, `dstuser`, `command`).

```json
{
  "rule": {"level": 5, "description": "sshd: authentication failed.", "id": "5716",
           "groups": ["syslog", "sshd", "authentication_failed"], "mitre": {"id": ["T1110"], …}, …},
  "agent": {"id": "004", "name": "EB-WEB01", "ip": "10.10.30.10"},
  "full_log": "Oct 27 15:45:30 EB-WEB01 sshd[26588]: Failed password for svc-webapp from 45.148.10.121 port 44512 ssh2",
  "predecoder": {"program_name": "sshd", "timestamp": "Oct 27 15:45:30", "hostname": "EB-WEB01"},
  "decoder": {"parent": "sshd", "name": "sshd"},
  "data": {"srcip": "45.148.10.121", "srcport": "44512", "dstuser": "svc-webapp"},
  "location": "/var/log/auth.log"
}
```

### nginx access log (`web.py`)

`access_log(...)`: the "combined" format line in `full_log`; decoder `web-accesslog`; `data.srcip`, `data.url`, `data.id` (status), `data.protocol` (the method, as Wazuh names it). Wazuh picks attack rules by URL pattern, so the caller states what the URL contains (`attack="sql_injection" | "xss" | "common"`). A 200 response to an attack becomes 31106.

```json
{
  "rule": {"level": 7, "description": "SQL injection attempt.", "id": "31103", "mitre": {"id": ["T1190"], …}, …},
  "full_log": "45.148.10.121 - - [27/Oct/2026:15:45:30 +0530] \"GET /login?user=admin%27%20OR%201%3D1-- HTTP/1.1\" 403 153 \"-\" \"sqlmap/1.8.4#stable (https://sqlmap.org)\"",
  "decoder": {"name": "web-accesslog"},
  "data": {"protocol": "GET", "srcip": "45.148.10.121", "id": "403", "url": "/login?user=admin%27%20OR%201%3D1--"},
  "location": "/var/log/nginx/access.log"
}
```

### OpenVPN (`vpn.py`)

OpenVPN 2.6 lines via syslog (`openvpn[pid]`), decoder `openvpn`. Builders: `auth_failed` (`<ip>:<port> TLS Auth Error: Auth Username/Password verification failed for peer`; OpenVPN doesn't print the username here, so there is no user), `peer_connection_initiated` (`<ip>:<port> [<user>] Peer Connection Initiated with [AF_INET]<ip>:<port>`), `client_address_assigned` (`<user>/<ip>:<port> MULTI_sva: pool returned IPv4=<virtual>`), `client_disconnected` (`SIGTERM[soft,remote-exit] received, client-instance exiting`).

```json
{
  "rule": {"level": 3, "description": "OpenVPN: User logged in", "id": "81801", …},
  "full_log": "Oct 27 15:45:30 EB-VPN01 openvpn[1635]: 198.51.100.23:50122 [neha.sharma] Peer Connection Initiated with [AF_INET]198.51.100.23:50122",
  "decoder": {"name": "openvpn"},
  "data": {"srcip": "198.51.100.23", "srcport": "50122", "srcuser": "neha.sharma"},
  "location": "/var/log/syslog"
}
```

### pfSense filterlog + Suricata (`firewall.py`)

`filterlog(...)`: the IPv4 filterlog CSV line (rule, sub-rule, anchor, tracker, interface, reason, action, direction, version, tos, ecn, ttl, id, offset, flags, proto id, proto, length, src, dst, then the TCP/UDP fields), decoder `pf`. `suricata_alert(...)`: an EVE `alert` record in `data`, decoder `json`. Stock rule 86601 has `no_full_log` and is level 3 for every signature. Use real ET Open signatures/SIDs.

```json
{
  "rule": {"level": 5, "description": "pfSense firewall drop event.", "id": "87701", "groups": ["pfsense", "firewall_block"], …},
  "agent": {"id": "007", "name": "EB-FW01", "ip": "10.10.40.1"},
  "full_log": "Oct 27 15:45:30 EB-FW01 filterlog[47544]: 5,,,1000000103,igb0,match,block,in,4,0x0,,90,24977,0,DF,6,tcp,60,2.57.121.25,203.0.113.10,51234,3389,0,S,1727563948,,64240,,mss;sackOK;TS;nop;wscale",
  "decoder": {"name": "pf"},
  "data": {"action": "block", "protocol": "tcp", "srcip": "2.57.121.25", "dstip": "203.0.113.10", "srcport": "51234", "dstport": "3389"},
  "location": "/var/log/filter.log"
}
```

```json
{
  "rule": {"level": 3, "description": "Suricata: Alert - ET SCAN Sqlmap SQL Injection Scan", "id": "86601", "groups": ["ids", "suricata"], …},
  "decoder": {"name": "json"},
  "data": {"timestamp": "2026-10-27T15:45:30.000000+0530", "flow_id": "5726758047077539", "in_iface": "igb0",
           "event_type": "alert", "src_ip": "45.148.10.121", "src_port": "44512", "dest_ip": "10.10.30.10", "dest_port": "80",
           "proto": "TCP", "alert": {"action": "allowed", "gid": "1", "signature_id": "2008538", "rev": "8",
           "signature": "ET SCAN Sqlmap SQL Injection Scan", "category": "Attempted Information Leak", "severity": "2"},
           "app_proto": "http"},
  "location": "/var/log/suricata/eve.json"
}
```

### Mail gateway (`mail.py`)

Two lines per inbound message, tied together by the Postfix queue ID. `attachment_warning` is Postfix cleanup's `mime_header_checks` WARN line for the attachment's `Content-Type` (file name + MIME type). `content_filter_verdict` is the content filter's amavis-style verdict line: Passed/Blocked, verdict, client, sender → recipient, Queue-ID, Message-ID, Subject. CLEAN/SPAMMY fire custom rule 100501; SPAM/BANNED/INFECTED fire 100502.

```json
{
  "rule": {"level": 3, "description": "Mail content filter: message passed", "id": "100501", …},
  "full_log": "Oct 27 15:45:30 EB-MAIL01 amavis[57261]: (57261-48) Passed CLEAN {RelayedInbound}, [140.246.61.93]:41234 <billing@invoice-portal.example> -> <neha.sharma@emberbay.local>, Queue-ID: E4B19D504E83, Message-ID: <20261027.4471@invoice-portal.example>, Hits: 1.200, size: 48213, Subject: \"Overdue invoice 4471\", 1040 ms",
  "data": {"srcip": "140.246.61.93", "from": "billing@invoice-portal.example", "to": "neha.sharma@emberbay.local",
           "subject": "Overdue invoice 4471", "verdict": "CLEAN", "action": "passed", "queue_id": "E4B19D504E83", …},
  "location": "/var/log/mail.log"
}
```

### PostgreSQL (`database.py`)

PostgreSQL 15 server log, `log_line_prefix = '%m [%p] %h %q%u@%d '` with `log_connections` and `log_statement` on; decoder `postgresql_log`. Builders: `connection_authorized`, `password_authentication_failed`, `copy_to_stdout` (`statement: COPY <table> TO STDOUT WITH CSV HEADER`).

```json
{
  "rule": {"level": 7, "description": "PostgreSQL: bulk export (COPY ... TO STDOUT)", "id": "100600", "mitre": {"id": ["T1005"], …}, …},
  "agent": {"id": "003", "name": "EB-DB01", "ip": "10.10.20.30"},
  "full_log": "2026-10-27 15:45:30.000 IST [84541] 10.10.30.10 svc-sql@finance_core LOG:  statement: COPY public.customer_accounts TO STDOUT WITH CSV HEADER",
  "decoder": {"name": "postgresql_log"},
  "data": {"srcip": "10.10.30.10", "dstuser": "svc-sql", "database": "finance_core", "status": "LOG",
           "statement": "COPY public.customer_accounts TO STDOUT WITH CSV HEADER", "table": "public.customer_accounts"},
  "location": "/var/log/postgresql/postgresql-15-main.log"
}
```

### AWS CloudTrail (`cloudtrail.py`, source `aws_cloudtrail`)

The CloudTrail record schema, `eventVersion` 1.08: `userIdentity{type, principalId, arn, accountId, accessKeyId, userName}`, `eventTime`, `eventSource`, `eventName`, `awsRegion`, `sourceIPAddress`, `userAgent`, `requestParameters`, `responseElements`, optional `errorCode`/`errorMessage`, `requestID`, `eventID`, `readOnly`, `resources`, `eventType`, `managementEvent`, `recipientAccountId`, `eventCategory`. Builders: `get_caller_identity`, `list_buckets` (pass `error_code="AccessDenied"` for a denied call), `get_object` (a data event with object + bucket ARNs), `console_login` (`AwsConsoleSignIn`; a failure has `errorMessage: "Failed authentication"` and no errorCode). IAM `principalId`s are fictional but stable, derived from the user's ARN.

```json
{
  "eventVersion": "1.08",
  "userIdentity": {"type": "IAMUser", "principalId": "AIDAAYCL2E2L6AY3MXQVC", "arn": "arn:aws:iam::111122223333:user/svc-web-deploy",
                   "accountId": "111122223333", "accessKeyId": "AKIAIOSFODNN7EXAMPLE", "userName": "svc-web-deploy"},
  "eventTime": "2026-10-27T10:15:30Z", "eventSource": "s3.amazonaws.com", "eventName": "GetObject", "awsRegion": "ap-south-1",
  "sourceIPAddress": "203.0.113.20", "userAgent": "aws-cli/2.17.20 …",
  "requestParameters": {"bucketName": "eb-web-assets", "Host": "eb-web-assets.s3.ap-south-1.amazonaws.com", "key": "css/portal.css"},
  "responseElements": null, "additionalEventData": {"bytesTransferredOut": 18342, …},
  "requestID": "3B21E26174E909E8", "eventID": "936941b1-7437-56a9-8c3f-4783e0aa0731", "readOnly": true,
  "resources": [{"type": "AWS::S3::Object", "ARN": "arn:aws:s3:::eb-web-assets/css/portal.css"},
                {"accountId": "111122223333", "type": "AWS::S3::Bucket", "ARN": "arn:aws:s3:::eb-web-assets"}],
  "eventType": "AwsApiCall", "managementEvent": false, "recipientAccountId": "111122223333", "eventCategory": "Data"
}
```

### AWS GuardDuty (`guardduty.py`, source `aws_guardduty`)

Findings in the GetFindings shape (SchemaVersion 2.0, PascalCase): `AccountId`, `Region`, `Partition`, `Id`, `Arn`, `Type`, `Resource{ResourceType: AccessKey, AccessKeyDetails{…}}`, `Service{ServiceName, DetectorId, Action{ActionType: AWS_API_CALL, AwsApiCallAction{Api, CallerType, ServiceName, RemoteIpDetails{IpAddressV4, Country, Organization}}}, Count, EventFirstSeen, EventLastSeen}`, `Severity`, `CreatedAt`, `UpdatedAt`, `Title`, `Description`. `finding(...)` is generic. `instance_credential_exfiltration_outside_aws(...)` builds `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` (severity 8.0), which GuardDuty raises for **EC2 instance-role** (AssumedRole) credentials. **`Country` and `Organization` are caller-supplied** (`remote_ip_details(ip, country=…, asn=…)`, default "Unknown"), so no geo or ASN is ever hard-coded for a real IP.

```json
{
  "SchemaVersion": "2.0", "AccountId": "111122223333", "Region": "ap-south-1", "Partition": "aws",
  "Id": "3034a9dbe5a342882a817795aad3e4c9", "Arn": "arn:aws:guardduty:ap-south-1:111122223333:detector/…/finding/3034a9dbe5a342882a817795aad3e4c9",
  "Type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
  "Resource": {"ResourceType": "AccessKey", "AccessKeyDetails": {"AccessKeyId": "ASIAIOSFODNN7EXAMPLE", "UserType": "AssumedRole", …}},
  "Service": {"ServiceName": "guardduty", "Action": {"ActionType": "AWS_API_CALL", "AwsApiCallAction": {
                "Api": "GetCallerIdentity", "CallerType": "Remote IP", "ServiceName": "sts.amazonaws.com",
                "RemoteIpDetails": {"IpAddressV4": "93.174.95.106", "Country": {"CountryName": "Unknown"},
                                    "Organization": {"Asn": "Unknown", "AsnOrg": "Unknown", "Isp": "Unknown", "Org": "Unknown"}}}},
              "Count": 1, "EventFirstSeen": "2026-10-27T10:15:30.000Z", "EventLastSeen": "2026-10-27T10:15:30.000Z", …},
  "Severity": 8.0, "CreatedAt": "2026-10-27T10:15:30.000Z", "UpdatedAt": "2026-10-27T10:15:30.000Z",
  "Title": "Credentials for instance role example-instance-role used from external IP address.", …
}
```

## Wazuh rule IDs

**Stock** rules were verified against the public wazuh/wazuh ruleset at tag **v4.9.2** (`ruleset/rules/<file>`). The ID, level, description, groups and MITRE IDs are copied from the rule. **Custom** rules use Wazuh's local-rule range 100000–100999, because the stock ruleset has no alerting rule for that event. The source of truth is `RULES` in `injector/sim/formats/wazuh_common.py`, and a test keeps custom IDs inside the range.

| ID | Level | Description | Stock file / custom | Builder |
|---|---|---|---|---|
| 60106 | 3 | Windows Logon Success | 0580-win-security_rules.xml | windows.logon_success (type 3/10) |
| 60118 | 3 | Windows Workstation Logon Success | 0580-win-security_rules.xml | windows.logon_success (type 2) |
| 60122 | 5 | Logon Failure - Unknown user or bad password | 0580-win-security_rules.xml | windows.logon_failure |
| 60109 | 8 | User account enabled or created | 0580-win-security_rules.xml | windows.user_created |
| 60141 | 5 | Security Enabled Global Group Member Added | 0580-win-security_rules.xml | windows.member_added_global_group (other groups) |
| 60159 | 12 | Domain Admins Group Changed | 0580-win-security_rules.xml | windows.member_added_global_group (Domain Admins) |
| 60160 | 5 | Domain Users Group Changed | 0580-win-security_rules.xml | windows.member_added_global_group (Domain Users) |
| 60144 | 5 | Security Enabled Local Group Member Added | 0580-win-security_rules.xml | windows.member_added_local_group (other groups) |
| 60154 | 12 | Administrators Group Changed | 0580-win-security_rules.xml | windows.member_added_local_group (Administrators) |
| 60170 | 5 | Users Group Changed | 0580-win-security_rules.xml | windows.member_added_local_group (Users) |
| 60179 | 10 | Remote Desktop Users Group Changed | 0580-win-security_rules.xml | windows.member_added_local_group (Remote Desktop Users) |
| 60117 | 9 | Windows audit log was cleared | 0580-win-security_rules.xml | windows.audit_log_cleared |
| 60227 | 8 | A new external device was recognized by the system | 0580-win-security_rules.xml | windows.usb_device_recognized |
| 100100 | 3 | Windows: Special privileges assigned to new logon | custom (no stock alert for 4672) | windows.special_privileges |
| 100101 | 3 | Windows: A new process has been created | custom (no stock alert for 4688) | windows.process_created |
| 100110 | 3 | Sysmon - Event 1: Process creation | custom (stock 61603 is level 0) | windows.sysmon_process_create |
| 100111 | 3 | Sysmon - Event 3: Network connection | custom (stock 61605 is level 0) | windows.sysmon_network_connect |
| 100112 | 3 | Sysmon - Event 11: File created | custom (stock 61613 is level 0) | windows.sysmon_file_create |
| 100113 | 3 | Sysmon - Event 23: File deleted and archived | custom (stock 61651 is level 0) | windows.sysmon_file_delete |
| 5716 | 5 | sshd: authentication failed. | 0095-sshd_rules.xml | linux.ssh_failed_password |
| 5710 | 5 | sshd: Attempt to login using a non-existent user | 0095-sshd_rules.xml | linux.ssh_invalid_user |
| 5715 | 3 | sshd: authentication success. | 0095-sshd_rules.xml | linux.ssh_accepted_password |
| 5402 | 3 | Successful sudo to ROOT executed. | 0020-syslog_rules.xml | linux.sudo_command (USER=root) |
| 5407 | 3 | Successful sudo executed. | 0020-syslog_rules.xml | linux.sudo_command (other users) |
| 31101 | 5 | Web server 400 error code. | 0245-web_rules.xml | web.access_log (4xx) |
| 31120 | 5 | Web server 500 error code (server error). | 0245-web_rules.xml | web.access_log (5xx other than 500) |
| 31122 | 5 | Web server 500 error code (Internal Error). | 0245-web_rules.xml | web.access_log (500) |
| 31103 | 7 | SQL injection attempt. | 0245-web_rules.xml | web.access_log (attack=sql_injection) |
| 31104 | 6 | Common web attack. | 0245-web_rules.xml | web.access_log (attack=common) |
| 31105 | 6 | XSS (Cross Site Scripting) attempt. | 0245-web_rules.xml | web.access_log (attack=xss) |
| 31106 | 6 | A web attack returned code 200 (success). | 0245-web_rules.xml | web.access_log (attack + 200) |
| 100300 | 3 | nginx: web request | custom (stock 31100 is level 0) | web.access_log (plain request) |
| 81801 | 3 | OpenVPN: User logged in | 0400-openvpn_rules.xml | vpn.peer_connection_initiated |
| 100400 | 5 | OpenVPN: Username/password authentication failed | custom | vpn.auth_failed |
| 100401 | 3 | OpenVPN: Client assigned a virtual address | custom | vpn.client_address_assigned |
| 100402 | 3 | OpenVPN: Client disconnected | custom | vpn.client_disconnected |
| 87701 | 5 | pfSense firewall drop event. | 0540-pfsense_rules.xml | firewall.filterlog (block) |
| 100700 | 3 | pfSense firewall pass event. | custom (stock 87700 is level 0) | firewall.filterlog (pass) |
| 86601 | 3 | Suricata: Alert - $(alert.signature) | 0475-suricata_rules.xml | firewall.suricata_alert |
| 100500 | 4 | Postfix: inbound message with attachment | custom | mail.attachment_warning |
| 100501 | 3 | Mail content filter: message passed | custom | mail.content_filter_verdict (CLEAN/SPAMMY) |
| 100502 | 8 | Mail content filter: message blocked | custom | mail.content_filter_verdict (SPAM/BANNED/INFECTED) |
| 50511 | 3 | PostgreSQL: Database authentication success. | 0300-postgresql_rules.xml | database.connection_authorized |
| 50512 | 9 | PostgreSQL: Database authentication failure. | 0300-postgresql_rules.xml | database.password_authentication_failed |
| 100600 | 7 | PostgreSQL: bulk export (COPY ... TO STDOUT) | custom (stock 50510 is level 0) | database.copy_to_stdout |

## CLI

Run from the repository root. Install the requirements with `pip install -r injector/requirements.txt` (requests, PyYAML).

```bash
python -m injector.sim org                                          # summary + validation result
python -m injector.sim org --diagram                                # Mermaid to stdout
python -m injector.sim org --diagram --out docs/simulator-network.mmd
python -m injector.sim samples --out samples.jsonl                  # one event per builder, {"source", "payload"} per line
python -m injector.sim samples --send                               # log in, POST per source, print accepted/rejected
```

Global flags (before or after the subcommand): `--org PATH` (default: the bundled EmberBay YAML), `--api-base` (default `http://localhost:8000`), `--tenant-id` / `--email` / `--password` (default: the demo tenant from `injector/injector.py`; run `python injector/demo.py` once to provision it). `samples` also takes `--run-id` and `--batch-size`.

## Planned

- **Attack scenarios.** Ordered, timed event sequences per attacker (VPN brute force → intrusion, phishing → macro → C2, portal exploitation, leaked-key abuse in AWS, ransomware). They will use only the builders above and `Org.target()`.
- **Default simulator.** A steady background of normal business activity (logons, web traffic, VPN sessions, mail) so detections have noise to stand out from.
- **Random simulator.** Randomised attacks drawn from the attacker pool.
- **Story simulator.** A multi-stage incident across on-prem and cloud, told through the same hosts and users.
