"""
SafeSOC — Simulator PostgreSQL Builders
PostgreSQL 15 server log lines from EB-DB01 as Wazuh alerts (decoder
postgresql_log), using log_line_prefix = '%m [%p] %h %q%u@%d ' with
log_connections and log_statement enabled.
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Optional

from injector.sim.formats.wazuh_common import RULES, alert, iso_z, local_time, pick_int
from injector.sim.org import Asset, Org

__all__ = ["connection_authorized", "password_authentication_failed", "copy_to_stdout"]

PG_LOG = "/var/log/postgresql/postgresql-15-main.log"


def _line(org: Org, db: Asset, ts: datetime, *, pid: int, client_ip: str, user: str, database: str, level: str,
          message: str) -> str:
    local = local_time(org, ts)
    stamp = local.strftime("%Y-%m-%d %H:%M:%S.") + f"{local.microsecond // 1000:03d} " + local.strftime("%Z")
    return f"{stamp} [{pid}] {client_ip} {user}@{database} {level}:  {message}"


def _pg(org, db, ts, *, rule_name, pid, client_ip, user, database, level, message, extra, simulation, rng) -> dict:
    return alert(
        org, db, ts, rule=RULES[rule_name], decoder={"name": "postgresql_log"}, location=PG_LOG,
        full_log=_line(org, db, ts, pid=pid, client_ip=client_ip, user=user, database=database, level=level, message=message),
        data={"srcip": client_ip, "dstuser": user, "database": database, "status": level, **extra},
        simulation=simulation, rng=rng,
    )


def _backend_pid(rng, db: Asset, ts: datetime, client_ip: str, pid: Optional[int]) -> int:
    return pid if pid is not None else pick_int(rng, 10000, 99999, "pgpid", db.hostname, client_ip, iso_z(ts, digits=6))


def connection_authorized(
    org: Org, db: Asset, timestamp: datetime, *, client_ip: str, db_user: str, database: str,
    application_name: str = "psql", pid: Optional[int] = None, simulation: Optional[dict] = None,
    rng: Optional[random.Random] = None,
) -> dict:
    """'LOG:  connection authorized: user=.. database=.. application_name=..' (stock rule 50511)."""
    backend = _backend_pid(rng, db, timestamp, client_ip, pid)
    return _pg(
        org, db, timestamp, rule_name="pg_auth_success", pid=backend, client_ip=client_ip, user=db_user,
        database=database, level="LOG",
        message=f"connection authorized: user={db_user} database={database} application_name={application_name}",
        extra={}, simulation=simulation, rng=rng,
    )


def password_authentication_failed(
    org: Org, db: Asset, timestamp: datetime, *, client_ip: str, db_user: str, database: str,
    pid: Optional[int] = None, simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """'FATAL:  password authentication failed for user "<user>"' (stock rule 50512, level 9)."""
    backend = _backend_pid(rng, db, timestamp, client_ip, pid)
    return _pg(
        org, db, timestamp, rule_name="pg_auth_failed", pid=backend, client_ip=client_ip, user=db_user,
        database=database, level="FATAL", message=f'password authentication failed for user "{db_user}"',
        extra={}, simulation=simulation, rng=rng,
    )


def copy_to_stdout(
    org: Org, db: Asset, timestamp: datetime, *, client_ip: str, db_user: str, database: str, table: str,
    pid: Optional[int] = None, simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """'LOG:  statement: COPY <table> TO STDOUT WITH CSV HEADER' (custom rule 100600: bulk export)."""
    backend = _backend_pid(rng, db, timestamp, client_ip, pid)
    statement = f"COPY {table} TO STDOUT WITH CSV HEADER"
    return _pg(
        org, db, timestamp, rule_name="pg_copy_to_stdout", pid=backend, client_ip=client_ip, user=db_user,
        database=database, level="LOG", message=f"statement: {statement}",
        extra={"statement": statement, "table": table}, simulation=simulation, rng=rng,
    )
