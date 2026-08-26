# SafeSOC — Plugin/Adapter SDK

SS-069. Formalizes the internal source-adapter pattern shipped in v0.3.0 (SS-018–021: Wazuh, AWS CloudTrail, AWS GuardDuty, plus SS-038's CloudLens adapter) into a documented, versioned interface — the step from "four hardcoded internal modules" to "an interface a third party could implement without forking this repository," per `PRODUCT_ROADMAP.md`'s own framing of this issue.

**Explicitly out of scope:** a plugin marketplace, adapter discovery/distribution mechanism, or third-party plugin registry. That's SS-082 (`PRODUCT_ROADMAP.md` v2.0), a Research Feature explicitly blocked pending validated demand this project doesn't have yet. This document covers the *contract* and *registration* — how adapters are found and installed is a separate, later concern.

## The Problem This Solves

Before this issue, adding a new log source meant editing a dict literal inside `services/ingestion.py` directly:

```python
# The old way — required editing ingestion.py itself
ADAPTER_REGISTRY: dict[str, Callable[[dict], dict]] = {
    LogSource.WAZUH.value: wazuh.transform,
    ...
}
```

That's a fork, not an extension point. `backend/app/adapters/sdk.py` replaces it with a formal contract (`LogAdapter`) and a registration call (`AdapterRegistry.register()`) any module can call — including one that lives entirely outside this repository.

## The `LogAdapter` Contract

```python
from typing import Protocol, runtime_checkable

@runtime_checkable
class LogAdapter(Protocol):
    def __call__(self, raw: dict) -> dict: ...
```

Any callable taking one raw, source-native payload `dict` and returning a `NormalizedLog`-shaped `dict` (see `backend/app/schemas/log.py`) satisfies it — a plain function is enough, no base class to inherit from. Structural rules every adapter (built-in or third-party) must follow:

- **Never raise** for a malformed/sparse payload. Degrade to sensible defaults (`"unknown-host"`, `Severity.LOW`, etc.) — a single bad record must never fail ingestion at the adapter layer. `NormalizedLog` validation in `services/ingestion.py` is the one place a record is legitimately rejected, with a per-item accepted/rejected result.
- **Never set `tenant_id`.** It's always injected by the ingestion pipeline from the caller's authenticated JWT (SS-016) — an adapter-supplied value is silently overwritten, so setting one is misleading at best.
- **Preserve the raw payload** in `raw_log` (JSON-serialized) so nothing is lost even when a field couldn't be mapped.
- Only set `source` if the batch-level `source` argument wouldn't already be correct for this individual record (see `adapters/cloudtrail.py` for the one built-in example that does this).

Full contract documentation, with a worked example, lives in the `LogAdapter` docstring in `backend/app/adapters/sdk.py` — read it before writing a new adapter.

## Registering an Adapter

```python
from app.adapters.sdk import registry

def transform(raw: dict) -> dict:
    return {
        "log_type": "authentication",
        "timestamp": raw.get("time") or datetime.now(timezone.utc).isoformat(),
        "host_id": raw.get("host") or "unknown-host",
        "host_ip": raw.get("ip") or "0.0.0.0",
        "action": raw.get("event_type") or "unknown",
        "description": raw.get("message") or "Third-party alert",
        "severity": "low",
        "raw_log": json.dumps(raw, default=str),
    }

registry.register("my_source", transform)
```

`register()` raises `ValueError` if `my_source` is already taken (pass `replace=True` if overriding an existing adapter is genuinely intended) and `TypeError` if `transform` isn't callable — both fail loudly at registration time rather than silently at ingestion time.

Once registered, `POST /api/v1/ingest` accepts `source: "my_source"` and routes every log in that batch through `transform()` automatically — no other code changes needed.

## Built-in Adapters (Reference Implementations)

| Source | File | Notes |
|---|---|---|
| `wazuh` | `backend/app/adapters/wazuh.py` | Maps Wazuh rule/decoder groups to `LogType`, rule levels (0–15) to `Severity` bands |
| `aws_cloudtrail` | `backend/app/adapters/cloudtrail.py` | `errorCode` presence maps to `Severity.HIGH` (a denied API call is more notable than routine activity) |
| `aws_guardduty` | `backend/app/adapters/guardduty.py` | GuardDuty finding severity (0.0–10.0 float) mapped to the 4-tier `Severity` enum |
| `cloudlens` | `backend/app/adapters/cloudlens.py` | Converts a CloudLens IAM risk `Finding` (SS-038) rather than a runtime event log — a static misconfiguration finding, not a log line |

All four register themselves against the shared `registry` in `backend/app/adapters/__init__.py` — importing that package (which `services/ingestion.py` does) wires them all up as a side effect. Read any of the four as a concrete template before writing a new one; they're all under 110 lines.

## SDK Versioning

`backend/app/adapters/sdk.py` exports `ADAPTER_SDK_VERSION` (currently `"1.0.0"`), tracking only the shape of the `LogAdapter` contract — independent of `APP_VERSION` (the whole application's release) and of the `/api/v1` REST versioning policy (`docs/api-versioning-policy.md`, SS-070). It changes only if `LogAdapter`'s contract itself changes in a way an existing third-party adapter would need to adapt to.
