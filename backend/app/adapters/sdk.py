"""
SafeSOC — Adapter SDK (SS-069)
Formalizes the internal pattern already established by the Wazuh/
CloudTrail/GuardDuty/CloudLens adapters (SS-018-020, SS-038) into a
documented, versioned interface a third party can implement and
register without forking this repository — closing the gap
PRODUCT_ROADMAP.md describes: v0.3.0 shipped those four as internal,
hardcoded modules, sufficient for v1.0 but not a formal, external-
implementer-friendly contract.

Deliberately NOT a plugin marketplace or discovery system (SS-082 —
out of scope and explicitly blocked in PRODUCT_ROADMAP.md's v2.0
section, gated on validated demand this project doesn't have yet).
This module is just the contract (LogAdapter) plus a registration
point (AdapterRegistry) — how third-party adapters get distributed or
discovered is a separate, later concern.
"""

from typing import Optional, Protocol, runtime_checkable

# SDK contract version — independent of app.core.config.settings.APP_VERSION
# (the whole application's release) and of the /api/v1 versioning policy
# (docs/api-versioning-policy.md, SS-070) — this tracks only the shape of
# LogAdapter itself. Bump it if that shape ever changes in a way an
# existing third-party adapter would need to adapt to.
ADAPTER_SDK_VERSION = "1.0.0"


@runtime_checkable
class LogAdapter(Protocol):
    """
    The contract every source adapter — built-in or third-party — must
    satisfy: a single callable taking one raw, source-native payload
    dict and returning a NormalizedLog-shaped dict (see
    `app/schemas/log.py`).

    Contract, matching what every existing adapter already does:

    - MUST NOT raise for a malformed/sparse payload. Degrade to
      sensible defaults (e.g. `"unknown-host"`, `Severity.LOW`) so one
      bad record never fails ingestion at the adapter layer —
      `services/ingestion.py`'s `NormalizedLog` validation is the one
      place a record is legitimately rejected, with a per-item
      accepted/rejected result, never the adapter itself.
    - MUST NOT set `tenant_id` on the returned dict. It's always
      injected by the ingestion pipeline from the caller's
      authenticated identity (SS-016) — an adapter-supplied value
      would be silently overwritten anyway, so setting one is
      pointless at best and misleading to read at worst.
    - SHOULD only set `source` if the batch-level `source` the caller
      passed to `process_ingest_batch()` wouldn't already be correct
      for this individual record (see `cloudtrail.transform`, which
      sets it explicitly).
    - SHOULD preserve the original raw payload in `raw_log` (as a
      JSON string, see `json.dumps(raw, default=str)` in every
      built-in adapter) so nothing is lost even when a field couldn't
      be mapped to a typed `NormalizedLog` column.

    Example — a minimal third-party adapter:

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

        from app.adapters.sdk import registry
        registry.register("my_source", transform)
    """

    def __call__(self, raw: dict) -> dict: ...


class AdapterRegistry:
    """
    Maps a `LogSource` string to its `LogAdapter`. Deliberately a small
    class rather than a plain dict literal (which is what
    `services/ingestion.py` used before this issue) so registering a
    new source is one documented call — `registry.register(...)` —
    instead of requiring a fork to edit that dict literal directly,
    and so an accidental double-registration is caught rather than
    silently overwriting an existing adapter.
    """

    def __init__(self) -> None:
        self._adapters: dict[str, LogAdapter] = {}

    def register(self, source: str, adapter: LogAdapter, *, replace: bool = False) -> None:
        """
        Raises:
            TypeError: if `adapter` doesn't satisfy the LogAdapter contract
            (i.e. isn't callable — the only part `isinstance` can check
            structurally; the behavioral contract above still applies).
            ValueError: if `source` is already registered and `replace`
            isn't explicitly set — guards against one adapter silently
            shadowing another (e.g. a naming collision between a
            built-in and a third-party adapter).
        """
        if not isinstance(adapter, LogAdapter):
            raise TypeError(f"Adapter for source '{source}' must implement LogAdapter (a callable dict -> dict).")
        if source in self._adapters and not replace:
            raise ValueError(
                f"An adapter is already registered for source '{source}'. "
                "Pass replace=True if you intend to override it."
            )
        self._adapters[source] = adapter

    def get(self, source: str) -> Optional[LogAdapter]:
        return self._adapters.get(source)

    def sources(self) -> list[str]:
        return list(self._adapters)


# One shared registry for the running application — built-in adapters
# register themselves against this in adapters/__init__.py; a
# third-party adapter imports this same object and calls .register()
# on it before the app starts handling ingestion requests.
registry = AdapterRegistry()
