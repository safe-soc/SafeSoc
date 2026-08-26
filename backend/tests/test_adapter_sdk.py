"""
SafeSOC — Adapter SDK Tests (SS-069)
Covers the public contract: the LogAdapter structural protocol and the
AdapterRegistry registration API. Built-in adapters' own transform()
behavior is already covered by test_adapters.py — unchanged here.
"""

import pytest

from app.adapters.sdk import ADAPTER_SDK_VERSION, AdapterRegistry, LogAdapter


def _valid_adapter(raw: dict) -> dict:
    return {"log_type": "system", "raw_log": "{}"}


class _NotCallable:
    pass


# ── LogAdapter structural protocol ───────────────────────────────────

def test_a_plain_function_satisfies_the_log_adapter_protocol():
    assert isinstance(_valid_adapter, LogAdapter)


def test_a_lambda_satisfies_the_log_adapter_protocol():
    assert isinstance(lambda raw: {}, LogAdapter)


def test_a_non_callable_does_not_satisfy_the_log_adapter_protocol():
    assert not isinstance(_NotCallable(), LogAdapter)
    assert not isinstance("not an adapter", LogAdapter)
    assert not isinstance(42, LogAdapter)


# ── AdapterRegistry ───────────────────────────────────────────────────

def test_register_and_get_round_trip():
    registry = AdapterRegistry()

    registry.register("my_source", _valid_adapter)

    assert registry.get("my_source") is _valid_adapter


def test_get_returns_none_for_an_unregistered_source():
    registry = AdapterRegistry()

    assert registry.get("nonexistent") is None


def test_sources_lists_every_registered_source():
    registry = AdapterRegistry()
    registry.register("a", _valid_adapter)
    registry.register("b", _valid_adapter)

    assert set(registry.sources()) == {"a", "b"}


def test_register_rejects_a_duplicate_source_without_replace():
    registry = AdapterRegistry()
    registry.register("my_source", _valid_adapter)

    with pytest.raises(ValueError, match="already registered"):
        registry.register("my_source", _valid_adapter)


def test_register_with_replace_true_overwrites_an_existing_adapter():
    registry = AdapterRegistry()
    registry.register("my_source", _valid_adapter)

    def _new_adapter(raw: dict) -> dict:
        return {"log_type": "network", "raw_log": "{}"}

    registry.register("my_source", _new_adapter, replace=True)

    assert registry.get("my_source") is _new_adapter


def test_register_rejects_a_non_callable_adapter():
    registry = AdapterRegistry()

    with pytest.raises(TypeError, match="LogAdapter"):
        registry.register("my_source", _NotCallable())


def test_sdk_version_is_a_non_empty_string():
    """Regression guard — a third-party integration may reasonably check this."""
    assert isinstance(ADAPTER_SDK_VERSION, str)
    assert ADAPTER_SDK_VERSION


# ── Built-in adapters actually register on import (app.adapters) ────

def test_all_four_built_in_adapters_are_registered_on_import():
    import app.adapters as adapters_package
    from app.adapters import cloudlens, cloudtrail, guardduty, wazuh
    from app.adapters.sdk import registry

    assert registry.get("wazuh") is wazuh.transform
    assert registry.get("aws_cloudtrail") is cloudtrail.transform
    assert registry.get("aws_guardduty") is guardduty.transform
    assert registry.get("cloudlens") is cloudlens.transform
    assert adapters_package.registry is registry
