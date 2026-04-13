"""Tests for settings module."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from defined_mcp.settings import Settings


def test_settings_from_env(settings_env: None) -> None:
    s = Settings()
    assert s.api_key == "dnkey-test-key-12345"
    assert s.api_base_url == "https://api.defined.net"
    assert s.page_size == 25


def test_settings_custom_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEFINED_API_KEY", "dnkey-custom")
    monkeypatch.setenv("DEFINED_API_BASE_URL", "https://custom.api")
    monkeypatch.setenv("DEFINED_PAGE_SIZE", "100")
    s = Settings()
    assert s.api_key == "dnkey-custom"
    assert s.api_base_url == "https://custom.api"
    assert s.page_size == 100


def test_settings_missing_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEFINED_API_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings()
