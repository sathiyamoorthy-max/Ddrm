from __future__ import annotations

import pytest

from app.config import validate_lab_base_url
from app.server import app


def _clear_external_env(monkeypatch):
    monkeypatch.delenv("LAB_EXTERNAL_TEST_MODE", raising=False)
    monkeypatch.delenv("LAB_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("LAB_GATEWAY_TOKEN", raising=False)


def test_local_lab_url_still_allowed(monkeypatch):
    _clear_external_env(monkeypatch)
    assert validate_lab_base_url("http://127.0.0.1:5000") == "http://127.0.0.1:5000"


def test_external_target_disabled_by_default(monkeypatch):
    _clear_external_env(monkeypatch)
    with pytest.raises(ValueError, match="external LAB_BASE_URL is disabled"):
        validate_lab_base_url("https://ddrm-lab.example.edu")


def test_external_target_requires_exact_allowed_host(monkeypatch):
    monkeypatch.setenv("LAB_EXTERNAL_TEST_MODE", "1")
    monkeypatch.setenv("LAB_ALLOWED_HOSTS", "lab.example.edu")
    monkeypatch.setenv("LAB_GATEWAY_TOKEN", "secret")

    with pytest.raises(ValueError, match="not listed"):
        validate_lab_base_url("https://other.example.edu")


def test_external_target_requires_https(monkeypatch):
    monkeypatch.setenv("LAB_EXTERNAL_TEST_MODE", "1")
    monkeypatch.setenv("LAB_ALLOWED_HOSTS", "ddrm-lab.example.edu")
    monkeypatch.setenv("LAB_GATEWAY_TOKEN", "secret")

    with pytest.raises(ValueError, match="must use https"):
        validate_lab_base_url("http://ddrm-lab.example.edu")


def test_external_target_requires_gateway_token(monkeypatch):
    monkeypatch.setenv("LAB_EXTERNAL_TEST_MODE", "1")
    monkeypatch.setenv("LAB_ALLOWED_HOSTS", "ddrm-lab.example.edu")
    monkeypatch.delenv("LAB_GATEWAY_TOKEN", raising=False)

    with pytest.raises(ValueError, match="LAB_GATEWAY_TOKEN is required"):
        validate_lab_base_url("https://ddrm-lab.example.edu")


def test_external_target_allowed_when_all_guards_are_set(monkeypatch):
    monkeypatch.setenv("LAB_EXTERNAL_TEST_MODE", "1")
    monkeypatch.setenv("LAB_ALLOWED_HOSTS", "ddrm-lab.example.edu")
    monkeypatch.setenv("LAB_GATEWAY_TOKEN", "secret")

    assert (
        validate_lab_base_url("https://ddrm-lab.example.edu/")
        == "https://ddrm-lab.example.edu"
    )


def test_gateway_token_protects_server_when_configured(monkeypatch):
    monkeypatch.setenv("LAB_GATEWAY_TOKEN", "top-secret")
    client = app.test_client()

    denied = client.get("/health")
    assert denied.status_code == 401

    allowed = client.get(
        "/health",
        headers={"Authorization": "Bearer top-secret"},
    )
    assert allowed.status_code == 200
    assert allowed.get_json()["project"] == "Unified DRM Cyber Lab"
