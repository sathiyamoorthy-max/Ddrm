from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.getenv("LAB_DATA_DIR", PROJECT_ROOT / "data")).resolve()

LOCAL_LAB_HOSTS = {"127.0.0.1", "localhost", "::1", "lab-server"}


def _external_mode_enabled() -> bool:
    return os.getenv("LAB_EXTERNAL_TEST_MODE", "").strip() == "1"


def _allowed_external_hosts() -> set[str]:
    return {
        value.strip().lower()
        for value in os.getenv("LAB_ALLOWED_HOSTS", "").split(",")
        if value.strip()
    }


def gateway_token() -> str:
    return os.getenv("LAB_GATEWAY_TOKEN", "").strip()


def lab_request_headers(user: str | None = None) -> dict[str, str]:
    headers: dict[str, str] = {}

    token = gateway_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    if user:
        headers["X-Lab-User"] = user

    return headers


def validate_lab_base_url(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    if not host:
        raise ValueError("LAB_BASE_URL must contain a hostname")

    if parsed.username or parsed.password:
        raise ValueError("credentials are not allowed inside LAB_BASE_URL")

    if parsed.query or parsed.fragment:
        raise ValueError("LAB_BASE_URL must not contain query parameters or fragments")

    if host in LOCAL_LAB_HOSTS:
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("local LAB_BASE_URL must use http or https")
        return url.rstrip("/")

    if not _external_mode_enabled():
        raise ValueError(
            "external LAB_BASE_URL is disabled; set LAB_EXTERNAL_TEST_MODE=1 "
            "only for a staging server you control"
        )

    if parsed.scheme != "https":
        raise ValueError("external staging LAB_BASE_URL must use https")

    if host not in _allowed_external_hosts():
        raise ValueError("external host is not listed in LAB_ALLOWED_HOSTS")

    if not gateway_token():
        raise ValueError(
            "LAB_GATEWAY_TOKEN is required when LAB_EXTERNAL_TEST_MODE=1"
        )

    return url.rstrip("/")
