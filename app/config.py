from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.getenv("LAB_DATA_DIR", PROJECT_ROOT / "data")).resolve()

ALLOWED_LAB_HOSTS = {"127.0.0.1", "localhost", "::1", "lab-server"}


def validate_lab_base_url(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    if parsed.scheme != "http":
        raise ValueError("LAB_BASE_URL must use http inside this local lab")

    if host not in ALLOWED_LAB_HOSTS:
        raise ValueError(
            "LAB_BASE_URL must point only to localhost/127.0.0.1/::1/lab-server"
        )

    if parsed.username or parsed.password:
        raise ValueError("credentials are not allowed inside LAB_BASE_URL")

    return url.rstrip("/")
