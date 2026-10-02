from __future__ import annotations

from app.assets import (
    MOCK_MPD_PATH,
    ensure_mock_assets,
)
from app.mock_cdm import (
    create_license_challenge,
    parse_mock_mpd,
)
from app.server import USERS, app, reset_state


def setup_function():
    reset_state()


def _challenge():
    ensure_mock_assets()
    manifest = parse_mock_mpd(
        MOCK_MPD_PATH.read_text(encoding="utf-8")
    )
    return create_license_challenge(manifest.pssh_b64)


def test_health():
    client = app.test_client()
    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json()["scope"] == "synthetic-local-content-only"


def test_insecure_hls_key_is_exposed_but_secure_key_requires_entitlement():
    client = app.test_client()

    insecure = client.get("/hls/key")
    assert insecure.status_code == 200
    assert len(insecure.data) == 16

    secure = client.get(
        "/hls/secure-key",
        headers={"X-Lab-User": "attacker"},
    )
    assert secure.status_code == 402
    assert secure.get_json()["error"] == "payment_required"


def test_student_can_purchase_hls_entitlement():
    client = app.test_client()

    payment = client.post(
        "/pay",
        headers={"X-Lab-User": "student"},
        json={"content_id": "hls-paid"},
    )
    assert payment.status_code == 200

    key = client.get(
        "/hls/secure-key",
        headers={"X-Lab-User": "student"},
    )
    assert key.status_code == 200
    assert len(key.data) == 16


def test_vulnerable_mock_license_skips_entitlement():
    client = app.test_client()

    response = client.post(
        "/mockdrm/vuln-license",
        headers={"X-Lab-User": "attacker"},
        json=_challenge(),
    )

    assert response.status_code == 200
    assert "wrapped_key_b64" in response.get_json()


def test_secure_mock_license_blocks_attacker():
    client = app.test_client()

    response = client.post(
        "/mockdrm/license",
        headers={"X-Lab-User": "attacker"},
        json=_challenge(),
    )

    assert response.status_code == 402
    assert response.get_json()["error"] == "payment_required"


def test_student_can_purchase_mock_entitlement_and_get_license():
    client = app.test_client()

    payment = client.post(
        "/pay",
        headers={"X-Lab-User": "student"},
        json={"content_id": "mock-paid"},
    )
    assert payment.status_code == 200
    assert "mock-paid" in USERS["student"]["entitlements"]

    license_response = client.post(
        "/mockdrm/license",
        headers={"X-Lab-User": "student"},
        json=_challenge(),
    )
    assert license_response.status_code == 200
    assert "wrapped_key_b64" in license_response.get_json()
