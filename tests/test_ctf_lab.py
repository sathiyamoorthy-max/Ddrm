from __future__ import annotations

import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.ctf_lab import (
    EPISODE_COUNT,
    catalog,
    ensure_ctf_assets,
    load_episode_ciphertext,
    load_episode_key_material,
)
from app.server import app, reset_state


def setup_function():
    reset_state()


def test_ctf_catalog_lists_all_episodes_locked():
    ensure_ctf_assets()
    payload = catalog()

    assert payload["episode_count"] == EPISODE_COUNT
    assert len(payload["episodes"]) == EPISODE_COUNT
    assert all(ep["locked"] is True for ep in payload["episodes"])


def test_ctf_vulnerable_unlock_allows_locked_episode_without_entitlement():
    client = app.test_client()

    response = client.post("/ctf/vuln/unlock/1")

    assert response.status_code == 200
    body = response.get_json()
    assert body["unlocked"] is True
    assert body["playback_token"]


def test_ctf_vulnerable_media_and_key_recover_synthetic_episode():
    client = app.test_client()

    unlock = client.post("/ctf/vuln/unlock/1").get_json()
    token = unlock["playback_token"]

    media = client.get(
        "/ctf/vuln/media/1",
        query_string={"token": token},
    )
    key_response = client.get(
        "/ctf/vuln/key/1",
        query_string={"token": token},
    )

    assert media.status_code == 200
    assert key_response.status_code == 200

    material = load_episode_key_material(1)
    content_id = material["content_id"]
    key = base64.b64decode(key_response.get_json()["key_b64"])
    encrypted = media.data

    clear = AESGCM(key).decrypt(
        encrypted[:12],
        encrypted[12:],
        content_id.encode("utf-8"),
    )

    assert len(clear) > 100
    assert clear[:3] == b"ID3" or clear[0] == 0xFF


def test_ctf_secure_path_blocks_every_locked_episode_for_attacker():
    client = app.test_client()

    for episode_id in range(1, EPISODE_COUNT + 1):
        response = client.get(
            f"/ctf/secure/media/{episode_id}",
            headers={"X-Lab-User": "attacker"},
        )
        assert response.status_code == 402
        assert response.get_json()["error"] == "payment_required"


def test_ctf_invalid_predictable_token_is_rejected():
    client = app.test_client()

    response = client.get(
        "/ctf/vuln/media/1",
        query_string={"token": "wrong"},
    )

    assert response.status_code == 403
