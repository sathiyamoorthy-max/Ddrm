from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import DATA_DIR

CTF_DIR = DATA_DIR / "ctf"
CATALOG_PATH = CTF_DIR / "catalog.json"
EPISODE_COUNT = 12


def _ffmpeg() -> str:
    exe = shutil.which("ffmpeg")
    if not exe:
        raise RuntimeError("ffmpeg is required for the CTF lab")
    return exe


def _episode_paths(episode_id: int) -> tuple[Path, Path]:
    return (
        CTF_DIR / f"ep{episode_id:02d}.enc",
        CTF_DIR / f"ep{episode_id:02d}.key.json",
    )


def ensure_ctf_assets() -> None:
    CTF_DIR.mkdir(parents=True, exist_ok=True)

    if CATALOG_PATH.exists():
        catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
        if len(catalog.get("episodes", [])) == EPISODE_COUNT:
            complete = all(
                all(path.exists() for path in _episode_paths(ep["id"]))
                for ep in catalog["episodes"]
            )
            if complete:
                return

    episodes: list[dict] = []

    for episode_id in range(1, EPISODE_COUNT + 1):
        clear_path = CTF_DIR / f"ep{episode_id:02d}.mp3"
        enc_path, key_path = _episode_paths(episode_id)

        frequency = 400 + episode_id * 35
        subprocess.run(
            [
                _ffmpeg(),
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-f",
                "lavfi",
                "-i",
                f"sine=frequency={frequency}:duration=2",
                "-c:a",
                "libmp3lame",
                "-q:a",
                "5",
                str(clear_path),
            ],
            check=True,
        )

        content_id = f"ctf-episode-{episode_id:02d}"
        key = AESGCM.generate_key(bit_length=128)
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(
            nonce,
            clear_path.read_bytes(),
            content_id.encode("utf-8"),
        )

        enc_path.write_bytes(nonce + ciphertext)
        key_path.write_text(
            json.dumps(
                {
                    "content_id": content_id,
                    "key_b64": base64.b64encode(key).decode("ascii"),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        clear_path.unlink(missing_ok=True)

        episodes.append(
            {
                "id": episode_id,
                "content_id": content_id,
                "title": f"Locked Lab Episode {episode_id}",
                "locked": True,
            }
        )

    CATALOG_PATH.write_text(
        json.dumps(
            {
                "show": "Unlimited Unlock CTF",
                "episode_count": EPISODE_COUNT,
                "episodes": episodes,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def catalog() -> dict:
    ensure_ctf_assets()
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def vulnerable_token(episode_id: int) -> str:
    return f"ctf-{episode_id:02d}-predictable-token"


def load_episode_ciphertext(episode_id: int) -> bytes:
    ensure_ctf_assets()
    enc_path, _ = _episode_paths(episode_id)
    if not enc_path.exists():
        raise KeyError(episode_id)
    return enc_path.read_bytes()


def load_episode_key_material(episode_id: int) -> dict[str, str]:
    ensure_ctf_assets()
    _, key_path = _episode_paths(episode_id)
    if not key_path.exists():
        raise KeyError(episode_id)
    return json.loads(key_path.read_text(encoding="utf-8"))


def decrypt_episode(
    episode_id: int,
    encrypted: bytes,
    key_b64: str,
) -> bytes:
    metadata = load_episode_key_material(episode_id)
    content_id = metadata["content_id"]
    key = base64.b64decode(key_b64)
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]

    return AESGCM(key).decrypt(
        nonce,
        ciphertext,
        content_id.encode("utf-8"),
    )
