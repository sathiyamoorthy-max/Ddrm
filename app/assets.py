from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import DATA_DIR

HLS_DIR = DATA_DIR / "hls"
MOCK_DIR = DATA_DIR / "mockdrm"

HLS_KEY_PATH = HLS_DIR / "enc.key"
HLS_PLAYLIST_PATH = HLS_DIR / "playlist.m3u8"
HLS_IV_HEX = "00112233445566778899AABBCCDDEEFF"

MOCK_CLEAR_PATH = MOCK_DIR / "clear.mp3"
MOCK_MEDIA_PATH = MOCK_DIR / "media.enc"
MOCK_KEY_PATH = MOCK_DIR / "content_key.json"
MOCK_MPD_PATH = MOCK_DIR / "manifest.mpd"
MOCK_CONTENT_ID = "mock-paid"
MOCK_KEY_ID = "mock-key-001"


def _ffmpeg() -> str:
    exe = shutil.which("ffmpeg")
    if not exe:
        raise RuntimeError("ffmpeg is required for the lab")
    return exe


def _run_ffmpeg(args: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(
        [_ffmpeg(), "-hide_banner", "-loglevel", "error", "-y", *args],
        cwd=str(cwd) if cwd else None,
        check=True,
    )


def ensure_hls_assets() -> None:
    HLS_DIR.mkdir(parents=True, exist_ok=True)

    if HLS_PLAYLIST_PATH.exists() and HLS_KEY_PATH.exists():
        segments = list(HLS_DIR.glob("seg*.ts"))
        if segments:
            return

    for old in HLS_DIR.glob("*"):
        if old.is_file():
            old.unlink()

    HLS_KEY_PATH.write_bytes(os.urandom(16))

    key_info = HLS_DIR / "key_info.txt"
    key_info.write_text(
        "\n".join(
            [
                "/hls/key",
                str(HLS_KEY_PATH),
                HLS_IV_HEX,
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    _run_ffmpeg(
        [
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=523:duration=8",
            "-c:a",
            "aac",
            "-b:a",
            "96k",
            "-f",
            "hls",
            "-hls_time",
            "2",
            "-hls_list_size",
            "0",
            "-hls_segment_filename",
            "seg%03d.ts",
            "-hls_key_info_file",
            str(key_info),
            "playlist.m3u8",
        ],
        cwd=HLS_DIR,
    )

    key_info.unlink(missing_ok=True)


def _ensure_mock_clear_audio() -> None:
    MOCK_DIR.mkdir(parents=True, exist_ok=True)
    if MOCK_CLEAR_PATH.exists():
        return

    _run_ffmpeg(
        [
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=660:duration=7",
            "-c:a",
            "libmp3lame",
            "-q:a",
            "4",
            str(MOCK_CLEAR_PATH),
        ]
    )


def _mock_pssh() -> str:
    payload = {
        "system": "mock-widevine",
        "content_id": MOCK_CONTENT_ID,
        "key_id": MOCK_KEY_ID,
        "note": "synthetic educational PSSH-like payload",
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def ensure_mock_assets() -> None:
    MOCK_DIR.mkdir(parents=True, exist_ok=True)
    _ensure_mock_clear_audio()

    if MOCK_MEDIA_PATH.exists() and MOCK_KEY_PATH.exists() and MOCK_MPD_PATH.exists():
        return

    key = AESGCM.generate_key(bit_length=128)
    nonce = os.urandom(12)
    clear = MOCK_CLEAR_PATH.read_bytes()
    ciphertext = AESGCM(key).encrypt(
        nonce,
        clear,
        MOCK_CONTENT_ID.encode("utf-8"),
    )

    MOCK_MEDIA_PATH.write_bytes(nonce + ciphertext)
    MOCK_KEY_PATH.write_text(
        json.dumps(
            {
                "content_id": MOCK_CONTENT_ID,
                "key_id": MOCK_KEY_ID,
                "key_b64": base64.b64encode(key).decode("ascii"),
                "sha256": hashlib.sha256(clear).hexdigest(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    mpd = f"""<?xml version="1.0" encoding="UTF-8"?>
<MPD xmlns:cenc="urn:mpeg:cenc:2013" type="static">
  <Period>
    <AdaptationSet contentType="audio">
      <ContentProtection schemeIdUri="urn:example:mock-widevine">
        <cenc:pssh>{_mock_pssh()}</cenc:pssh>
      </ContentProtection>
      <Representation id="audio-1">
        <BaseURL>/mockdrm/media</BaseURL>
      </Representation>
    </AdaptationSet>
  </Period>
  <SupplementalProperty
      schemeIdUri="urn:example:mock-license"
      value="/mockdrm/license" />
</MPD>
"""
    MOCK_MPD_PATH.write_text(mpd, encoding="utf-8")


def load_mock_content_key() -> bytes:
    ensure_mock_assets()
    payload = json.loads(MOCK_KEY_PATH.read_text(encoding="utf-8"))
    return base64.b64decode(payload["key_b64"])


def load_mock_key_metadata() -> dict[str, str]:
    ensure_mock_assets()
    return json.loads(MOCK_KEY_PATH.read_text(encoding="utf-8"))


def ensure_all_assets() -> None:
    ensure_hls_assets()
    ensure_mock_assets()
