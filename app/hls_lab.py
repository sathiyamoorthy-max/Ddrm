from __future__ import annotations

import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin

import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .config import validate_lab_base_url


@dataclass(frozen=True)
class HLSPlaylist:
    key_uri: str
    iv: bytes
    segments: tuple[str, ...]


_ATTR_RE = re.compile(r'([A-Z0-9-]+)=("[^"]*"|[^,]*)')


def _parse_attrs(raw: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for key, value in _ATTR_RE.findall(raw):
        value = value.strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        attrs[key] = value
    return attrs


def parse_hls_playlist(text: str) -> HLSPlaylist:
    key_uri: str | None = None
    iv: bytes | None = None
    segments: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("#EXT-X-KEY:"):
            attrs = _parse_attrs(line.split(":", 1)[1])
            if attrs.get("METHOD") != "AES-128":
                raise ValueError("lab supports only AES-128 HLS")
            key_uri = attrs.get("URI")
            raw_iv = attrs.get("IV", "")
            if raw_iv.lower().startswith("0x"):
                raw_iv = raw_iv[2:]
            if not raw_iv:
                raise ValueError("lab playlist must contain an explicit IV")
            iv = bytes.fromhex(raw_iv)
            if len(iv) != 16:
                raise ValueError("AES-128 HLS IV must be 16 bytes")
            continue

        if not line.startswith("#"):
            segments.append(line)

    if not key_uri:
        raise ValueError("AES-128 key URI not found")
    if iv is None:
        raise ValueError("AES-128 IV not found")
    if not segments:
        raise ValueError("playlist contains no media segments")

    return HLSPlaylist(key_uri=key_uri, iv=iv, segments=tuple(segments))


def decrypt_aes128_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes")

    decryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
    ).decryptor()

    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def download_and_decrypt_hls(
    playlist_url: str,
    *,
    headers: dict[str, str] | None = None,
    session: requests.Session | None = None,
) -> bytes:
    base = playlist_url.split("/hls/", 1)[0]
    validate_lab_base_url(base)

    http = session or requests.Session()
    response = http.get(playlist_url, headers=headers, timeout=15)
    response.raise_for_status()

    playlist = parse_hls_playlist(response.text)
    key_url = urljoin(playlist_url, playlist.key_uri)

    key_response = http.get(key_url, headers=headers, timeout=15)
    key_response.raise_for_status()
    key = key_response.content

    clear_segments: list[bytes] = []
    for relative_uri in playlist.segments:
        segment_url = urljoin(playlist_url, relative_uri)
        segment = http.get(segment_url, headers=headers, timeout=15)
        segment.raise_for_status()
        clear_segments.append(
            decrypt_aes128_cbc(segment.content, key, playlist.iv)
        )

    return b"".join(clear_segments)


def remux_ts_to_m4a(ts_bytes: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        source = root / "combined.ts"
        output = root / "recovered.m4a"
        source.write_bytes(ts_bytes)

        subprocess.run(
            [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-i",
                str(source),
                "-vn",
                "-c:a",
                "copy",
                str(output),
            ],
            check=True,
        )

        return output.read_bytes()
