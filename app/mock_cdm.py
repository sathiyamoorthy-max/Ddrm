from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEVICE_ID = "college-lab-device-001"
DEVICE_SECRET = hashlib.sha256(
    b"unified-drm-cyber-lab-device-secret"
).digest()


@dataclass(frozen=True)
class MockManifest:
    pssh_b64: str
    media_path: str
    license_path: str
    content_id: str
    key_id: str


def decode_pssh(pssh_b64: str) -> dict[str, str]:
    raw = base64.b64decode(pssh_b64)
    payload = json.loads(raw.decode("utf-8"))
    if payload.get("system") != "mock-widevine":
        raise ValueError("unsupported mock DRM system")
    return payload


def parse_mock_mpd(text: str) -> MockManifest:
    root = ET.fromstring(text)

    pssh_text: str | None = None
    media_path: str | None = None
    license_path: str | None = None

    for node in root.iter():
        tag = node.tag.rsplit("}", 1)[-1]

        if tag == "pssh" and node.text:
            pssh_text = node.text.strip()
        elif tag == "BaseURL" and node.text:
            media_path = node.text.strip()
        elif tag == "SupplementalProperty":
            if node.attrib.get("schemeIdUri") == "urn:example:mock-license":
                license_path = node.attrib.get("value")

    if not pssh_text or not media_path or not license_path:
        raise ValueError("mock MPD is missing required lab fields")

    pssh = decode_pssh(pssh_text)

    return MockManifest(
        pssh_b64=pssh_text,
        media_path=media_path,
        license_path=license_path,
        content_id=pssh["content_id"],
        key_id=pssh["key_id"],
    )


def _challenge_message(device_id: str, content_id: str, nonce_b64: str) -> bytes:
    return f"{device_id}|{content_id}|{nonce_b64}".encode("utf-8")


def create_license_challenge(pssh_b64: str) -> dict[str, str]:
    payload = decode_pssh(pssh_b64)
    nonce_b64 = base64.b64encode(os.urandom(16)).decode("ascii")
    message = _challenge_message(
        DEVICE_ID,
        payload["content_id"],
        nonce_b64,
    )
    signature = hmac.new(
        DEVICE_SECRET,
        message,
        hashlib.sha256,
    ).digest()

    return {
        "device_id": DEVICE_ID,
        "content_id": payload["content_id"],
        "key_id": payload["key_id"],
        "nonce_b64": nonce_b64,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }


def verify_license_challenge(challenge: dict[str, str]) -> bool:
    try:
        message = _challenge_message(
            challenge["device_id"],
            challenge["content_id"],
            challenge["nonce_b64"],
        )
        supplied = base64.b64decode(challenge["signature_b64"])
    except (KeyError, ValueError):
        return False

    expected = hmac.new(
        DEVICE_SECRET,
        message,
        hashlib.sha256,
    ).digest()

    return (
        challenge.get("device_id") == DEVICE_ID
        and hmac.compare_digest(expected, supplied)
    )


def _wrap_key(challenge: dict[str, str]) -> bytes:
    challenge_nonce = base64.b64decode(challenge["nonce_b64"])
    return hashlib.sha256(
        DEVICE_SECRET + challenge_nonce + challenge["content_id"].encode("utf-8")
    ).digest()


def create_license_response(
    challenge: dict[str, str],
    content_key: bytes,
) -> dict[str, str]:
    if not verify_license_challenge(challenge):
        raise ValueError("invalid mock CDM challenge")

    wrap_nonce = os.urandom(12)
    wrapped = AESGCM(_wrap_key(challenge)).encrypt(
        wrap_nonce,
        content_key,
        challenge["content_id"].encode("utf-8"),
    )

    return {
        "license_id": base64.urlsafe_b64encode(os.urandom(12)).decode("ascii"),
        "content_id": challenge["content_id"],
        "key_id": challenge["key_id"],
        "wrap_nonce_b64": base64.b64encode(wrap_nonce).decode("ascii"),
        "wrapped_key_b64": base64.b64encode(wrapped).decode("ascii"),
        "note": "mock license response for synthetic local content",
    }


def unwrap_license_key(
    challenge: dict[str, str],
    license_response: dict[str, str],
) -> bytes:
    if license_response.get("content_id") != challenge.get("content_id"):
        raise ValueError("license content mismatch")

    nonce = base64.b64decode(license_response["wrap_nonce_b64"])
    wrapped = base64.b64decode(license_response["wrapped_key_b64"])

    return AESGCM(_wrap_key(challenge)).decrypt(
        nonce,
        wrapped,
        challenge["content_id"].encode("utf-8"),
    )


def decrypt_mock_media(
    encrypted_media: bytes,
    content_key: bytes,
    content_id: str,
) -> bytes:
    if len(encrypted_media) <= 12:
        raise ValueError("encrypted mock media is truncated")

    nonce = encrypted_media[:12]
    ciphertext = encrypted_media[12:]

    return AESGCM(content_key).decrypt(
        nonce,
        ciphertext,
        content_id.encode("utf-8"),
    )
