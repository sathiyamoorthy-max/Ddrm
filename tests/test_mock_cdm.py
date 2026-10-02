from __future__ import annotations

from app.assets import (
    MOCK_MEDIA_PATH,
    MOCK_MPD_PATH,
    ensure_mock_assets,
    load_mock_content_key,
)
from app.mock_cdm import (
    create_license_challenge,
    create_license_response,
    decrypt_mock_media,
    parse_mock_mpd,
    unwrap_license_key,
    verify_license_challenge,
)


def test_mock_pssh_challenge_license_and_decryption_roundtrip():
    ensure_mock_assets()

    manifest = parse_mock_mpd(
        MOCK_MPD_PATH.read_text(encoding="utf-8")
    )
    challenge = create_license_challenge(manifest.pssh_b64)

    assert verify_license_challenge(challenge)

    original_key = load_mock_content_key()
    license_response = create_license_response(
        challenge,
        original_key,
    )
    recovered_key = unwrap_license_key(
        challenge,
        license_response,
    )

    assert recovered_key == original_key

    clear = decrypt_mock_media(
        MOCK_MEDIA_PATH.read_bytes(),
        recovered_key,
        manifest.content_id,
    )

    assert len(clear) > 100
    assert clear[:3] == b"ID3" or clear[0] == 0xFF


def test_tampered_mock_challenge_is_rejected():
    ensure_mock_assets()

    manifest = parse_mock_mpd(
        MOCK_MPD_PATH.read_text(encoding="utf-8")
    )
    challenge = create_license_challenge(manifest.pssh_b64)
    challenge["content_id"] = "tampered"

    assert not verify_license_challenge(challenge)
