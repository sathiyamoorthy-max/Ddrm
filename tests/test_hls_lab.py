from __future__ import annotations

from app.assets import (
    HLS_DIR,
    HLS_IV_HEX,
    HLS_KEY_PATH,
    HLS_PLAYLIST_PATH,
    ensure_hls_assets,
)
from app.hls_lab import decrypt_aes128_cbc, parse_hls_playlist


def test_generated_hls_playlist_has_aes128_key_and_segments():
    ensure_hls_assets()

    playlist = parse_hls_playlist(
        HLS_PLAYLIST_PATH.read_text(encoding="utf-8")
    )

    assert playlist.key_uri == "/hls/key"
    assert playlist.iv.hex().upper() == HLS_IV_HEX
    assert len(playlist.segments) >= 1


def test_generated_hls_segment_decrypts_to_mpeg_ts():
    ensure_hls_assets()

    playlist = parse_hls_playlist(
        HLS_PLAYLIST_PATH.read_text(encoding="utf-8")
    )
    key = HLS_KEY_PATH.read_bytes()
    encrypted = (HLS_DIR / playlist.segments[0]).read_bytes()

    clear = decrypt_aes128_cbc(
        encrypted,
        key,
        playlist.iv,
    )

    assert len(clear) > 188
    assert clear[0] == 0x47
