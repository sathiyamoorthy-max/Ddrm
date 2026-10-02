from __future__ import annotations

import argparse
from urllib.parse import urljoin

import requests

from .config import validate_lab_base_url
from .hls_lab import download_and_decrypt_hls, remux_ts_to_m4a
from .mock_cdm import (
    create_license_challenge,
    decrypt_mock_media,
    parse_mock_mpd,
    unwrap_license_key,
)


def run_hls_demo(
    base_url: str,
    *,
    secure: bool = False,
    user: str | None = None,
) -> bytes:
    base_url = validate_lab_base_url(base_url)
    headers = {"X-Lab-User": user} if user else None
    suffix = "?mode=secure" if secure else ""

    ts_bytes = download_and_decrypt_hls(
        f"{base_url}/hls/playlist.m3u8{suffix}",
        headers=headers,
    )
    return remux_ts_to_m4a(ts_bytes)


def run_mock_drm_demo(
    base_url: str,
    *,
    secure: bool = False,
    user: str | None = None,
) -> bytes:
    base_url = validate_lab_base_url(base_url)
    headers = {"X-Lab-User": user} if user else {}

    manifest_response = requests.get(
        f"{base_url}/mockdrm/manifest.mpd",
        headers=headers,
        timeout=15,
    )
    manifest_response.raise_for_status()
    manifest = parse_mock_mpd(manifest_response.text)

    challenge = create_license_challenge(manifest.pssh_b64)
    license_path = manifest.license_path if secure else "/mockdrm/vuln-license"

    license_response = requests.post(
        urljoin(base_url + "/", license_path.lstrip("/")),
        json=challenge,
        headers=headers,
        timeout=15,
    )
    license_response.raise_for_status()

    content_key = unwrap_license_key(
        challenge,
        license_response.json(),
    )

    media_response = requests.get(
        urljoin(base_url + "/", manifest.media_path.lstrip("/")),
        headers=headers,
        timeout=15,
    )
    media_response.raise_for_status()

    return decrypt_mock_media(
        media_response.content,
        content_key,
        manifest.content_id,
    )


def buy_lab_entitlement(
    base_url: str,
    *,
    user: str,
    content_id: str,
) -> dict:
    base_url = validate_lab_base_url(base_url)
    response = requests.post(
        f"{base_url}/pay",
        json={"content_id": content_id},
        headers={"X-Lab-User": user},
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def _main() -> None:
    parser = argparse.ArgumentParser(description="Unified DRM Cyber Lab controller")
    parser.add_argument(
        "mode",
        choices=["hls", "mock", "secure-hls", "secure-mock"],
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:5000",
    )
    parser.add_argument("--user", default="student")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    if args.mode == "hls":
        data = run_hls_demo(args.base_url)
    elif args.mode == "mock":
        data = run_mock_drm_demo(args.base_url)
    elif args.mode == "secure-hls":
        data = run_hls_demo(args.base_url, secure=True, user=args.user)
    else:
        data = run_mock_drm_demo(args.base_url, secure=True, user=args.user)

    with open(args.output, "wb") as fh:
        fh.write(data)


if __name__ == "__main__":
    _main()
