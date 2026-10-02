from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_file

from .assets import (
    HLS_DIR,
    HLS_KEY_PATH,
    HLS_PLAYLIST_PATH,
    MOCK_CONTENT_ID,
    MOCK_MEDIA_PATH,
    MOCK_MPD_PATH,
    ensure_hls_assets,
    ensure_mock_assets,
    load_mock_content_key,
)
from .mock_cdm import (
    create_license_response,
    verify_license_challenge,
)

app = Flask(__name__)

CONTENT_IDS = {"hls-paid", MOCK_CONTENT_ID}

USERS = {
    "student": {
        "credits": 2,
        "entitlements": set(),
    },
    "attacker": {
        "credits": 0,
        "entitlements": set(),
    },
}


def reset_state() -> None:
    USERS["student"]["credits"] = 2
    USERS["student"]["entitlements"].clear()
    USERS["attacker"]["credits"] = 0
    USERS["attacker"]["entitlements"].clear()


def _lab_user():
    name = request.headers.get("X-Lab-User", "")
    return name, USERS.get(name)


def _has_entitlement(user: dict | None, content_id: str) -> bool:
    return bool(user and content_id in user["entitlements"])


@app.get("/health")
def health():
    return jsonify(
        {
            "ok": True,
            "project": "Unified DRM Cyber Lab",
            "scope": "synthetic-local-content-only",
        }
    )


@app.post("/reset")
def reset():
    name, user = _lab_user()
    if name != "student" or not user:
        return jsonify({"error": "student_identity_required"}), 403

    reset_state()
    return jsonify({"reset": True})


@app.post("/pay")
def pay():
    payload = request.get_json(silent=True) or {}
    content_id = str(payload.get("content_id", ""))

    if content_id not in CONTENT_IDS:
        return jsonify({"error": "unknown_content"}), 404

    name, user = _lab_user()
    if not user:
        return jsonify({"error": "unknown_lab_user"}), 401

    if content_id in user["entitlements"]:
        return jsonify(
            {
                "paid": True,
                "already_entitled": True,
                "content_id": content_id,
                "credits": user["credits"],
                "user": name,
            }
        )

    if user["credits"] < 1:
        return jsonify({"error": "insufficient_credits"}), 402

    user["credits"] -= 1
    user["entitlements"].add(content_id)

    return jsonify(
        {
            "paid": True,
            "content_id": content_id,
            "credits": user["credits"],
            "user": name,
        }
    )


@app.get("/hls/playlist.m3u8")
def hls_playlist():
    ensure_hls_assets()
    text = HLS_PLAYLIST_PATH.read_text(encoding="utf-8")

    if request.args.get("mode") == "secure":
        text = text.replace('URI="/hls/key"', 'URI="/hls/secure-key"')

    return Response(
        text,
        mimetype="application/vnd.apple.mpegurl",
    )


@app.get("/hls/key")
def hls_insecure_key():
    """
    Intentionally vulnerable local endpoint:
    the AES-128 key is returned without entitlement validation.
    """
    ensure_hls_assets()
    return Response(
        HLS_KEY_PATH.read_bytes(),
        mimetype="application/octet-stream",
        headers={"X-Lab-Warning": "intentionally-exposed-local-key"},
    )


@app.get("/hls/secure-key")
def hls_secure_key():
    ensure_hls_assets()
    _name, user = _lab_user()

    if not _has_entitlement(user, "hls-paid"):
        return jsonify({"error": "payment_required"}), 402

    return Response(
        HLS_KEY_PATH.read_bytes(),
        mimetype="application/octet-stream",
    )


@app.get("/hls/<path:filename>")
def hls_segment(filename: str):
    ensure_hls_assets()

    if not filename.startswith("seg") or not filename.endswith(".ts"):
        return jsonify({"error": "not_found"}), 404

    path = (HLS_DIR / filename).resolve()
    if path.parent != HLS_DIR.resolve() or not path.exists():
        return jsonify({"error": "not_found"}), 404

    return send_file(path, mimetype="video/mp2t")


@app.get("/mockdrm/manifest.mpd")
def mock_manifest():
    ensure_mock_assets()
    return Response(
        MOCK_MPD_PATH.read_text(encoding="utf-8"),
        mimetype="application/dash+xml",
    )


@app.get("/mockdrm/media")
def mock_media():
    ensure_mock_assets()
    return send_file(
        MOCK_MEDIA_PATH,
        mimetype="application/octet-stream",
        download_name="mock_paid_audio.enc",
    )


def _validated_challenge():
    challenge = request.get_json(silent=True) or {}

    if not verify_license_challenge(challenge):
        return None, (jsonify({"error": "invalid_mock_cdm_challenge"}), 400)

    if challenge.get("content_id") != MOCK_CONTENT_ID:
        return None, (jsonify({"error": "content_mismatch"}), 400)

    return challenge, None


@app.post("/mockdrm/vuln-license")
def vulnerable_mock_license():
    """
    Intentionally vulnerable local endpoint:
    a valid mock device challenge is enough; entitlement is not checked.
    """
    ensure_mock_assets()
    challenge, error = _validated_challenge()
    if error:
        return error

    response = create_license_response(
        challenge,
        load_mock_content_key(),
    )
    response["warning"] = "entitlement check intentionally omitted in local lab"
    return jsonify(response)


@app.post("/mockdrm/license")
def secure_mock_license():
    ensure_mock_assets()
    challenge, error = _validated_challenge()
    if error:
        return error

    _name, user = _lab_user()
    if not _has_entitlement(user, MOCK_CONTENT_ID):
        return jsonify({"error": "payment_required"}), 402

    return jsonify(
        create_license_response(
            challenge,
            load_mock_content_key(),
        )
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5000")),
        debug=False,
    )
