from __future__ import annotations

import os
import tempfile
from pathlib import Path

import requests
import telebot

from .config import lab_request_headers, validate_lab_base_url
from .controller import (
    buy_lab_entitlement,
    run_hls_demo,
    run_mock_drm_demo,
    verify_lab_identity,
)
from .ctf_client import (
    exploit_all_lab_episodes,
    fetch_ctf_catalog,
)

BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
LAB_BASE_URL = validate_lab_base_url(
    os.getenv("LAB_BASE_URL", "http://127.0.0.1:5000")
)
LAB_USER = os.getenv("LAB_USER", "student")

ALLOWED_USER_IDS = {
    int(value.strip())
    for value in os.getenv("ALLOWED_USER_IDS", "").split(",")
    if value.strip().isdigit()
}

if not ALLOWED_USER_IDS:
    raise RuntimeError(
        "ALLOWED_USER_IDS is mandatory for this cybersecurity lab bot"
    )

bot = telebot.TeleBot(BOT_TOKEN)


def _allowed(message) -> bool:
    return bool(
        message.from_user
        and message.from_user.id in ALLOWED_USER_IDS
    )


def _guard(message) -> bool:
    if _allowed(message):
        return True
    bot.reply_to(message, "⛔ இந்த lab bot private.")
    return False


def _send_audio_bytes(
    chat_id: int,
    data: bytes,
    *,
    filename: str,
    title: str,
    caption: str,
) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / filename
        path.write_bytes(data)

        with path.open("rb") as audio:
            bot.send_audio(
                chat_id,
                audio,
                title=title,
                performer="Unified DRM Cyber Lab",
                caption=caption,
            )


@bot.message_handler(commands=["start", "help"])
def start(message):
    if not _guard(message):
        return

    bot.reply_to(
        message,
        (
            "🧪 Unified DRM Cyber Lab\n\n"
            "/hlsdemo - AES-128 HLS lab demo\n"
            "/cdmdemo - mock CDM/license lab demo\n"
            "/securecheck - patched endpoints reject attacker\n"
            "/legitdemo - server-side payment + authorized playback\n"
            "/ctfshow - show all locked synthetic CTF episodes\n"
            "/attackall - recover every locked synthetic CTF episode\n"
            "/secureall - prove patched CTF path blocks attacker\n"
            "/compare - HLS vs mock CDM architecture\n"
            "/reset - reset lab credits/entitlements\n"
            "/health - verify lab target identity\n\n"
            "Local or explicitly authorized staging deployments of this lab only."
        ),
    )


@bot.message_handler(commands=["health"])
def health(message):
    if not _guard(message):
        return

    try:
        verify_lab_identity(LAB_BASE_URL)
        bot.reply_to(
            message,
            f"✅ Verified Unified DRM Cyber Lab target: {LAB_BASE_URL}",
        )
    except Exception as exc:
        bot.reply_to(message, f"❌ Lab unavailable/refused: {exc}")


@bot.message_handler(commands=["hlsdemo"])
def hls_demo(message):
    if not _guard(message):
        return

    status = bot.reply_to(
        message,
        "🔐 AES-128 HLS lab flow running...",
    )

    try:
        audio = run_hls_demo(LAB_BASE_URL)
        bot.edit_message_text(
            (
                "⚠️ Lab HLS key endpoint had no entitlement check.\n"
                "Bot fetched the lab key, decrypted HLS segments, "
                "and remuxed the synthetic audio."
            ),
            message.chat.id,
            status.message_id,
        )
        _send_audio_bytes(
            message.chat.id,
            audio,
            filename="hls_recovered.m4a",
            title="HLS AES-128 Lab Recovery",
            caption="🧪 Synthetic HLS lab sample",
        )
    except Exception as exc:
        bot.edit_message_text(
            f"❌ HLS demo failed: {str(exc)[:1000]}",
            message.chat.id,
            status.message_id,
        )


@bot.message_handler(commands=["cdmdemo"])
def cdm_demo(message):
    if not _guard(message):
        return

    status = bot.reply_to(
        message,
        "🔐 Mock CDM/license lab flow running...",
    )

    try:
        audio = run_mock_drm_demo(LAB_BASE_URL)
        bot.edit_message_text(
            (
                "⚠️ Lab vulnerable license endpoint validated the mock "
                "device challenge but skipped entitlement.\n"
                "The wrapped synthetic content key was returned and the "
                "lab audio was decrypted."
            ),
            message.chat.id,
            status.message_id,
        )
        _send_audio_bytes(
            message.chat.id,
            audio,
            filename="mock_cdm_recovered.mp3",
            title="Mock CDM Lab Recovery",
            caption="🧪 Synthetic mock license/CDM sample",
        )
    except Exception as exc:
        bot.edit_message_text(
            f"❌ Mock CDM demo failed: {str(exc)[:1000]}",
            message.chat.id,
            status.message_id,
        )


@bot.message_handler(commands=["securecheck"])
def secure_check(message):
    if not _guard(message):
        return

    results: list[str] = []

    try:
        run_hls_demo(
            LAB_BASE_URL,
            secure=True,
            user="attacker",
        )
        results.append("❌ Secure HLS unexpectedly allowed attacker")
    except requests.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else "?"
        results.append(f"✅ Secure HLS blocked attacker ({code})")
    except Exception as exc:
        results.append(f"⚠️ Secure HLS check error: {exc}")

    try:
        run_mock_drm_demo(
            LAB_BASE_URL,
            secure=True,
            user="attacker",
        )
        results.append("❌ Secure mock license unexpectedly allowed attacker")
    except requests.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else "?"
        results.append(f"✅ Secure mock license blocked attacker ({code})")
    except Exception as exc:
        results.append(f"⚠️ Secure mock check error: {exc}")

    bot.reply_to(message, "\n".join(results))


@bot.message_handler(commands=["legitdemo"])
def legit_demo(message):
    if not _guard(message):
        return

    try:
        buy_lab_entitlement(
            LAB_BASE_URL,
            user=LAB_USER,
            content_id="hls-paid",
        )
        buy_lab_entitlement(
            LAB_BASE_URL,
            user=LAB_USER,
            content_id="mock-paid",
        )

        hls_audio = run_hls_demo(
            LAB_BASE_URL,
            secure=True,
            user=LAB_USER,
        )
        mock_audio = run_mock_drm_demo(
            LAB_BASE_URL,
            secure=True,
            user=LAB_USER,
        )

        bot.reply_to(
            message,
            (
                "✅ Server-side entitlements created. "
                "Both secure flows are now authorized."
            ),
        )

        _send_audio_bytes(
            message.chat.id,
            hls_audio,
            filename="authorized_hls.m4a",
            title="Authorized HLS Lab Playback",
            caption="✅ Secure HLS entitlement flow",
        )
        _send_audio_bytes(
            message.chat.id,
            mock_audio,
            filename="authorized_mock.mp3",
            title="Authorized Mock CDM Playback",
            caption="✅ Secure mock license/CDM flow",
        )

    except Exception as exc:
        bot.reply_to(message, f"❌ Legit demo failed: {str(exc)[:1000]}")



@bot.message_handler(commands=["ctfshow"])
def ctf_show(message):
    if not _guard(message):
        return

    try:
        payload = fetch_ctf_catalog(LAB_BASE_URL)
        lines = [
            f"🔒 {episode['id']:02d}. {episode['title']}"
            for episode in payload["episodes"]
        ]
        bot.reply_to(
            message,
            "🎓 Unlimited Unlock CTF\n"
            f"Locked episodes: {len(lines)}\n\n"
            + "\n".join(lines),
        )
    except Exception as exc:
        bot.reply_to(message, f"❌ CTF catalog failed: {str(exc)[:1000]}")


@bot.message_handler(commands=["attackall"])
def attack_all(message):
    if not _guard(message):
        return

    status = bot.reply_to(
        message,
        "🧪 Recovering all locked synthetic CTF episodes...",
    )

    try:
        recovered = exploit_all_lab_episodes(LAB_BASE_URL)
        bot.edit_message_text(
            (
                f"⚠️ CTF vulnerable path recovered {len(recovered)} locked episodes.\n"
                "This demonstrates missing entitlement + predictable token + "
                "raw lab-key exposure against synthetic content only."
            ),
            message.chat.id,
            status.message_id,
        )

        for episode, audio in recovered:
            _send_audio_bytes(
                message.chat.id,
                audio,
                filename=f"ctf_ep_{int(episode['id']):02d}.mp3",
                title=episode["title"],
                caption=(
                    f"🧪 CTF recovered episode {episode['id']} "
                    "(synthetic lab content)"
                ),
            )

    except Exception as exc:
        bot.edit_message_text(
            f"❌ CTF attack-all failed: {str(exc)[:1000]}",
            message.chat.id,
            status.message_id,
        )


@bot.message_handler(commands=["secureall"])
def secure_all(message):
    if not _guard(message):
        return

    try:
        payload = fetch_ctf_catalog(LAB_BASE_URL)
        blocked = 0
        unexpected = 0

        for episode in payload["episodes"]:
            response = requests.get(
                f"{LAB_BASE_URL}/ctf/secure/media/{episode['id']}",
                headers=lab_request_headers("attacker"),
                timeout=15,
            )
            if response.status_code == 402:
                blocked += 1
            else:
                unexpected += 1

        bot.reply_to(
            message,
            (
                f"✅ Secure CTF path blocked: {blocked}/{len(payload['episodes'])}\n"
                f"Unexpected allows: {unexpected}\n"
                "Server-side entitlement is checked for every episode."
            ),
        )
    except Exception as exc:
        bot.reply_to(message, f"❌ Secure-all check failed: {str(exc)[:1000]}")


@bot.message_handler(commands=["compare"])
def compare(message):
    if not _guard(message):
        return

    bot.reply_to(
        message,
        (
            "HLS AES-128 LAB\n"
            "Manifest: M3U8 + EXT-X-KEY\n"
            "Key path: key URI\n"
            "Crypto: AES-128-CBC per segment\n"
            "Failure demo: key endpoint lacks entitlement\n\n"
            "MOCK CDM/LICENSE LAB\n"
            "Manifest: MPD + PSSH-like metadata\n"
            "Key path: license response\n"
            "Device concept: signed mock CDM challenge\n"
            "Media crypto: AES-GCM synthetic payload\n"
            "Failure demo: license endpoint skips entitlement\n\n"
            "Both use only generated synthetic content."
        ),
    )


@bot.message_handler(commands=["reset"])
def reset(message):
    if not _guard(message):
        return

    try:
        response = requests.post(
            f"{LAB_BASE_URL}/reset",
            headers=lab_request_headers(LAB_USER),
            timeout=10,
        )
        response.raise_for_status()
        bot.reply_to(message, "✅ Lab state reset.")
    except Exception as exc:
        bot.reply_to(message, f"❌ Reset failed: {exc}")


if __name__ == "__main__":
    print(f"Unified DRM Cyber Lab bot started; target={LAB_BASE_URL}")
    bot.infinity_polling(
        timeout=30,
        long_polling_timeout=30,
        skip_pending=True,
    )
