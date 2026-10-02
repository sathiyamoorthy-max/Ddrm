# Authorized Staging Test Mode

This mode lets the Telegram bot/controller test a **remote deployment of this same synthetic Ddrm lab** over HTTPS.

It is not a generic DRM target mode. Do not put PocketFM/OTT license servers, real PSSH values, WVD/CDM files, cookies, account tokens, or third-party content-key endpoints into this configuration.

## 1. Deploy the lab server you control

Deploy this repository's `app.server` behind HTTPS on a hostname you control, for example:

```text
https://ddrm-lab.example.edu
```

Set a strong gateway secret on the server:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Example server environment:

```env
PORT=5000
LAB_GATEWAY_TOKEN=PASTE_THE_RANDOM_SECRET_HERE
```

The gateway token protects the intentionally vulnerable educational endpoints from unauthenticated internet access.

## 2. Verify the deployed lab identity

From your own machine:

```bash
export LAB_GATEWAY_TOKEN="PASTE_THE_RANDOM_SECRET_HERE"

curl \
  -H "Authorization: Bearer $LAB_GATEWAY_TOKEN" \
  https://ddrm-lab.example.edu/health
```

Expected response:

```json
{
  "ok": true,
  "project": "Unified DRM Cyber Lab",
  "scope": "synthetic-local-content-only"
}
```

The controller refuses a remote target if these project/scope markers do not match.

## 3. Configure the Telegram bot/controller

Use the same gateway secret:

```env
TELEGRAM_BOT_TOKEN=YOUR_BOTFATHER_TOKEN
ALLOWED_USER_IDS=YOUR_TELEGRAM_NUMERIC_ID
LAB_USER=student

LAB_EXTERNAL_TEST_MODE=1
LAB_ALLOWED_HOSTS=ddrm-lab.example.edu
LAB_BASE_URL=https://ddrm-lab.example.edu
LAB_GATEWAY_TOKEN=PASTE_THE_SAME_RANDOM_SECRET_HERE
```

Rules enforced by the code:

- external mode must be explicitly enabled;
- remote URL must use HTTPS;
- hostname must exactly match `LAB_ALLOWED_HOSTS`;
- `LAB_GATEWAY_TOKEN` is mandatory;
- embedded URL credentials are rejected;
- query strings/fragments in `LAB_BASE_URL` are rejected;
- `/health` must identify the target as this synthetic lab.

Multiple lab hosts can be comma-separated:

```env
LAB_ALLOWED_HOSTS=lab1.example.edu,lab2.example.edu
```

## 4. Run the bot

```bash
python -m app.telegram_bot
```

Telegram test order:

```text
/health
/securecheck
/hlsdemo
/cdmdemo
/reset
/legitdemo
/compare
```

Expected behavior:

- `/health`: verifies the remote server is this Ddrm lab.
- `/securecheck`: attacker identity is blocked by secure HLS and secure mock-license paths.
- `/hlsdemo`: demonstrates the intentionally weak lab key endpoint using synthetic HLS media.
- `/cdmdemo`: demonstrates the intentionally weak mock-license entitlement path using synthetic media.
- `/legitdemo`: buys lab entitlements and demonstrates the secure versions.

## 5. CLI test

```bash
export LAB_EXTERNAL_TEST_MODE=1
export LAB_ALLOWED_HOSTS=ddrm-lab.example.edu
export LAB_GATEWAY_TOKEN="PASTE_THE_RANDOM_SECRET_HERE"

python -m app.controller hls \
  --base-url https://ddrm-lab.example.edu \
  --output recovered.m4a

python -m app.controller mock \
  --base-url https://ddrm-lab.example.edu \
  --output recovered.mp3
```

## 6. What not to configure

Do not replace the staging host with:

- PocketFM or another OTT production domain;
- a real Widevine/PlayReady/FairPlay license endpoint;
- a proxy that forwards to a production DRM service;
- a URL derived from captured account/session credentials.

This staging mode is specifically for a deployment of the included synthetic lab server.
