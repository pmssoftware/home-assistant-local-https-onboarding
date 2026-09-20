# Local HTTPS Onboarding for Home Assistant

[![Add app repository to Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fpmssoftware%2Fhome-assistant-local-https-onboarding)

A consent-based Home Assistant app (formerly called an add-on) that helps people
trust the private certificate authority used by a local Home Assistant HTTPS
installation.

It provides guided setup for:

- iPhone and iPad using an Apple configuration profile
- Android using the system CA certificate installer
- Firefox, Chrome, Edge, Safari, Windows, macOS, and Linux
- A QR-code handoff to another phone on the same LAN or VPN

The app never installs trust silently. Every device displays its native approval
flow, and the onboarding page requires an explicit consent checkbox first.

## Install

Click the button above, or add this repository manually under **Settings → Apps
→ App store → ⋮ → Repositories**:

```text
https://github.com/pmssoftware/home-assistant-local-https-onboarding
```

Then install **Local HTTPS Onboarding** from the App Store.

> This is a Home Assistant Supervisor app, not a HACS integration. HACS cannot
> install or run add-ons. The official Home Assistant repository button above is
> the correct one-click installer for this package type.

## Configure

Before starting the app:

1. Paste your CA's **public PEM certificate** into `ca_certificate_pem`.
2. Enter the IP address or hostname covered by your Home Assistant server
   certificate in `home_assistant_host`.
3. Confirm the HTTPS port, normally `8123`.
4. Keep the onboarding port at `8098` unless you also change its Network mapping.

Never paste a private key. The app rejects private-key markers and has no access
to Home Assistant's `/ssl` directory.

Start the app and open its Web UI. New devices can browse directly to the HTTP
onboarding address shown there. The temporary HTTP page solves the certificate
bootstrap problem and exposes only the public CA certificate. Do not forward the
onboarding port to the public internet; stop the app when onboarding is finished.

See [the full documentation](local_ca_onboarding/DOCS.md) for iOS, Android,
desktop, VPN, removal, and troubleshooting instructions.

## Supported Home Assistant systems

This app requires Home Assistant OS or a Supervised installation with Apps.
Supported CPU architectures:

- `aarch64`
- `amd64`

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m unittest discover -s local_ca_onboarding/tests -v
```

This project is licensed under the [MIT License](LICENSE).
