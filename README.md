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
flow, and the onboarding page requires an explicit consent checkbox first. App
setup itself is automatic: it discovers the public root CA in `/ssl` and detects
the Home Assistant address from the browser.

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

## Start

There are no required configuration fields. Install and start the app, then open
its Web UI. The app automatically:

- finds a valid, unexpired, self-signed public CA certificate in `/ssl`;
- ignores key files and non-CA server certificates;
- derives the Home Assistant IP or hostname from the browser request;
- creates the iOS profile, Android certificate, desktop certificate, and QR code.

Unusual installations can optionally select a specific public CA filename or
override the detected host in the Configuration tab. PEM paste remains available
only as an advanced fallback.

New devices can browse directly to the HTTP
onboarding address shown there. The temporary HTTP page solves the certificate
bootstrap problem and exposes only the public CA certificate. Do not forward the
onboarding port to the public internet; stop the app when onboarding is finished.

For browsers where a per-site certificate exception is sufficient, the page also
offers an optional **browser-only quick mode**. It skips CA installation and opens
Home Assistant directly so the browser can offer its own warning/exception flow.
This shortcut is browser-specific and does not establish system-wide trust or
configure the Home Assistant mobile app.

The onboarding interface is available in English and German. It selects the
browser language automatically and also provides a language menu.

### Adding a translation

Translations are intentionally separate from the page layout. Contributors can
copy `local_ca_onboarding/app/static/locales/en.json`, translate every value into
a new `<language-code>.json` file, and add its code and native name to
`languages.json`. Keep the same keys; the automated tests verify that registered
locale files are served by the app.

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
