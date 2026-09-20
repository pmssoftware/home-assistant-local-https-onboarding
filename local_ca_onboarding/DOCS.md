# Local HTTPS Onboarding

This app helps a person explicitly trust the public certificate authority (CA)
behind a local Home Assistant HTTPS certificate. It does **not** install anything
silently, change Home Assistant's HTTPS configuration, or expose the CA private
key.

## Before starting

Home Assistant must already use an HTTPS server certificate signed by your local
CA. Paste that CA's **public** PEM certificate into the app configuration before
starting it. The public CA is safe to distribute; the CA private key must never
be pasted. The app rejects any configuration containing a private-key marker and
has no access to Home Assistant's `/ssl` directory.

## Configuration

- **Public CA certificate:** PEM text for the public root CA.
- **Home Assistant address:** the exact IP address or hostname present in the
  server certificate, for example `192.168.1.50`.
- **Home Assistant HTTPS port:** normally `8123`.
- **Onboarding page port:** normally `8098`. If you change this value, also
  change the host-side port in the app's Network settings to match.

Start the app, then open its Web UI. For a new phone, open the direct onboarding
address shown on that page, or scan the QR code. The direct page intentionally
uses HTTP: it solves the bootstrap problem where a new device cannot yet trust
the HTTPS certificate it needs to download.

The onboarding page exposes only the public CA certificate and its metadata. It
does not require or collect a Home Assistant password.

## VPN-only remote access

If the same private address is used both at home and while connected through a
VPN, set Home Assistant's **Internet** URL to that HTTPS address under
**Settings → System → Network → Home Assistant URL**. For example:

```text
https://192.168.1.50:8123
```

Leave the **Local network** field empty in this arrangement. This tells Home
Assistant and the Companion app to use the same HTTPS URL everywhere. It does
not expose Home Assistant to the public internet; remote access still requires
the VPN. Do not create a router port-forward for either Home Assistant or this
onboarding app.

## Device-specific behavior

### iPhone and iPad

After approving the download, install the profile in **Settings**. Apple also
requires enabling **Full Trust** for manually installed root certificates under
**Settings → General → About → Certificate Trust Settings**. Managed devices can
instead receive the profile through MDM.

### Android

Approve the download and choose the system's CA certificate installer. Menu
names differ by manufacturer; it is commonly under **Security → Encryption &
credentials → Install a certificate → CA certificate**. Android requires the
device PIN or biometric confirmation. Some apps intentionally do not trust
user-installed CAs; verify both the browser and the Home Assistant Companion app.

### Desktop browsers

The page downloads the public CA and shows instructions for Firefox, Windows,
macOS, and Linux. Browsers do not permit a normal webpage to edit trust stores,
so the operating system or browser always asks for confirmation.

## Removing trust

Remove the installed profile or CA from the same device certificate settings.
Removing this app does not remove certificates already installed on client
devices.

## Security notes

- Keep the CA private key offline or otherwise tightly protected. This app does
  not map or read Home Assistant's `/ssl` directory.
- Compare the SHA-256 fingerprint displayed by the app with a trusted copy before
  installing the CA.
- Use this only on a trusted LAN; do not forward the onboarding port to the
  internet.
- Stop the app when onboarding is complete if you do not need it continuously.
