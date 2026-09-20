# Local HTTPS Onboarding

This app helps a person explicitly trust the public certificate authority (CA)
behind a local Home Assistant HTTPS certificate. It does **not** install anything
silently, change Home Assistant's HTTPS configuration, or expose the CA private
key.

## Before starting

If Home Assistant already uses a server certificate signed by a local CA, the app
automatically finds that CA's public certificate in `/ssl`. It rejects key files
and non-CA certificates. No certificate copy-and-paste is required.

If `/ssl` does not contain a usable root CA, automatic generation creates:

- `/ssl/homeassistant-local-ca.crt` and its protected private key;
- `/ssl/homeassistant-ip.crt` and `/ssl/homeassistant-ip.key`;
- `/ssl/homeassistant-ip-fullchain.pem` for Home Assistant.

No existing file is overwritten. To use the generated certificate, Home
Assistant's `http` configuration must reference the full-chain and server-key
paths above. Restart Home Assistant after changing its HTTPS certificate.

## Configuration

- **Public CA certificate:** normally detected automatically. An optional
  filename or PEM override is available for unusual installations.
- **Home Assistant address:** detected from the browser. An optional override is
  available if a reverse proxy hides the original address.
- **Home Assistant HTTPS port:** normally `8123`.
- **Onboarding page port:** normally `8098`. If you change this value, also
  change the host-side port in the app's Network settings to match.
- **Generate missing certificates automatically:** enabled by default.
- **Allow manual server-certificate regeneration:** disabled by default. Enable
  temporarily to show the guarded generation and restore buttons, then disable
  it again after use. Restore validates the newest backup before activation and
  preserves the replaced files in `/ssl/local-https-restore-rollbacks/`.

Start the app, then open its Web UI. For a new phone, open the direct onboarding
address shown on that page, or scan the QR code. The direct page intentionally
uses HTTP: it solves the bootstrap problem where a new device cannot yet trust
the HTTPS certificate it needs to download.

The onboarding page exposes only the public CA certificate and its metadata. It
does not require or collect a Home Assistant password.

### Browser-only quick mode

Turn on **Use browser-only quick mode** to skip certificate installation and
open Home Assistant HTTPS immediately. The browser should show its normal
certificate warning, where the user can explicitly continue or add an exception.
An exception is normally limited to that browser profile. It may retain a warning
indicator, does not configure the operating system or Home Assistant mobile app,
and must be repeated for other browsers and devices. Use the normal CA installation
flow when full trust is required.

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

- Keep the CA private key tightly protected. The app needs write access to `/ssl`
  for generation; its discovery code never selects filenames containing
  `key` or `priv`, nor files containing private-key data.
- Compare the SHA-256 fingerprint displayed by the app with a trusted copy before
  installing the CA.
- Use this only on a trusted LAN; do not forward the onboarding port to the
  internet.
- Stop the app when onboarding is complete if you do not need it continuously.

---

# Deutsche Dokumentation

# Lokale HTTPS-Einrichtung

Diese App hilft dabei, der privaten Zertifizierungsstelle (CA) einer lokalen
Home-Assistant-HTTPS-Verbindung ausdrücklich zu vertrauen. Sie installiert kein
Vertrauen unbemerkt und gibt den privaten CA-Schlüssel niemals über die
Einrichtungsseite aus.

## Erster Start und Zertifikate

Wenn bereits eine lokale CA vorhanden ist, erkennt die App deren öffentliches
Zertifikat automatisch in `/ssl`. Schlüsseldateien und Serverzertifikate werden
bei der CA-Suche ausgeschlossen.

Ist keine verwendbare CA vorhanden, erzeugt die App standardmäßig automatisch:

- `/ssl/homeassistant-local-ca.crt` und den geschützten privaten CA-Schlüssel;
- `/ssl/homeassistant-ip.crt` und `/ssl/homeassistant-ip.key`;
- `/ssl/homeassistant-ip-fullchain.pem` für Home Assistant.

Vorhandene Dateien werden niemals überschrieben. Home Assistant muss unter
`http` auf `/ssl/homeassistant-ip-fullchain.pem` und
`/ssl/homeassistant-ip.key` verweisen. Nach einer Änderung des Zertifikats muss
Home Assistant neu gestartet werden.

## Konfiguration

- **Fehlende Zertifikate automatisch erzeugen:** standardmäßig aktiviert.
- **Manuelle Erneuerung des Serverzertifikats erlauben:** standardmäßig
  deaktiviert. Aktiviert vorübergehend die Schaltflächen zum Erzeugen und
  Wiederherstellen. Danach sollte die Option wieder deaktiviert werden.
- **Öffentliches CA-Zertifikat:** wird normalerweise automatisch erkannt.
- **Home-Assistant-Adresse:** wird normalerweise automatisch ermittelt und kann
  für besondere Netzwerke überschrieben werden.
- **Home-Assistant-HTTPS-Port:** normalerweise `8123`.
- **Port der Einrichtungsseite:** normalerweise `8098`.

Die Erneuerung behält die vorhandene CA, damit bereits eingerichtete Geräte
weiterhin vertrauen. Ersetzte Dateien werden unter
`/ssl/local-https-backups/` gesichert. Die Wiederherstellung prüft Zertifikat,
CA und privaten Schlüssel, bevor der neueste Sicherungsstand aktiviert wird.
Dabei ersetzte Dateien bleiben unter `/ssl/local-https-restore-rollbacks/`
erhalten.

## Geräte einrichten

Öffne nach dem Start die Weboberfläche der App. Ein weiteres Gerät kann die dort
angezeigte direkte HTTP-Adresse öffnen oder den QR-Code scannen. Diese Seite
verwendet absichtlich HTTP, damit ein neues Gerät das benötigte CA-Zertifikat
vor der Vertrauensstellung herunterladen kann. Der Port darf nicht ins Internet
weitergeleitet werden.

### Schnellmodus

Der Schnellmodus überspringt die CA-Installation und öffnet Home Assistant
direkt. Der Browser kann daraufhin eine eigene Zertifikatsausnahme anbieten.
Diese Ausnahme gilt nur für das jeweilige Browserprofil, kann weiterhin ein
Warnsymbol anzeigen und richtet kein Vertrauen in der Home-Assistant-App ein.

### iPhone und iPad

Installiere das heruntergeladene Profil in den Einstellungen. Aktiviere danach
unter **Einstellungen → Allgemein → Info → Zertifikatsvertrauenseinstellungen**
das **volle Vertrauen** für die Home-Assistant-CA.

### Android

Öffne das heruntergeladene Zertifikat mit der Zertifikatsinstallation und wähle
**CA-Zertifikat**. Je nach Hersteller befindet sich dies unter **Sicherheit →
Verschlüsselung & Anmeldedaten → Zertifikat installieren**. Manche Apps
vertrauen absichtlich keinen vom Benutzer installierten CAs.

### Computer

Firefox kann die CA unter **Einstellungen → Datenschutz & Sicherheit →
Zertifikate → Zertifikate anzeigen → Zertifizierungsstellen** importieren.
Windows, macOS, Chrome, Edge und Safari verwenden normalerweise den
Zertifikatsspeicher des Betriebssystems.

## VPN-Nutzung

Wenn dieselbe private IP-Adresse zu Hause und über VPN verwendet wird, trage die
HTTPS-Adresse unter **Einstellungen → System → Netzwerk → Home-Assistant-URL**
als Internetadresse ein und lasse die lokale Adresse leer. Dadurch wird kein
Port öffentlich freigegeben; der Fernzugriff erfordert weiterhin das VPN.

## Sicherheit und Entfernen

- Vergleiche vor der Installation den angezeigten SHA-256-Fingerabdruck.
- Schütze den privaten CA-Schlüssel in `/ssl`.
- Beende die App nach der Einrichtung, wenn sie nicht dauerhaft benötigt wird.
- Entferne ein installiertes Profil oder eine CA später in den
  Zertifikatseinstellungen des jeweiligen Geräts.
