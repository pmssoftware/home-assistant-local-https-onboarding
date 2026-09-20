#!/usr/bin/env python3
"""Small, dependency-light web app for local CA onboarding."""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import os
import plistlib
import re
import ssl
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
DEFAULT_OPTIONS_PATH = Path("/data/options.json")
MAX_CERT_SIZE = 1024 * 1024
UUID_NAMESPACE = uuid.UUID("28a02e85-d4cb-43ed-a903-04647ac52480")


class ConfigurationError(RuntimeError):
    """Raised for a safe, user-actionable startup error."""


@dataclass(frozen=True)
class Settings:
    ca_pem: bytes
    host: str
    https_port: int
    onboarding_port: int
    listen_port: int = 8099

    @property
    def formatted_host(self) -> str:
        try:
            value = ipaddress.ip_address(self.host)
            return f"[{value}]" if value.version == 6 else str(value)
        except ValueError:
            return self.host

    @property
    def home_assistant_url(self) -> str:
        return f"https://{self.formatted_host}:{self.https_port}/"

    @property
    def onboarding_url(self) -> str:
        return f"http://{self.formatted_host}:{self.onboarding_port}/"


@dataclass(frozen=True)
class Certificate:
    pem: bytes
    der: bytes
    subject: str
    issuer: str
    not_before: str
    not_after: str
    fingerprint: str
    common_name: str


def _validated_host(raw_host: object) -> str:
    if raw_host is None:
        raise ConfigurationError("Home Assistant address cannot be empty")
    host = str(raw_host).strip()
    if not host:
        raise ConfigurationError("Home Assistant address cannot be empty")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        if len(host) > 253 or not re.fullmatch(
            r"(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?",
            host,
        ):
            raise ConfigurationError("Home Assistant address must be an IP address or hostname")
        return host.rstrip(".")


def _validated_port(value: object, label: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(f"{label} must be a number") from exc
    if not 1 <= port <= 65535:
        raise ConfigurationError(f"{label} must be between 1 and 65535")
    return port


def load_settings(options_path: Path | None = None) -> Settings:
    options_path = options_path or Path(os.environ.get("OPTIONS_PATH", DEFAULT_OPTIONS_PATH))
    try:
        options = json.loads(options_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigurationError(f"Options file not found: {options_path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Cannot read options: {exc}") from exc

    cert_setting = str(options.get("ca_certificate_pem", "")).strip()
    if not cert_setting:
        raise ConfigurationError("Public CA certificate cannot be empty")
    try:
        ca_pem = (cert_setting + "\n").encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise ConfigurationError("Public CA certificate must contain ASCII PEM text") from exc
    if len(ca_pem) > MAX_CERT_SIZE:
        raise ConfigurationError("Public CA certificate is unexpectedly large")
    if b"PRIVATE KEY" in ca_pem.upper():
        raise ConfigurationError("Refusing to use configuration containing a private key")
    if b"-----BEGIN CERTIFICATE-----" not in ca_pem:
        raise ConfigurationError("Public CA certificate must be PEM certificate text")

    return Settings(
        ca_pem=ca_pem,
        host=_validated_host(options.get("home_assistant_host", "")),
        https_port=_validated_port(
            options.get("home_assistant_https_port", 8123), "HTTPS port"
        ),
        onboarding_port=_validated_port(
            options.get("onboarding_http_port", 8098), "Onboarding port"
        ),
        listen_port=_validated_port(os.environ.get("LISTEN_PORT", 8099), "Listen port"),
    )


def _openssl(*args: str, input_data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            ["openssl", *args],
            input=input_data,
            check=True,
            capture_output=True,
            timeout=10,
        )
    except FileNotFoundError as exc:
        raise ConfigurationError("OpenSSL is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise ConfigurationError("Timed out while reading the CA certificate") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", "replace").strip()
        raise ConfigurationError(f"Cannot read the CA certificate: {detail}") from exc
    return result.stdout


def _certificate_time(value: str, label: str) -> datetime:
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ConfigurationError(f"Cannot determine the CA certificate {label}") from exc


def load_certificate_data(raw: bytes) -> Certificate:
    if len(raw) > MAX_CERT_SIZE:
        raise ConfigurationError("Public CA certificate is unexpectedly large")
    if b"PRIVATE KEY" in raw.upper():
        raise ConfigurationError("Refusing to serve a file containing a private key")

    der = _openssl("x509", "-outform", "DER", input_data=raw)
    pem_text = ssl.DER_cert_to_PEM_cert(der)
    pem = pem_text.encode("ascii")
    details = _openssl(
        "x509",
        "-noout",
        "-subject",
        "-issuer",
        "-startdate",
        "-enddate",
        "-nameopt",
        "RFC2253",
        "-text",
        input_data=raw,
    ).decode("utf-8", "replace")
    fields: dict[str, str] = {}
    for line in details.splitlines():
        for key in ("subject", "issuer", "notBefore", "notAfter"):
            prefix = f"{key}="
            if line.startswith(prefix):
                fields[key] = line[len(prefix) :].strip()
    if fields.get("subject") != fields.get("issuer"):
        raise ConfigurationError("The configured certificate is not a self-signed root CA")
    if "CA:TRUE" not in details.replace(" ", ""):
        raise ConfigurationError("The configured certificate is not marked as a CA")
    try:
        not_before = _certificate_time(fields["notBefore"], "start date")
        not_after = _certificate_time(fields["notAfter"], "expiry")
    except KeyError as exc:
        raise ConfigurationError("Cannot determine the CA certificate validity") from exc
    now = datetime.now(timezone.utc)
    if not_before > now:
        raise ConfigurationError("The configured CA certificate is not valid yet")
    if not_after <= now:
        raise ConfigurationError("The configured CA certificate has expired")
    with tempfile.NamedTemporaryFile(prefix="local-ca-", suffix=".crt") as public_ca:
        public_ca.write(pem)
        public_ca.flush()
        _openssl("verify", "-CAfile", public_ca.name, public_ca.name)

    digest = hashlib.sha256(der).hexdigest().upper()
    fingerprint = ":".join(digest[index : index + 2] for index in range(0, 64, 2))
    subject = fields.get("subject", "Unknown")
    cn_match = re.search(r"(?:^|,)CN=([^,]+)", subject)
    common_name = cn_match.group(1).replace("\\,", ",") if cn_match else "Local CA"
    return Certificate(
        pem=pem,
        der=der,
        subject=subject,
        issuer=fields.get("issuer", "Unknown"),
        not_before=not_before.isoformat().replace("+00:00", "Z"),
        not_after=not_after.isoformat().replace("+00:00", "Z"),
        fingerprint=fingerprint,
        common_name=common_name,
    )


def load_certificate(path: Path) -> Certificate:
    """Load a certificate file for development and automated tests."""
    try:
        return load_certificate_data(path.read_bytes())
    except OSError as exc:
        raise ConfigurationError(f"Cannot read public CA certificate {path}: {exc}") from exc


def make_mobileconfig(cert: Certificate, settings: Settings) -> bytes:
    stable_name = cert.fingerprint.replace(":", "")
    root_uuid = str(uuid.uuid5(UUID_NAMESPACE, f"root:{stable_name}")).upper()
    profile_uuid = str(uuid.uuid5(UUID_NAMESPACE, f"profile:{stable_name}")).upper()
    identifier = f"local.homeassistant.ca.{stable_name.lower()[:16]}"
    profile = {
        "ConsentText": {
            "default": (
                f"This profile adds {cert.common_name} as a trusted root certificate. "
                f"Only continue if you recognize {settings.home_assistant_url} and have "
                "verified the SHA-256 fingerprint shown on the onboarding page."
            )
        },
        "PayloadContent": [
            {
                "PayloadCertificateFileName": "home-assistant-local-ca.cer",
                "PayloadContent": cert.der,
                "PayloadDescription": "Trust the local CA used by Home Assistant",
                "PayloadDisplayName": cert.common_name,
                "PayloadIdentifier": f"{identifier}.root",
                "PayloadOrganization": "Home Assistant local network",
                "PayloadType": "com.apple.security.root",
                "PayloadUUID": root_uuid,
                "PayloadVersion": 1,
            }
        ],
        "PayloadDescription": "Trust the local HTTPS certificate used by Home Assistant",
        "PayloadDisplayName": "Home Assistant Local HTTPS",
        "PayloadIdentifier": identifier,
        "PayloadOrganization": "Home Assistant local network",
        "PayloadRemovalDisallowed": False,
        "PayloadType": "Configuration",
        "PayloadUUID": profile_uuid,
        "PayloadVersion": 1,
    }
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=True)


def make_qr_svg(url: str) -> bytes:
    import qrcode
    import qrcode.image.svg

    image = qrcode.make(
        url,
        image_factory=qrcode.image.svg.SvgPathImage,
        box_size=8,
        border=3,
    )
    output = io.BytesIO()
    image.save(output)
    return output.getvalue()


def public_info(cert: Certificate, settings: Settings) -> dict[str, object]:
    return {
        "certificate_name": cert.common_name,
        "fingerprint_sha256": cert.fingerprint,
        "not_before": cert.not_before,
        "not_after": cert.not_after,
        "home_assistant_url": settings.home_assistant_url,
        "onboarding_url": settings.onboarding_url,
        "platforms": ["ios", "android", "desktop"],
    }


class OnboardingServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], settings: Settings, cert: Certificate):
        super().__init__(address, OnboardingHandler)
        self.settings = settings
        self.cert = cert
        self.mobileconfig = make_mobileconfig(cert, settings)
        self.qr_svg = make_qr_svg(settings.onboarding_url)


class OnboardingHandler(BaseHTTPRequestHandler):
    server_version = "LocalHTTPSOnboarding/0.1"
    protocol_version = "HTTP/1.1"

    @property
    def app(self) -> OnboardingServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stdout.write(f"request: {self.address_string()} {fmt % args}\n")
        sys.stdout.flush()

    def _send(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        *,
        disposition: str | None = None,
        cache: str = "no-store",
        send_body: bool = True,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; connect-src 'self'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'self'",
        )
        if disposition:
            self.send_header("Content-Disposition", disposition)
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def _route(self, send_body: bool) -> None:
        path = urlsplit(self.path).path
        if path in ("", "/"):
            body = (STATIC_DIR / "index.html").read_bytes()
            self._send(HTTPStatus.OK, body, "text/html; charset=utf-8", send_body=send_body)
            return
        if path == "/assets/styles.css":
            body = (STATIC_DIR / "styles.css").read_bytes()
            self._send(
                HTTPStatus.OK,
                body,
                "text/css; charset=utf-8",
                cache="public, max-age=3600",
                send_body=send_body,
            )
            return
        if path == "/assets/app.js":
            body = (STATIC_DIR / "app.js").read_bytes()
            self._send(
                HTTPStatus.OK,
                body,
                "text/javascript; charset=utf-8",
                cache="public, max-age=3600",
                send_body=send_body,
            )
            return
        if path == "/api/info":
            body = json.dumps(public_info(self.app.cert, self.app.settings)).encode("utf-8")
            self._send(HTTPStatus.OK, body, "application/json", send_body=send_body)
            return
        if path == "/qr.svg":
            self._send(
                HTTPStatus.OK,
                self.app.qr_svg,
                "image/svg+xml",
                cache="public, max-age=3600",
                send_body=send_body,
            )
            return
        if path == "/download/home-assistant-local-ca.crt":
            self._send(
                HTTPStatus.OK,
                self.app.cert.pem,
                "application/x-x509-ca-cert",
                disposition='attachment; filename="home-assistant-local-ca.crt"',
                send_body=send_body,
            )
            return
        if path == "/download/home-assistant-local-ca.cer":
            self._send(
                HTTPStatus.OK,
                self.app.cert.der,
                "application/pkix-cert",
                disposition='attachment; filename="home-assistant-local-ca.cer"',
                send_body=send_body,
            )
            return
        if path == "/download/home-assistant-local-https.mobileconfig":
            self._send(
                HTTPStatus.OK,
                self.app.mobileconfig,
                "application/x-apple-aspen-config",
                disposition='attachment; filename="home-assistant-local-https.mobileconfig"',
                send_body=send_body,
            )
            return
        if path == "/health":
            self._send(HTTPStatus.OK, b"ok\n", "text/plain; charset=utf-8", send_body=send_body)
            return
        body = b"Not found\n"
        self._send(HTTPStatus.NOT_FOUND, body, "text/plain; charset=utf-8", send_body=send_body)

    def do_GET(self) -> None:  # noqa: N802
        self._route(True)

    def do_HEAD(self) -> None:  # noqa: N802
        self._route(False)

    def do_POST(self) -> None:  # noqa: N802
        self._send(
            HTTPStatus.METHOD_NOT_ALLOWED,
            b"Method not allowed\n",
            "text/plain; charset=utf-8",
        )


def main() -> int:
    try:
        settings = load_settings()
        cert = load_certificate_data(settings.ca_pem)
    except ConfigurationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 2

    print(f"Serving public CA: {cert.common_name}", flush=True)
    print(f"SHA-256 fingerprint: {cert.fingerprint}", flush=True)
    print(f"Direct onboarding page: {settings.onboarding_url}", flush=True)
    server = OnboardingServer(("0.0.0.0", settings.listen_port), settings, cert)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
