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
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
DEFAULT_OPTIONS_PATH = Path("/data/options.json")
MAX_CERT_SIZE = 1024 * 1024
UUID_NAMESPACE = uuid.UUID("28a02e85-d4cb-43ed-a903-04647ac52480")


class ConfigurationError(RuntimeError):
    """Raised for a safe, user-actionable startup error."""


class NoCertificateFound(ConfigurationError):
    """Raised when discovery completed successfully but found no root CA."""


@dataclass(frozen=True)
class Settings:
    https_port: int
    onboarding_port: int
    ca_pem: bytes | None = None
    ca_file: str | None = None
    host: str | None = None
    listen_port: int = 8099
    auto_generate: bool = True
    allow_regeneration: bool = False

    def formatted_host(self, host: str | None = None) -> str:
        resolved = host or self.host or "homeassistant.local"
        try:
            value = ipaddress.ip_address(resolved)
            return f"[{value}]" if value.version == 6 else str(value)
        except ValueError:
            return resolved

    def home_assistant_url_for(self, host: str | None = None) -> str:
        return f"https://{self.formatted_host(host)}:{self.https_port}/"

    def onboarding_url_for(self, host: str | None = None) -> str:
        return f"http://{self.formatted_host(host)}:{self.onboarding_port}/"

    @property
    def home_assistant_url(self) -> str:
        return self.home_assistant_url_for()

    @property
    def onboarding_url(self) -> str:
        return self.onboarding_url_for()


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

    cert_setting = str(options.get("ca_certificate_pem") or "").strip()
    ca_pem = None
    if cert_setting:
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

    ca_file = str(options.get("ca_certificate_file") or "").strip() or None
    if ca_file and (Path(ca_file).name != ca_file or "key" in ca_file.lower()):
        raise ConfigurationError("CA filename must be a public certificate directly inside /ssl")
    raw_host = options.get("home_assistant_host")
    host = _validated_host(raw_host) if raw_host not in (None, "") else None

    return Settings(
        https_port=_validated_port(
            options.get("home_assistant_https_port", 8123), "HTTPS port"
        ),
        onboarding_port=_validated_port(
            options.get("onboarding_http_port", 8098), "Onboarding port"
        ),
        ca_pem=ca_pem,
        ca_file=ca_file,
        host=host,
        listen_port=_validated_port(os.environ.get("LISTEN_PORT", 8099), "Listen port"),
        auto_generate=bool(options.get("auto_generate_certificates", True)),
        allow_regeneration=bool(options.get("allow_certificate_regeneration", False)),
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


def load_ca_certificates(path: Path) -> list[Certificate]:
    """Return every valid root CA found in a PEM file or certificate file."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigurationError(f"Cannot read public CA certificate {path}: {exc}") from exc
    if len(raw) > MAX_CERT_SIZE:
        raise ConfigurationError("Certificate file is unexpectedly large")
    if b"PRIVATE KEY" in raw.upper():
        raise ConfigurationError("File contains private-key data")

    blocks = re.findall(
        rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        raw,
        flags=re.DOTALL,
    )
    if not blocks:
        blocks = [raw]
    certificates: list[Certificate] = []
    errors: list[str] = []
    for block in blocks:
        try:
            certificates.append(load_certificate_data(block + b"\n"))
        except ConfigurationError as exc:
            errors.append(str(exc))
    if not certificates:
        detail = errors[0] if errors else "no certificates found"
        raise ConfigurationError(detail)
    return certificates


def discover_certificate(settings: Settings, ssl_dir: Path = Path("/ssl")) -> Certificate:
    """Resolve an explicit public CA or safely discover one in Home Assistant's SSL folder."""
    if settings.ca_pem:
        return load_certificate_data(settings.ca_pem)

    ssl_dir = ssl_dir.resolve()
    if settings.ca_file:
        candidate = (ssl_dir / settings.ca_file).resolve()
        if candidate.parent != ssl_dir:
            raise ConfigurationError("CA certificate override must be directly inside /ssl")
        certificates = load_ca_certificates(candidate)
        if len(certificates) > 1:
            raise ConfigurationError(
                "The selected file contains multiple root CAs; choose a file with one root CA"
            )
        return certificates[0]

    try:
        paths = sorted(ssl_dir.iterdir())
    except OSError as exc:
        raise ConfigurationError(f"Cannot scan Home Assistant's /ssl folder: {exc}") from exc

    candidates: dict[str, tuple[int, Path, Certificate]] = {}
    inspected: list[str] = []
    for path in paths:
        lowered = path.name.lower()
        if (
            not path.is_file()
            or path.suffix.lower() not in {".crt", ".pem", ".cer"}
            or "key" in lowered
            or "priv" in lowered
        ):
            continue
        try:
            certificates = load_ca_certificates(path)
        except ConfigurationError as exc:
            inspected.append(f"{path.name}: {exc}")
            continue
        score = 0
        if "ca" in lowered or "root" in lowered:
            score += 2
        if "homeassistant" in lowered or "home-assistant" in lowered:
            score += 2
        for cert in certificates:
            inspected.append(f"{path.name}: root CA {cert.common_name}")
            existing = candidates.get(cert.fingerprint)
            item = (score, path, cert)
            if existing is None or score > existing[0]:
                candidates[cert.fingerprint] = item

    if not candidates:
        for result in inspected:
            print(f"CA discovery: {result}", file=sys.stderr, flush=True)
        raise NoCertificateFound(
            "No self-signed public CA certificate was found in /ssl. "
            "Place the public CA there or enable automatic generation."
        )
    ranked = sorted(candidates.values(), key=lambda item: (-item[0], item[1].name))
    if len(ranked) > 1 and ranked[0][0] == ranked[1][0]:
        names = ", ".join(item[1].name for item in ranked)
        raise ConfigurationError(
            f"Multiple public CA certificates were found ({names}). "
            "Set the CA filename override to choose one."
        )
    selected = ranked[0]
    print(f"Automatically selected public CA: /ssl/{selected[1].name}", flush=True)
    return selected[2]


GENERATED_FILES = {
    "ca_cert": "homeassistant-local-ca.crt",
    "ca_key": "homeassistant-local-ca.key",
    "server_cert": "homeassistant-ip.crt",
    "server_key": "homeassistant-ip.key",
    "fullchain": "homeassistant-ip-fullchain.pem",
}
GENERATION_LOCK = threading.Lock()


def supervisor_ipv4() -> str:
    """Return the primary host IPv4 address exposed by Supervisor."""
    token = os.environ.get("SUPERVISOR_TOKEN", "").strip()
    if not token:
        raise ConfigurationError(
            "Supervisor access is unavailable; set the Home Assistant address override"
        )
    request = Request(
        "http://supervisor/network/info",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=8) as response:
            payload = json.load(response)
    except (HTTPError, URLError, OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(
            "Cannot detect the Home Assistant host IP from Supervisor; "
            "set the Home Assistant address override"
        ) from exc
    data = payload.get("data", payload) if isinstance(payload, dict) else {}
    interfaces = data.get("interfaces", []) if isinstance(data, dict) else []
    if isinstance(interfaces, dict):
        interfaces = [dict(value, interface=name) for name, value in interfaces.items()]
    ranked: list[tuple[int, str]] = []
    for interface in interfaces if isinstance(interfaces, list) else []:
        if not isinstance(interface, dict) or interface.get("enabled") is False:
            continue
        ipv4 = interface.get("ipv4") or {}
        raw_addresses: list[object] = []
        if isinstance(ipv4, dict):
            address_list = ipv4.get("address") or []
            raw_addresses.extend(
                address_list if isinstance(address_list, list) else [address_list]
            )
            if ipv4.get("ip_address"):
                raw_addresses.append(ipv4["ip_address"])
        if interface.get("ip_address"):
            raw_addresses.append(interface["ip_address"])
        for raw in raw_addresses:
            try:
                address = ipaddress.ip_interface(str(raw)).ip
            except ValueError:
                continue
            if address.version != 4 or address.is_loopback or address.is_link_local:
                continue
            score = (2 if interface.get("primary") else 0) + (
                1 if interface.get("connected", True) else 0
            )
            ranked.append((score, str(address)))
    if not ranked:
        raise ConfigurationError(
            "Supervisor did not report a usable host IPv4 address; "
            "set the Home Assistant address override"
        )
    return sorted(ranked, key=lambda item: (-item[0], item[1]))[0][1]


def certificate_identity(settings: Settings) -> tuple[str, str]:
    """Return an OpenSSL SAN entry and matching common name."""
    host = settings.host or supervisor_ipv4()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return f"DNS:{host}", host
    return f"IP:{address}", str(address)


def _generate_server_files(
    work: Path, ca_cert: Path, ca_key: Path, san: str, common_name: str
) -> dict[str, Path]:
    server_key = work / GENERATED_FILES["server_key"]
    server_csr = work / "homeassistant-ip.csr"
    server_cert = work / GENERATED_FILES["server_cert"]
    fullchain = work / GENERATED_FILES["fullchain"]
    _openssl(
        "genpkey", "-quiet", "-algorithm", "RSA", "-pkeyopt",
        "rsa_keygen_bits:3072", "-out", str(server_key),
    )
    _openssl(
        "req", "-new", "-sha256", "-key", str(server_key),
        "-out", str(server_csr), "-subj", f"/CN={common_name}",
        "-addext", f"subjectAltName={san}",
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
        "-addext", "extendedKeyUsage=serverAuth",
    )
    _openssl(
        "x509", "-req", "-sha256", "-days", "825", "-in", str(server_csr),
        "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
        "-copy_extensions", "copy", "-out", str(server_cert),
    )
    fullchain.write_bytes(server_cert.read_bytes() + ca_cert.read_bytes())
    os.chmod(server_key, 0o600)
    os.chmod(server_cert, 0o644)
    os.chmod(fullchain, 0o644)
    return {"server_key": server_key, "server_cert": server_cert, "fullchain": fullchain}


def generate_initial_certificates(
    settings: Settings, ssl_dir: Path = Path("/ssl")
) -> Certificate:
    """Create a new root CA and server certificate without overwriting files."""
    ssl_dir = ssl_dir.resolve()
    ssl_dir.mkdir(parents=True, exist_ok=True)
    targets = {key: ssl_dir / name for key, name in GENERATED_FILES.items()}
    collisions = [path.name for path in targets.values() if path.exists()]
    if collisions:
        raise ConfigurationError(
            "Automatic generation refuses to overwrite existing files: "
            + ", ".join(collisions)
        )
    san, common_name = certificate_identity(settings)
    with GENERATION_LOCK, tempfile.TemporaryDirectory(
        prefix=".local-https-", dir=ssl_dir
    ) as temp:
        work = Path(temp)
        ca_key = work / GENERATED_FILES["ca_key"]
        ca_cert = work / GENERATED_FILES["ca_cert"]
        _openssl(
            "genpkey", "-quiet", "-algorithm", "RSA", "-pkeyopt",
            "rsa_keygen_bits:3072", "-out", str(ca_key),
        )
        _openssl(
            "req", "-x509", "-new", "-sha256", "-days", "3650",
            "-key", str(ca_key), "-out", str(ca_cert),
            "-subj", "/CN=Home Assistant Local Root CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash",
        )
        os.chmod(ca_key, 0o600)
        os.chmod(ca_cert, 0o644)
        generated = _generate_server_files(work, ca_cert, ca_key, san, common_name)
        generated.update({"ca_key": ca_key, "ca_cert": ca_cert})
        for key in ("ca_cert", "ca_key", "server_cert", "server_key", "fullchain"):
            os.replace(generated[key], targets[key])
    print(f"Generated new local CA and Home Assistant certificate for {san}", flush=True)
    print(f"SSL certificate: /ssl/{GENERATED_FILES['fullchain']}", flush=True)
    print(f"SSL private key: /ssl/{GENERATED_FILES['server_key']}", flush=True)
    return load_certificate(targets["ca_cert"])


def regenerate_server_certificate(
    settings: Settings, ssl_dir: Path = Path("/ssl")
) -> str:
    """Replace only the generated server certificate after backing it up."""
    ssl_dir = ssl_dir.resolve()
    ca_cert = ssl_dir / GENERATED_FILES["ca_cert"]
    ca_key = ssl_dir / GENERATED_FILES["ca_key"]
    if not ca_cert.is_file() or not ca_key.is_file():
        raise ConfigurationError(
            "The generated CA certificate and private key are required for regeneration"
        )
    san, common_name = certificate_identity(settings)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = ssl_dir / "local-https-backups" / stamp
    with GENERATION_LOCK, tempfile.TemporaryDirectory(
        prefix=".local-https-", dir=ssl_dir
    ) as temp:
        generated = _generate_server_files(Path(temp), ca_cert, ca_key, san, common_name)
        backup.mkdir(parents=True, exist_ok=False)
        for key in ("server_cert", "server_key", "fullchain"):
            target = ssl_dir / GENERATED_FILES[key]
            if target.exists():
                os.replace(target, backup / target.name)
            os.replace(generated[key], target)
    print(f"Regenerated Home Assistant server certificate for {san}", flush=True)
    return f"Server certificate generated for {common_name}. Restart Home Assistant to use it."


def available_certificate_backups(ssl_dir: Path = Path("/ssl")) -> list[Path]:
    root = ssl_dir.resolve() / "local-https-backups"
    if not root.is_dir():
        return []
    required = [GENERATED_FILES[key] for key in ("server_cert", "server_key", "fullchain")]
    try:
        candidates = [
            path
            for path in root.iterdir()
            if path.is_dir() and all((path / name).is_file() for name in required)
        ]
    except OSError:
        return []
    return sorted(candidates, key=lambda path: path.name, reverse=True)


def restore_latest_server_certificate(
    ssl_dir: Path = Path("/ssl"),
) -> str:
    """Validate and restore the newest complete server-certificate backup."""
    ssl_dir = ssl_dir.resolve()
    backups = available_certificate_backups(ssl_dir)
    if not backups:
        raise ConfigurationError("No complete server-certificate backup is available")
    selected = backups[0]
    ca_cert = ssl_dir / GENERATED_FILES["ca_cert"]
    backup_cert = selected / GENERATED_FILES["server_cert"]
    backup_key = selected / GENERATED_FILES["server_key"]
    if not ca_cert.is_file():
        raise ConfigurationError("The generated CA certificate is required for restoration")
    _openssl("verify", "-CAfile", str(ca_cert), str(backup_cert))
    cert_public = _openssl("x509", "-in", str(backup_cert), "-pubkey", "-noout")
    key_public = _openssl("pkey", "-in", str(backup_key), "-pubout")
    if cert_public != key_public:
        raise ConfigurationError("The backup certificate and private key do not match")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    rollback = ssl_dir / "local-https-restore-rollbacks" / stamp
    with GENERATION_LOCK, tempfile.TemporaryDirectory(
        prefix=".local-https-restore-", dir=ssl_dir
    ) as temp:
        work = Path(temp)
        for key in ("server_cert", "server_key", "fullchain"):
            shutil.copy2(selected / GENERATED_FILES[key], work / GENERATED_FILES[key])
        os.chmod(work / GENERATED_FILES["server_key"], 0o600)
        rollback.mkdir(parents=True, exist_ok=False)
        for key in ("server_cert", "server_key", "fullchain"):
            target = ssl_dir / GENERATED_FILES[key]
            if target.exists():
                os.replace(target, rollback / target.name)
            os.replace(work / GENERATED_FILES[key], target)
    print(f"Restored server certificate backup {selected.name}", flush=True)
    return f"Restored backup {selected.name}. Restart Home Assistant to use it."


def discover_or_generate_certificate(
    settings: Settings, ssl_dir: Path = Path("/ssl")
) -> Certificate:
    try:
        return discover_certificate(settings, ssl_dir)
    except NoCertificateFound:
        if not settings.auto_generate:
            raise
        return generate_initial_certificates(settings, ssl_dir)


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
        image_factory=qrcode.image.svg.SvgPathFillImage,
        box_size=8,
        border=3,
    )
    output = io.BytesIO()
    image.save(output)
    return output.getvalue()


def public_info(
    cert: Certificate, settings: Settings, host: str | None = None
) -> dict[str, object]:
    return {
        "certificate_name": cert.common_name,
        "fingerprint_sha256": cert.fingerprint,
        "not_before": cert.not_before,
        "not_after": cert.not_after,
        "home_assistant_url": settings.home_assistant_url_for(host),
        "onboarding_url": settings.onboarding_url_for(host),
        "platforms": ["ios", "android", "desktop"],
        "allow_certificate_regeneration": settings.allow_regeneration,
        "certificate_backup_available": bool(available_certificate_backups()),
    }


class OnboardingServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], settings: Settings, cert: Certificate):
        super().__init__(address, OnboardingHandler)
        self.settings = settings
        self.cert = cert


class OnboardingHandler(BaseHTTPRequestHandler):
    server_version = "LocalHTTPSOnboarding/0.2"
    protocol_version = "HTTP/1.1"

    @property
    def app(self) -> OnboardingServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stdout.write(f"request: {self.address_string()} {fmt % args}\n")
        sys.stdout.flush()

    def _request_host(self) -> str:
        query = parse_qs(urlsplit(self.path).query)
        candidates = [
            query.get("host", [""])[0],
            self.headers.get("X-Forwarded-Host", ""),
            self.headers.get("Host", ""),
            self.app.settings.host or "",
            "homeassistant.local",
        ]
        for candidate in candidates:
            if not candidate:
                continue
            try:
                parsed = urlsplit(f"//{candidate}")
                if parsed.hostname:
                    return _validated_host(parsed.hostname)
            except (ConfigurationError, ValueError):
                continue
        return "homeassistant.local"

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
                send_body=send_body,
            )
            return
        if path == "/assets/app.js":
            body = (STATIC_DIR / "app.js").read_bytes()
            self._send(
                HTTPStatus.OK,
                body,
                "text/javascript; charset=utf-8",
                send_body=send_body,
            )
            return
        if path.startswith("/assets/locales/"):
            locale_name = path.removeprefix("/assets/locales/")
            if not locale_name or "/" in locale_name or not locale_name.endswith(".json"):
                self._send(HTTPStatus.NOT_FOUND, b"Not found\n", "text/plain; charset=utf-8", send_body=send_body)
                return
            locale_path = STATIC_DIR / "locales" / locale_name
            if not locale_path.is_file():
                self._send(HTTPStatus.NOT_FOUND, b"Not found\n", "text/plain; charset=utf-8", send_body=send_body)
                return
            self._send(
                HTTPStatus.OK,
                locale_path.read_bytes(),
                "application/json; charset=utf-8",
                send_body=send_body,
            )
            return
        if path == "/api/info":
            body = json.dumps(
                public_info(self.app.cert, self.app.settings, self._request_host())
            ).encode("utf-8")
            self._send(HTTPStatus.OK, body, "application/json", send_body=send_body)
            return
        if path == "/qr.svg":
            qr_svg = make_qr_svg(
                self.app.settings.onboarding_url_for(self._request_host())
            )
            self._send(
                HTTPStatus.OK,
                qr_svg,
                "image/svg+xml",
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
            request_settings = Settings(
                https_port=self.app.settings.https_port,
                onboarding_port=self.app.settings.onboarding_port,
                ca_pem=self.app.settings.ca_pem,
                ca_file=self.app.settings.ca_file,
                host=self._request_host(),
                listen_port=self.app.settings.listen_port,
            )
            mobileconfig = make_mobileconfig(self.app.cert, request_settings)
            self._send(
                HTTPStatus.OK,
                mobileconfig,
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
        path = urlsplit(self.path).path
        if path == "/api/regenerate-server-certificate":
            if not self.app.settings.allow_regeneration:
                self._send(
                    HTTPStatus.FORBIDDEN,
                    json.dumps({"error": "Certificate regeneration is disabled"}).encode(),
                    "application/json",
                )
                return
            if self.headers.get_content_type() != "application/json":
                self._send(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, b'{"error":"JSON required"}', "application/json")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 1024:
                    raise ValueError
                payload = json.loads(self.rfile.read(length))
                if payload.get("confirmation") != "GENERATE":
                    raise ValueError
                request_settings = Settings(
                    https_port=self.app.settings.https_port,
                    onboarding_port=self.app.settings.onboarding_port,
                    host=self._request_host(),
                    listen_port=self.app.settings.listen_port,
                    auto_generate=self.app.settings.auto_generate,
                    allow_regeneration=self.app.settings.allow_regeneration,
                )
                result = regenerate_server_certificate(request_settings)
            except (ValueError, json.JSONDecodeError):
                self._send(HTTPStatus.BAD_REQUEST, b'{"error":"Explicit confirmation required"}', "application/json")
                return
            except ConfigurationError as exc:
                self._send(
                    HTTPStatus.CONFLICT,
                    json.dumps({"error": str(exc)}).encode(),
                    "application/json",
                )
                return
            self._send(
                HTTPStatus.OK,
                json.dumps({"message": result}).encode(),
                "application/json",
            )
            return
        if path == "/api/restore-server-certificate":
            if not self.app.settings.allow_regeneration:
                self._send(
                    HTTPStatus.FORBIDDEN,
                    json.dumps({"error": "Certificate restoration is disabled"}).encode(),
                    "application/json",
                )
                return
            if self.headers.get_content_type() != "application/json":
                self._send(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, b'{"error":"JSON required"}', "application/json")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 1024:
                    raise ValueError
                payload = json.loads(self.rfile.read(length))
                if payload.get("confirmation") != "RESTORE":
                    raise ValueError
                result = restore_latest_server_certificate()
            except (ValueError, json.JSONDecodeError):
                self._send(HTTPStatus.BAD_REQUEST, b'{"error":"Explicit confirmation required"}', "application/json")
                return
            except ConfigurationError as exc:
                self._send(
                    HTTPStatus.CONFLICT,
                    json.dumps({"error": str(exc)}).encode(),
                    "application/json",
                )
                return
            self._send(
                HTTPStatus.OK,
                json.dumps({"message": result}).encode(),
                "application/json",
            )
            return
        self._send(
            HTTPStatus.METHOD_NOT_ALLOWED,
            b"Method not allowed\n",
            "text/plain; charset=utf-8",
        )


def main() -> int:
    try:
        settings = load_settings()
        cert = discover_or_generate_certificate(settings)
    except ConfigurationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 2

    print(f"Serving public CA: {cert.common_name}", flush=True)
    print(f"SHA-256 fingerprint: {cert.fingerprint}", flush=True)
    print(
        "Direct onboarding page: "
        f"http://<home-assistant-address>:{settings.onboarding_port}/",
        flush=True,
    )
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
