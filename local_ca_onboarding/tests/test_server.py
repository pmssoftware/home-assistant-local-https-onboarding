import importlib.util
import json
import plistlib
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock
from pathlib import Path


SERVER_PATH = Path(__file__).parents[1] / "app" / "server.py"
FIXTURE_CERT = Path(__file__).parent / "fixtures" / "test-ca.crt"
SPEC = importlib.util.spec_from_file_location("onboarding_server", SERVER_PATH)
server = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)


class SettingsTests(unittest.TestCase):
    def write_options(self, directory: Path, **overrides):
        options = {
            "ca_certificate_pem": FIXTURE_CERT.read_text(encoding="ascii"),
            "home_assistant_host": "192.168.1.50",
            "home_assistant_https_port": 8123,
            "onboarding_http_port": 8098,
        }
        options.update(overrides)
        path = directory / "options.json"
        path.write_text(json.dumps(options), encoding="utf-8")
        return path

    def test_expected_urls(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            settings = server.load_settings(self.write_options(root))
            self.assertEqual(settings.home_assistant_url, "https://192.168.1.50:8123/")
            self.assertEqual(settings.onboarding_url, "http://192.168.1.50:8098/")

    def test_ipv6_urls_use_brackets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            settings = server.load_settings(self.write_options(root, home_assistant_host="fd00::25"))
            self.assertEqual(settings.home_assistant_url, "https://[fd00::25]:8123/")

    def test_rejects_private_key_text(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            options = self.write_options(
                root,
                ca_certificate_pem="-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
            )
            with self.assertRaises(server.ConfigurationError):
                server.load_settings(options)

    def test_rejects_invalid_hostname(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            options = self.write_options(root, home_assistant_host="https://bad host")
            with self.assertRaises(server.ConfigurationError):
                server.load_settings(options)

    def test_unconfigured_host_uses_browser_safe_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            options = self.write_options(root, home_assistant_host=None)
            settings = server.load_settings(options)
            self.assertIsNone(settings.host)
            self.assertEqual(
                settings.home_assistant_url, "https://homeassistant.local:8123/"
            )

    def test_automatic_ca_discovery(self):
        with tempfile.TemporaryDirectory() as temp:
            ssl_dir = Path(temp)
            (ssl_dir / "homeassistant-local-ca.crt").write_bytes(FIXTURE_CERT.read_bytes())
            fullchain = ssl_dir / "homeassistant-fullchain.pem"
            fullchain.write_bytes(FIXTURE_CERT.read_bytes() + FIXTURE_CERT.read_bytes())
            (ssl_dir / "homeassistant-private.key").write_text(
                "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n", encoding="ascii"
            )
            self.assertEqual(len(server.load_ca_certificates(fullchain)), 2)
            settings = server.Settings(https_port=8123, onboarding_port=8098)
            cert = server.discover_certificate(settings, ssl_dir)
            self.assertEqual(cert.common_name, "Test Local HTTPS CA")

    def test_first_start_generates_ca_and_server_certificate(self):
        with tempfile.TemporaryDirectory() as temp:
            ssl_dir = Path(temp)
            settings = server.Settings(
                host="192.168.1.50",
                https_port=8123,
                onboarding_port=8098,
            )
            cert = server.discover_or_generate_certificate(settings, ssl_dir)
            self.assertEqual(cert.common_name, "Home Assistant Local Root CA")
            for name in server.GENERATED_FILES.values():
                self.assertTrue((ssl_dir / name).is_file(), name)
            self.assertEqual((ssl_dir / "homeassistant-local-ca.key").stat().st_mode & 0o777, 0o600)
            details = server._openssl(
                "x509", "-in", str(ssl_dir / "homeassistant-ip.crt"), "-noout", "-text"
            )
            self.assertIn(b"IP Address:192.168.1.50", details)

    def test_generation_never_overwrites_partial_files(self):
        with tempfile.TemporaryDirectory() as temp:
            ssl_dir = Path(temp)
            existing = ssl_dir / "homeassistant-ip.key"
            existing.write_text("keep", encoding="ascii")
            settings = server.Settings(
                host="192.168.1.50", https_port=8123, onboarding_port=8098
            )
            with self.assertRaises(server.ConfigurationError):
                server.generate_initial_certificates(settings, ssl_dir)
            self.assertEqual(existing.read_text(encoding="ascii"), "keep")

    def test_regeneration_keeps_ca_and_backs_up_server_files(self):
        with tempfile.TemporaryDirectory() as temp:
            ssl_dir = Path(temp)
            settings = server.Settings(
                host="192.168.1.50", https_port=8123, onboarding_port=8098
            )
            server.generate_initial_certificates(settings, ssl_dir)
            ca_before = (ssl_dir / "homeassistant-local-ca.crt").read_bytes()
            cert_before = (ssl_dir / "homeassistant-ip.crt").read_bytes()
            result = server.regenerate_server_certificate(settings, ssl_dir)
            self.assertIn("192.168.1.50", result)
            self.assertEqual(
                (ssl_dir / "homeassistant-local-ca.crt").read_bytes(), ca_before
            )
            cert_after = (ssl_dir / "homeassistant-ip.crt").read_bytes()
            self.assertNotEqual(cert_after, cert_before)
            backups = list((ssl_dir / "local-https-backups").glob("*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(
                (backups[0] / "homeassistant-ip.crt").read_bytes(), cert_before
            )
            server._openssl(
                "verify",
                "-CAfile",
                str(ssl_dir / "homeassistant-local-ca.crt"),
                str(ssl_dir / "homeassistant-ip.crt"),
            )
            restore_result = server.restore_latest_server_certificate(ssl_dir)
            self.assertIn(backups[0].name, restore_result)
            self.assertEqual(
                (ssl_dir / "homeassistant-ip.crt").read_bytes(), cert_before
            )
            rollbacks = list((ssl_dir / "local-https-restore-rollbacks").glob("*"))
            self.assertEqual(len(rollbacks), 1)
            self.assertEqual(
                (rollbacks[0] / "homeassistant-ip.crt").read_bytes(), cert_after
            )


class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_path = FIXTURE_CERT
        cls.cert = server.load_certificate(cls.cert_path)
        cls.settings = server.Settings(
            ca_pem=cls.cert.pem,
            host="192.168.1.50",
            https_port=8123,
            onboarding_port=8098,
        )

    def test_certificate_metadata(self):
        self.assertEqual(self.cert.common_name, "Test Local HTTPS CA")
        self.assertEqual(
            self.cert.fingerprint,
            "72:4B:16:BD:59:15:96:99:3B:6C:E9:F1:6E:37:81:61:5B:13:54:01:BB:3A:89:C3:67:6C:E9:1C:F7:31:B8:A6",
        )

    def test_ios_profile_contains_only_public_certificate(self):
        data = server.make_mobileconfig(self.cert, self.settings)
        profile = plistlib.loads(data)
        payload = profile["PayloadContent"][0]
        self.assertEqual(payload["PayloadType"], "com.apple.security.root")
        self.assertEqual(payload["PayloadContent"], self.cert.der)
        self.assertNotIn(b"PRIVATE KEY", data)

    def test_public_info_has_no_filesystem_path(self):
        info = server.public_info(self.cert, self.settings)
        encoded = json.dumps(info)
        self.assertNotIn(str(self.cert_path), encoded)
        self.assertEqual(info["home_assistant_url"], "https://192.168.1.50:8123/")


class HttpTests(CertificateTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.httpd = server.OnboardingServer(("127.0.0.1", 0), cls.settings, cls.cert)
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_port}/"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def fetch(self, path):
        with urllib.request.urlopen(self.base_url + path, timeout=2) as response:
            return response, response.read()

    def test_info_endpoint(self):
        response, body = self.fetch("api/info")
        self.assertEqual(response.headers.get_content_type(), "application/json")
        info = json.loads(body)
        self.assertEqual(info["certificate_name"], "Test Local HTTPS CA")
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])

    def test_page_offers_browser_only_quick_mode(self):
        response, body = self.fetch("")
        self.assertEqual(response.headers.get_content_type(), "text/html")
        self.assertIn(b'id="quick-mode"', body)
        self.assertIn(b'id="quick-open-link"', body)
        self.assertIn(b"does not install the CA", body)

    def test_translation_script_uses_formatted_message_key(self):
        response, body = self.fetch("assets/app.js")
        self.assertEqual(response.headers.get_content_type(), "text/javascript")
        self.assertIn(b"element.dataset.i18nHtml", body)
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_registered_locales_are_complete(self):
        response, body = self.fetch("assets/locales/languages.json")
        self.assertEqual(response.headers.get_content_type(), "application/json")
        languages = json.loads(body)
        codes = {item["code"] for item in languages}
        self.assertTrue({"en", "de"}.issubset(codes))
        _, english_body = self.fetch("assets/locales/en.json")
        english_keys = set(json.loads(english_body))
        for locale in codes:
            locale_response, locale_body = self.fetch(f"assets/locales/{locale}.json")
            self.assertEqual(locale_response.headers.get_content_type(), "application/json")
            self.assertEqual(set(json.loads(locale_body)), english_keys)

    def test_locale_path_traversal_is_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.fetch("assets/locales/missing.json")
        self.assertEqual(caught.exception.code, 404)
        caught.exception.close()

    def test_android_download_is_der_public_certificate(self):
        response, body = self.fetch("download/home-assistant-local-ca.cer")
        self.assertEqual(response.headers.get_content_type(), "application/pkix-cert")
        self.assertEqual(body, self.cert.der)
        self.assertNotIn(b"PRIVATE KEY", body)

    def test_ios_download_is_profile(self):
        response, body = self.fetch("download/home-assistant-local-https.mobileconfig")
        self.assertEqual(
            response.headers.get_content_type(), "application/x-apple-aspen-config"
        )
        self.assertEqual(
            plistlib.loads(body)["PayloadContent"][0]["PayloadContent"], self.cert.der
        )

    def test_qr_is_svg(self):
        response, body = self.fetch("qr.svg")
        self.assertEqual(response.headers.get_content_type(), "image/svg+xml")
        self.assertIn(b"<svg", body)
        self.assertIn(b'<rect fill="white"', body)

    def test_regeneration_endpoint_is_disabled_by_default(self):
        request = urllib.request.Request(
            self.base_url + "api/regenerate-server-certificate",
            data=b'{"confirmation":"GENERATE"}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=2)
        self.assertEqual(caught.exception.code, 403)
        caught.exception.close()

    def test_regeneration_endpoint_requires_opt_in_and_confirmation(self):
        settings = server.Settings(
            ca_pem=self.cert.pem,
            host="192.168.1.50",
            https_port=8123,
            onboarding_port=8098,
            allow_regeneration=True,
        )
        httpd = server.OnboardingServer(("127.0.0.1", 0), settings, self.cert)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        request = urllib.request.Request(
            f"http://127.0.0.1:{httpd.server_port}/api/regenerate-server-certificate",
            data=b'{"confirmation":"GENERATE"}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with mock.patch.object(
                server,
                "regenerate_server_certificate",
                return_value="Certificate generated",
            ) as regenerate:
                with urllib.request.urlopen(request, timeout=2) as response:
                    payload = json.load(response)
                self.assertEqual(payload["message"], "Certificate generated")
                regenerate.assert_called_once()
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2)

    def test_unknown_path_is_404(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.fetch("does-not-exist")
        self.assertEqual(caught.exception.code, 404)
        caught.exception.close()


if __name__ == "__main__":
    unittest.main()
