import importlib.util
import json
import plistlib
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
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

    def test_unknown_path_is_404(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.fetch("does-not-exist")
        self.assertEqual(caught.exception.code, 404)
        caught.exception.close()


if __name__ == "__main__":
    unittest.main()
