"""Exercise the CI cookie verifier with synthetic responses and real curl cookie loading."""

import contextlib
import http.server
import io
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import verify_gitlab_cookies


class CookieVerificationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.cookie_file = Path(self.directory.name) / "cookies.txt"
        self.cookie_file.write_text(
            "# Netscape HTTP Cookie File\n"
            "#HttpOnly_127.0.0.1\tFALSE\t/\tFALSE\t0\tsession\tsynthetic-cookie\n"
        )
        self.cookie_file.chmod(0o600)
        self.status = 200
        self.body = b'{"id": 123, "username": "synthetic-user"}'
        self.requests = []
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                fixture.requests.append((self.path, self.headers.get("Cookie")))
                if self.headers.get("Cookie") != "session=synthetic-cookie":
                    self.send_response(401)
                    self.end_headers()
                    return
                self.send_response(fixture.status)
                self.send_header("Location", "/sign-in")
                self.end_headers()
                self.wfile.write(fixture.body)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        self.url = f"http://127.0.0.1:{server.server_port}/api/v4/user"

    def test_sends_saved_session_cookie(self):
        verify_gitlab_cookies.verify_cookies(self.cookie_file, self.url)
        self.assertEqual(self.requests, [("/api/v4/user", "session=synthetic-cookie")])

    def test_missing_and_empty_cookie_files_cannot_authenticate(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                if missing:
                    self.cookie_file.unlink()
                else:
                    self.cookie_file.write_text("# Netscape HTTP Cookie File\n")
                with self.assertRaisesRegex(ValueError, "HTTP 200"):
                    verify_gitlab_cookies.verify_cookies(self.cookie_file, self.url)

    def test_cookies_for_other_hosts_cannot_authenticate(self):
        self.cookie_file.write_text(self.cookie_file.read_text().replace("127.0.0.1", "auth.example"))
        with self.assertRaisesRegex(ValueError, "HTTP 200"):
            verify_gitlab_cookies.verify_cookies(self.cookie_file, self.url)

    def test_rejects_redirect_without_following_it(self):
        self.status = 302
        with self.assertRaisesRegex(ValueError, "HTTP 200"):
            verify_gitlab_cookies.verify_cookies(self.cookie_file, self.url)
        self.assertEqual(len(self.requests), 1)

    def test_rejects_http_error(self):
        self.status = 401
        with self.assertRaisesRegex(ValueError, "HTTP 200"):
            verify_gitlab_cookies.verify_cookies(self.cookie_file, self.url)

    def test_rejects_login_html_without_echoing_response(self):
        self.body = b'<html>Sign in to CERN <input value="synthetic-secret"></html>'
        with self.assertRaisesRegex(ValueError, "did not return JSON") as caught:
            verify_gitlab_cookies.verify_cookies(self.cookie_file, self.url)
        self.assertNotIn("synthetic-secret", str(caught.exception))

    def test_requires_valid_authenticated_user(self):
        for body in (b'{}', b'null', b'[]', b'{"id": true, "username": "user"}',
                     b'{"id": 0, "username": "user"}', b'{"id": 1, "username": ""}'):
            with self.subTest(body=body):
                self.body = body
                with self.assertRaisesRegex(ValueError, "authenticated user"):
                    verify_gitlab_cookies.verify_cookies(self.cookie_file, self.url)

    def test_command_failure_never_prints_curl_output(self):
        result = mock.Mock(returncode=1, stdout="synthetic-secret", stderr="synthetic-secret")
        output = io.StringIO()
        with mock.patch.object(verify_gitlab_cookies.subprocess, "run", return_value=result), \
                mock.patch("sys.argv", ["verify_gitlab_cookies.py", str(self.cookie_file)]), \
                contextlib.redirect_stderr(output):
            self.assertEqual(verify_gitlab_cookies.main(), 1)
        self.assertIn("request failed", output.getvalue())
        self.assertNotIn("synthetic-secret", output.getvalue())


if __name__ == "__main__":
    unittest.main()
