import tempfile
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from app import PING_ATTEMPTS, app, create_user, db_session, init_db


class PingSecurityTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_config = {
            key: app.config.get(key) for key in ("TESTING", "SECRET_KEY", "DATABASE_PATH", "PING_ALLOWED_NETWORKS")
        }
        app.config.update(
            TESTING=True,
            SECRET_KEY="test-only-secret",
            DATABASE_PATH=str(Path(self.temp_dir.name) / "users.db"),
            PING_ALLOWED_NETWORKS="127.0.0.0/8,::1/128",
        )
        init_db()
        with db_session() as connection:
            create_user(connection, "pinguser", "SecurePass123")
            row = connection.execute("SELECT id FROM users WHERE username = ?", ("pinguser",)).fetchone()
        self.client = app.test_client()
        with self.client.session_transaction() as session_data:
            session_data["user_id"] = row["id"]
            session_data["_csrf_token"] = "csrf-test-token"
        PING_ATTEMPTS.clear()

    def tearDown(self):
        PING_ATTEMPTS.clear()
        app.config.update(self.original_config)
        self.temp_dir.cleanup()

    def post_ping(self, ip, csrf_token="csrf-test-token"):
        return self.client.post("/ping", data={"ip": ip, "csrf_token": csrf_token})

    @patch("app.subprocess.check_output")
    def test_rejects_command_injection_payload(self, check_output):
        payloads = [
            "127.0.0.1; whoami",
            "127.0.0.1 && whoami",
            "127.0.0.1 | whoami",
            "127.0.0.1 $(whoami)",
            "127.0.0.1 `whoami`",
            "127.0.0.1\nwhoami",
            "127.0.0.1 & calc.exe",
            "%COMSPEC% /c whoami",
            "-n 1 127.0.0.1",
            "localhost",
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                check_output.reset_mock()
                response = self.post_ping(payload)
                self.assertEqual(response.status_code, 200)
                self.assertIn("IP 地址格式无效", response.get_data(as_text=True))
                check_output.assert_not_called()

    @patch("app.subprocess.check_output")
    def test_missing_csrf_does_not_run_ping(self, check_output):
        response = self.client.post("/ping", data={"ip": "127.0.0.1"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("请求校验失败", response.get_data(as_text=True))
        check_output.assert_not_called()

    @patch("app.shutil.which", return_value="ping")
    @patch("app.subprocess.check_output", return_value=b"PING OK")
    @patch("app.platform.system", return_value="Linux")
    def test_linux_ping_uses_argument_list(self, _platform_system, check_output, _which):
        response = self.post_ping("127.0.0.1")
        self.assertEqual(response.status_code, 200)
        self.assertIn("PING OK", response.get_data(as_text=True))
        check_output.assert_called_once_with(
            ["ping", "-c", "3", "127.0.0.1"],
            shell=False,
            stderr=subprocess.STDOUT,
            timeout=30,
        )

    @patch("app.shutil.which", return_value="ping")
    @patch("app.subprocess.check_output", return_value=b"PING OK")
    @patch("app.platform.system", return_value="Windows")
    def test_windows_ping_uses_n_flag(self, _platform_system, check_output, _which):
        response = self.post_ping("::1")
        self.assertEqual(response.status_code, 200)
        check_output.assert_called_once_with(
            ["ping", "-n", "3", "::1"],
            shell=False,
            stderr=subprocess.STDOUT,
            timeout=30,
        )

    @patch("app.subprocess.check_output")
    def test_private_targets_are_blocked_by_default_and_never_executed(self, check_output):
        app.config["PING_ALLOWED_NETWORKS"] = ""
        for target in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fe80::1"):
            with self.subTest(target=target):
                check_output.reset_mock()
                response = self.post_ping(target)
                self.assertEqual(response.status_code, 403)
                self.assertIn("不在允许的网络范围", response.get_data(as_text=True))
                check_output.assert_not_called()

    @patch("app.shutil.which", return_value="ping")
    @patch("app.subprocess.check_output", return_value=b"PING OK")
    def test_ping_rate_limit_prevents_worker_exhaustion(self, _check_output, _which):
        for _ in range(5):
            self.assertEqual(self.post_ping("127.0.0.1").status_code, 200)
        response = self.post_ping("127.0.0.1")
        self.assertEqual(response.status_code, 429)
        self.assertIn("过于频繁", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
