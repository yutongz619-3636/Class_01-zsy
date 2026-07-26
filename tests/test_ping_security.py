import subprocess
import unittest
from unittest.mock import patch

from app import app


class PingSecurityTest(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True, SECRET_KEY="test-only-secret")
        self.client = app.test_client()
        with self.client.session_transaction() as session_data:
            session_data["username"] = "admin"

    @patch("app.subprocess.check_output")
    def test_rejects_command_injection_payload(self, check_output):
        response = self.client.post("/ping", data={"ip": "127.0.0.1; whoami"})

        self.assertEqual(response.status_code, 200)
        self.assertIn("IP 地址格式无效", response.get_data(as_text=True))
        check_output.assert_not_called()

    @patch("app.platform.system", return_value="Linux")
    @patch("app.subprocess.check_output", return_value=b"PING OK")
    def test_linux_ping_uses_argument_list(self, check_output, _platform_system):
        response = self.client.post("/ping", data={"ip": "127.0.0.1"})

        self.assertEqual(response.status_code, 200)
        self.assertIn("PING OK", response.get_data(as_text=True))
        check_output.assert_called_once_with(
            ["ping", "-c", "3", "127.0.0.1"],
            shell=False,
            stderr=subprocess.STDOUT,
            timeout=30,
        )

    @patch("app.platform.system", return_value="Windows")
    @patch("app.subprocess.check_output", return_value=b"PING OK")
    def test_windows_ping_uses_n_flag(self, check_output, _platform_system):
        self.client.post("/ping", data={"ip": "::1"})

        check_output.assert_called_once_with(
            ["ping", "-n", "3", "::1"],
            shell=False,
            stderr=subprocess.STDOUT,
            timeout=30,
        )


if __name__ == "__main__":
    unittest.main()
