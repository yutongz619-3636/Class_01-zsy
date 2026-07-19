import sys
import time
import unittest
from pathlib import Path

from werkzeug.security import generate_password_hash


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app import LOGIN_ATTEMPTS, USERS, app  # noqa: E402


class LoginSecurityTest(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True, SECRET_KEY="test-only-secret")
        LOGIN_ATTEMPTS.clear()
        self.client = app.test_client()
        self.original_hash = USERS["admin"]["password_hash"]
        USERS["admin"]["password_hash"] = generate_password_hash("test-password")

    def tearDown(self):
        USERS["admin"]["password_hash"] = self.original_hash
        LOGIN_ATTEMPTS.clear()

    def post_login(self, password, username="admin"):
        return self.client.post(
            "/login",
            data={"username": username, "password": password},
        )

    def test_anonymous_page_requires_login(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("请先登录", response.get_data(as_text=True))

    def test_successful_login_does_not_display_password(self):
        response = self.post_login("test-password")
        self.assertEqual(response.status_code, 302)

        page = self.client.get("/").get_data(as_text=True)
        self.assertIn("欢迎回来，admin", page)
        self.assertNotIn("test-password", page)
        self.assertNotIn("password_hash", page)
        self.assertNotIn("密码</span>", page)

    def test_failed_login_counts_remaining_attempts(self):
        response = self.post_login("wrong-password")
        self.assertEqual(response.status_code, 401)
        self.assertIn("还可尝试 4 次", response.get_data(as_text=True))

    def test_fifth_failure_locks_login(self):
        for _ in range(4):
            self.assertEqual(self.post_login("wrong-password").status_code, 401)

        response = self.post_login("wrong-password")
        self.assertEqual(response.status_code, 429)
        self.assertIn("账号已锁定 60 秒", response.get_data(as_text=True))

        response = self.post_login("test-password")
        self.assertEqual(response.status_code, 429)
        self.assertIn("秒后重试", response.get_data(as_text=True))

    def test_login_works_after_lock_expires(self):
        for _ in range(5):
            self.post_login("wrong-password")

        key = ("127.0.0.1", "admin")
        LOGIN_ATTEMPTS[key]["locked_until"] = time.time() - 1
        response = self.post_login("test-password")
        self.assertEqual(response.status_code, 302)
        self.assertNotIn(key, LOGIN_ATTEMPTS)

    def test_logout_clears_session(self):
        self.post_login("test-password")
        response = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("请先登录", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
