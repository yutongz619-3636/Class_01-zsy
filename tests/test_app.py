import tempfile
import time
import unittest
from pathlib import Path

from werkzeug.security import check_password_hash

from app import LOGIN_ATTEMPTS, PING_ATTEMPTS, UPLOAD_LAST_ACTION, app, db_session, init_db


class AuthenticationSecurityTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_config = {
            key: app.config.get(key)
            for key in ("TESTING", "SECRET_KEY", "DATABASE_PATH", "PING_ALLOWED_NETWORKS")
        }
        app.config.update(
            TESTING=True,
            SECRET_KEY="test-only-secret",
            DATABASE_PATH=str(Path(self.temp_dir.name) / "users.db"),
            PING_ALLOWED_NETWORKS="",
        )
        init_db()
        LOGIN_ATTEMPTS.clear()
        PING_ATTEMPTS.clear()
        UPLOAD_LAST_ACTION.clear()
        self.client = app.test_client()

    def tearDown(self):
        LOGIN_ATTEMPTS.clear()
        PING_ATTEMPTS.clear()
        UPLOAD_LAST_ACTION.clear()
        app.config.update(self.original_config)
        self.temp_dir.cleanup()

    def csrf_token(self, client=None):
        client = client or self.client
        with client.session_transaction() as session_data:
            session_data["_csrf_token"] = "csrf-test-token"
        return "csrf-test-token"

    def register(self, username="alice", password="SecurePass123", client=None, **extra):
        client = client or self.client
        return client.post(
            "/register",
            data={
                "csrf_token": self.csrf_token(client),
                "username": username,
                "password": password,
                "email": extra.get("email", f"{username}@example.com"),
                "phone": extra.get("phone", "13800138000"),
            },
        )

    def login(self, username="alice", password="SecurePass123", client=None):
        client = client or self.client
        return client.post(
            "/login",
            data={"csrf_token": self.csrf_token(client), "username": username, "password": password},
        )

    def user_id(self, username):
        with db_session() as connection:
            row = connection.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        return row["id"]

    def test_registration_hashes_password_and_login_uses_database(self):
        response = self.register()
        self.assertEqual(response.status_code, 201)
        with db_session() as connection:
            row = connection.execute(
                "SELECT password_hash FROM users WHERE username = ?", ("alice",)
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertNotEqual(row["password_hash"], "SecurePass123")
        self.assertTrue(check_password_hash(row["password_hash"], "SecurePass123"))

        response = self.login()
        self.assertEqual(response.status_code, 302)
        page = self.client.get("/").get_data(as_text=True)
        self.assertIn("欢迎回来，alice", page)
        self.assertNotIn("SecurePass123", page)
        self.assertNotIn("密码</span>", page)

    def test_failed_login_locks_after_five_attempts(self):
        self.register()
        for _ in range(4):
            response = self.login(password="wrong-password")
            self.assertEqual(response.status_code, 401)
        response = self.login(password="wrong-password")
        self.assertEqual(response.status_code, 429)
        self.assertIn("账号已锁定", response.get_data(as_text=True))

        response = self.login()
        self.assertEqual(response.status_code, 429)

        key = ("127.0.0.1", "alice")
        LOGIN_ATTEMPTS[key]["locked_until"] = time.time() - 1
        response = self.login()
        self.assertEqual(response.status_code, 302)
        self.assertNotIn(key, LOGIN_ATTEMPTS)

    def test_profile_ignores_another_users_id_and_change_password_is_self_only(self):
        self.register(username="alice", email="alice@private.example")
        alice_id = self.user_id("alice")
        other_client = app.test_client()
        self.register(username="bob", password="OtherPass123", client=other_client, email="bob@private.example")
        self.login(username="bob", password="OtherPass123", client=other_client)

        profile = other_client.get(f"/profile?user_id={alice_id}")
        body = profile.get_data(as_text=True)
        self.assertEqual(profile.status_code, 200)
        self.assertIn("bob@private.example", body)
        self.assertNotIn("alice@private.example", body)

        response = other_client.post(
            "/change-password",
            data={
                "csrf_token": self.csrf_token(other_client),
                "username": "alice",  # 伪造字段应被服务端忽略
                "current_password": "OtherPass123",
                "new_password": "NewBobPass123",
                "confirm_password": "NewBobPass123",
            },
        )
        self.assertEqual(response.status_code, 302)

        fresh_client = app.test_client()
        self.assertEqual(self.login(username="alice", client=fresh_client).status_code, 302)
        self.assertEqual(self.login(username="bob", password="OtherPass123", client=other_client).status_code, 401)
        self.assertEqual(self.login(username="bob", password="NewBobPass123", client=other_client).status_code, 302)

    def test_state_changing_logout_requires_csrf(self):
        self.register()
        self.login()
        self.assertEqual(self.client.post("/logout").status_code, 400)
        self.assertEqual(
            self.client.post("/logout", data={"csrf_token": self.csrf_token()}).status_code,
            302,
        )
        self.assertIn("请先登录", self.client.get("/").get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
