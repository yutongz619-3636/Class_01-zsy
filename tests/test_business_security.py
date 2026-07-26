import tempfile
import unittest
from pathlib import Path

from app import app, create_user, db_session, init_db


class BusinessSecurityTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_config = {
            key: app.config.get(key) for key in ("TESTING", "SECRET_KEY", "DATABASE_PATH")
        }
        app.config.update(
            TESTING=True,
            SECRET_KEY="test-only-secret",
            DATABASE_PATH=str(Path(self.temp_dir.name) / "users.db"),
        )
        init_db()
        with db_session() as connection:
            create_user(connection, "member", "MemberPass123")
            create_user(connection, "administrator", "AdminPass123", role="admin")
            self.member_id = connection.execute("SELECT id FROM users WHERE username = 'member'").fetchone()["id"]
            self.admin_id = connection.execute("SELECT id FROM users WHERE username = 'administrator'").fetchone()["id"]
        self.member_client = self.make_client(self.member_id)
        self.admin_client = self.make_client(self.admin_id)

    def tearDown(self):
        app.config.update(self.original_config)
        self.temp_dir.cleanup()

    @staticmethod
    def make_client(user_id):
        client = app.test_client()
        with client.session_transaction() as session_data:
            session_data["user_id"] = user_id
            session_data["_csrf_token"] = "csrf-test-token"
        return client

    def balance(self, user_id):
        with db_session() as connection:
            return connection.execute("SELECT balance FROM users WHERE id = ?", (user_id,)).fetchone()["balance"]

    def test_recharge_creates_pending_request_without_crediting_balance(self):
        before = self.balance(self.member_id)
        response = self.member_client.post(
            "/recharge", data={"csrf_token": "csrf-test-token", "amount": "5000"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.balance(self.member_id), before)
        with db_session() as connection:
            request_row = connection.execute(
                "SELECT id, amount, status FROM recharge_requests WHERE user_id = ?", (self.member_id,)
            ).fetchone()
        self.assertEqual(request_row["amount"], 5000)
        self.assertEqual(request_row["status"], "pending")

        denied = self.member_client.post(
            f"/admin/recharge/{request_row['id']}/approve", data={"csrf_token": "csrf-test-token"}
        )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(self.balance(self.member_id), before)

        approved = self.admin_client.post(
            f"/admin/recharge/{request_row['id']}/approve", data={"csrf_token": "csrf-test-token"}
        )
        self.assertEqual(approved.status_code, 302)
        self.assertEqual(self.balance(self.member_id), before + 5000)

        review_page = self.admin_client.get("/admin/recharge-requests")
        self.assertEqual(review_page.status_code, 200)
        self.assertIn("充值审核", review_page.get_data(as_text=True))
        self.assertEqual(self.member_client.get("/admin/recharge-requests").status_code, 403)

    def test_second_pending_recharge_is_rejected(self):
        self.member_client.post(
            "/recharge", data={"csrf_token": "csrf-test-token", "amount": "1"}
        )
        response = self.member_client.post(
            "/recharge", data={"csrf_token": "csrf-test-token", "amount": "2"}
        )
        self.assertEqual(response.status_code, 302)
        with db_session() as connection:
            count = connection.execute(
                "SELECT COUNT(*) AS count FROM recharge_requests WHERE user_id = ?", (self.member_id,)
            ).fetchone()["count"]
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
