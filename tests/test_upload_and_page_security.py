import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PIL import Image

from app import UPLOAD_LAST_ACTION, app, create_user, db_session, init_db


def png_bytes():
    content = io.BytesIO()
    Image.new("RGB", (2, 2), "#336699").save(content, format="PNG")
    content.seek(0)
    return content


class UploadAndPageSecurityTest(unittest.TestCase):
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
        UPLOAD_LAST_ACTION.clear()
        with db_session() as connection:
            create_user(connection, "uploaduser", "SecurePass123")
            row = connection.execute("SELECT id FROM users WHERE username = ?", ("uploaduser",)).fetchone()
        self.upload_dir = Path(self.temp_dir.name) / "private-uploads"
        self.upload_dir.mkdir()
        self.upload_patch = patch("app.PRIVATE_UPLOAD_DIR", self.upload_dir)
        self.upload_patch.start()
        self.client = app.test_client()
        with self.client.session_transaction() as session_data:
            session_data["user_id"] = row["id"]
            session_data["_csrf_token"] = "csrf-test-token"

    def tearDown(self):
        UPLOAD_LAST_ACTION.clear()
        self.upload_patch.stop()
        app.config.update(self.original_config)
        self.temp_dir.cleanup()

    def upload(self, content, filename, csrf_token="csrf-test-token"):
        return self.client.post(
            "/upload",
            data={"csrf_token": csrf_token, "file": (content, filename)},
            content_type="multipart/form-data",
        )

    def test_upload_requires_valid_csrf_before_writing_file(self):
        response = self.upload(png_bytes(), "avatar.png", csrf_token="invalid")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(list(self.upload_dir.iterdir()), [])

    def test_upload_rejects_forged_image_header(self):
        fake_jpeg = io.BytesIO(b"\xff\xd8\xffnot-a-real-image")
        response = self.upload(fake_jpeg, "fake.jpg")
        self.assertEqual(response.status_code, 400)
        self.assertIn("不是有效且安全的图片", response.get_data(as_text=True))
        self.assertEqual(list(self.upload_dir.iterdir()), [])

    def test_valid_avatar_is_private_and_reencoded(self):
        response = self.upload(png_bytes(), "profile.png")
        self.assertEqual(response.status_code, 200)
        saved_files = list(self.upload_dir.glob("*.png"))
        self.assertEqual(len(saved_files), 1)
        self.assertTrue(saved_files[0].read_bytes().startswith(b"\x89PNG\r\n\x1a\n"))

        avatar_response = self.client.get("/avatar")
        self.assertEqual(avatar_response.status_code, 200)
        self.assertEqual(avatar_response.mimetype, "image/png")
        avatar_response.close()
        anonymous = app.test_client().get("/avatar")
        self.assertEqual(anonymous.status_code, 302)

    def test_page_route_uses_fixed_template_allowlist(self):
        self.assertEqual(self.client.get("/page?name=help").status_code, 200)
        for payload in ("../../app.py", "..\\..\\app.py", "C:\\Windows\\win.ini", "unknown"):
            response = self.client.get("/page", query_string={"name": payload})
            self.assertEqual(response.status_code, 404)
            self.assertNotIn("import sqlite3", response.get_data(as_text=True))

    def test_security_headers_are_present(self):
        response = self.client.get("/welcome")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("Content-Security-Policy", response.headers)


if __name__ == "__main__":
    unittest.main()
