import unittest

from app import app


class TemplateSecurityTest(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True, SECRET_KEY="test-only-secret")
        self.client = app.test_client()
        with self.client.session_transaction() as session_data:
            session_data["username"] = "admin"
            session_data["_csrf_token"] = "csrf-test-token"

    def test_welcome_page_does_not_evaluate_template_expression(self):
        response = self.client.get("/welcome?name={{ 7*7 }}")

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("{{ 7*7 }}", body)
        self.assertNotIn("49", body)

    def test_feedback_page_does_not_evaluate_template_expression(self):
        response = self.client.post(
            "/feedback",
            data={
                "csrf_token": "csrf-test-token",
                "name": "{{ 7*7 }}",
                "message": "{{ 8*8 }}",
            },
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("{{ 7*7 }}", body)
        self.assertIn("{{ 8*8 }}", body)
        self.assertNotIn("49", body)
        self.assertNotIn("64", body)


if __name__ == "__main__":
    unittest.main()
