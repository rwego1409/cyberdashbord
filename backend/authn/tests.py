from django.test import TestCase
from rest_framework.test import APIClient


class AuthnAdminEndpointsTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.headers = {"HTTP_X_DEBUG_ROLE": "owner"}
        self.client.post(
            "/api/v1/authn/bootstrap/",
            {
                "username": "admin_test",
                "password": "ChangeMe123!",
                "email": "admin_test@example.com",
                "role": "owner",
                "organization": "TCIO Test",
            },
            format="json",
            **self.headers,
        )

    def test_users_list_and_api_keys(self):
        users_response = self.client.get("/api/v1/authn/users/", **self.headers)
        self.assertEqual(users_response.status_code, 200)
        self.assertGreaterEqual(users_response.json().get("count", 0), 1)

        keys_response = self.client.get("/api/v1/authn/api-keys/", **self.headers)
        self.assertEqual(keys_response.status_code, 200)
        self.assertGreaterEqual(keys_response.json().get("count", 0), 1)

    def test_role_update(self):
        response = self.client.post(
            "/api/v1/authn/users/admin_test/role/",
            {"role": "analyst"},
            format="json",
            **self.headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json().get("role"), "analyst")
