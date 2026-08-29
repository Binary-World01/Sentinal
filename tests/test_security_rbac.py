"""
AP Payment Fraud Sentinel — Security & RBAC Unit Tests
======================================================
Tests:
1. Public endpoints accessibility (health, auth config, static files)
2. Admin endpoint protection with 403 Forbidden for unauthorized requests
3. Admin access granted when valid authorization header / role provided
4. Error sanitization (no stack traces or SQL errors leaked to clients)
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import unittest
from fastapi.testclient import TestClient
from backend.server import app


client = TestClient(app)


class TestSecurityAndRBAC(unittest.TestCase):

    def test_public_health_endpoint(self):
        """Public health endpoint must be accessible without credentials."""
        res = client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("status"), "ok")
        self.assertIn("rocketride_online", data)
        # Verify no secret keys leaked
        self.assertNotIn("service_role", str(data).lower())
        self.assertNotIn("secret_key", str(data).lower())

    def test_public_auth_config_leak_prevention(self):
        """Auth config must return only public anon key and URL, never service role key."""
        res = client.get("/api/auth/config")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("supabase_url", data)
        self.assertIn("supabase_anon_key", data)
        self.assertNotIn("service_role", data)
        self.assertNotIn("supabase_service_key", data)

    def test_admin_telemetry_forbidden_for_standard_user(self):
        """Standard user must be rejected with 403 Forbidden from admin telemetry."""
        res = client.get(
            "/api/admin/telemetry",
            headers={"X-Sentinel-Role": "analyst", "X-Sentinel-User": "analyst@company.com"}
        )
        self.assertEqual(res.status_code, 403)
        self.assertIn("Administrative privileges required", res.json().get("detail", ""))

    def test_admin_telemetry_allowed_for_admin(self):
        """Authorized administrator can retrieve full telemetry metrics."""
        res = client.get(
            "/api/admin/telemetry",
            headers={"X-Sentinel-Role": "admin", "X-Sentinel-User": "admin@sentinel.finance"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("engine", data)
        self.assertIn("metrics", data)
        self.assertIn("active_models", data)

    def test_admin_vendor_mutation_protection(self):
        """Standard analyst cannot add/delete master vendors (403 Forbidden)."""
        payload = {
            "vendor_name": "Unauthorized Vendor Entry",
            "verified_domain": "unauth.com",
            "bank_account_number": "999888777"
        }
        res = client.post(
            "/api/vendors",
            json=payload,
            headers={"X-Sentinel-Role": "analyst", "X-Sentinel-User": "analyst@company.com"}
        )
        self.assertEqual(res.status_code, 403)

    def test_sanitized_400_rejection_for_non_invoice(self):
        """Non-invoice upload returns clean, human-readable 400 rejection."""
        fake_file = ("vacation_photo.txt", b"Hello this is my holiday photo with no financial content.")
        res = client.post(
            "/api/audit/upload",
            files={"file": fake_file}
        )
        self.assertEqual(res.status_code, 400)
        detail = res.json().get("detail", "")
        self.assertIn("Non-Invoice Document Rejected", detail)
        # Ensure no internal python stack traces leaked in error detail
        self.assertNotIn("Traceback", detail)
        self.assertNotIn("File \"", detail)


if __name__ == "__main__":
    unittest.main()
