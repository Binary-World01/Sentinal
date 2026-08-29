"""
AP Payment Fraud Sentinel — Comprehensive End-to-End Integration Test Suite
=============================================================================
Verifies all 7 production sub-systems:
  Section 1: System Health, Config & Multi-Tenant Schema
  Section 2: Master Vendor Registry CRUD (Supabase Cloud + SQLite Sync)
  Section 3: Document Ingestion & Stage 1 Smart Pre-Check Validator
  Section 4: Multi-Agent Forensic Fraud Analysis & Risk Tiers (CLEAN, HOLD, BEC)
  Section 5: Human-In-The-Loop Desk & Payout Guardrails
  Section 6: One-Click Payout Execution & Payment Webhook Handlers (Stripe, RazorpayX)
  Section 7: IMAP Email Polling & Audit Logs
"""

import unittest
import requests
import json
import time
import os

BASE_URL = "http://localhost:8000"
ADMIN_HEADERS = {"X-Sentinel-Role": "admin", "X-Sentinel-User": "admin@sentinel.finance"}


class TestSentinelE2EPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Ensure server is running
        try:
            r = requests.get(f"{BASE_URL}/api/health", timeout=3)
            if r.status_code != 200:
                raise Exception("Server not responding")
        except Exception:
            raise unittest.SkipTest("Server is not running on http://localhost:8000. Run server before integration tests.")

    # ── Section 1: Health & Config ───────────────────────────────────────────

    def test_01_system_health(self):
        res = requests.get(f"{BASE_URL}/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("status"), "ok")
        self.assertTrue(data.get("supabase_configured"))

    def test_02_auth_config(self):
        res = requests.get(f"{BASE_URL}/api/auth/config")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("is_configured"))
        self.assertNotIn("service_key", data)

    def test_03_sql_schema_export(self):
        res = requests.get(f"{BASE_URL}/api/schema/sql", headers=ADMIN_HEADERS)
        self.assertEqual(res.status_code, 200)
        self.assertIn("public.vendors", res.json().get("sql", ""))


    # ── Section 2: Master Vendor Registry CRUD ─────────────────────────────────

    def test_04_vendor_registry_crud(self):
        # 1. Create
        v_payload = {
            "vendor_name": "E2E Test Vendor Ltd",
            "verified_domain": "e2e-test-vendor.com",
            "bank_account_number": "1122334455",
            "bank_routing_code": "021000021",
            "contact_phone": "+1-800-555-9999",
            "avg_invoice_amount": 10000.0,
            "status": "ACTIVE"
        }
        res_create = requests.post(f"{BASE_URL}/api/vendors", json=v_payload, headers=ADMIN_HEADERS)
        self.assertEqual(res_create.status_code, 201)
        v_id = res_create.json().get("id")

        # 2. Query
        res_list = requests.get(f"{BASE_URL}/api/vendors")
        self.assertEqual(res_list.status_code, 200)
        self.assertTrue(any(v.get("id") == v_id for v in res_list.json()))

        # 3. Update
        v_payload["avg_invoice_amount"] = 15000.0
        res_edit = requests.put(f"{BASE_URL}/api/vendors/{v_id}", json=v_payload, headers=ADMIN_HEADERS)
        self.assertEqual(res_edit.status_code, 200)

        # 4. Delete
        res_del = requests.delete(f"{BASE_URL}/api/vendors/{v_id}", headers=ADMIN_HEADERS)
        self.assertEqual(res_del.status_code, 200)

    # ── Section 3: Smart Pre-Check Document Ingestion ─────────────────────────

    def test_05_non_invoice_document_rejected(self):
        fake_file = ("meeting_notes.txt", b"Notes from marketing sync meeting on Tuesday afternoon.")
        res = requests.post(f"{BASE_URL}/api/audit/upload", files={"file": fake_file})
        self.assertEqual(res.status_code, 400)
        self.assertIn("Non-Invoice Document Rejected", res.json().get("detail", ""))

    def test_06_valid_invoice_document_accepted(self):
        invoice_text = b"COMMERCIAL INVOICE\nVendor: GlobalTech Supplies\nInvoice Number: INV-E2E-001\nTotal Amount Due: $4,500.00 USD\nRemit to Bank Account: 987654321\nRouting: 021000021\nDue Date: Net 30"
        res = requests.post(f"{BASE_URL}/api/audit/upload", files={"file": ("invoice_sample.txt", invoice_text)})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("_document_precheck"), "PASSED")

    # ── Section 4: Forensic Fraud Auditing & BEC Interception ─────────────────

    def test_07_clean_invoice_audit(self):
        payload = {
            "invoice_id": "INV-2026-CLEAN-E2E",
            "vendor_name": "Acme Corp",
            "sender_domain": "acme-corp.com",
            "sender_email": "invoices@acme-corp.com",
            "invoice_number": "INV-2026-CLEAN-E2E",
            "invoice_amount": 4500.0,
            "bank_account_number": "123456789",
            "bank_routing_code": "021000021"
        }
        res = requests.post(f"{BASE_URL}/api/audit/single", json=payload)
        self.assertEqual(res.status_code, 200)
        verdict = res.json()
        self.assertEqual(verdict.get("risk_tier"), "CLEAN")
        self.assertTrue(verdict.get("payout_eligible"))
        self.assertFalse(verdict.get("hitl_required"))

    def test_08_bec_attack_interception(self):
        payload = {
            "invoice_id": "INV-2026-BEC-E2E",
            "vendor_name": "Acme Corp",
            "sender_domain": "acme-c0rp.com",
            "sender_email": "ceo@acme-c0rp.com",
            "invoice_number": "INV-2026-BEC-E2E",
            "invoice_amount": 84500.0,
            "bank_account_number": "999888777",
            "bank_routing_code": "021000021",
            "urgency_language_detected": True,
            "bank_change_request": True,
            "notes_or_text": "URGENT WIRE TRANSFER REQUIRED: Bank account updated per CFO instructions. Do not discuss."
        }
        res = requests.post(f"{BASE_URL}/api/audit/single", json=payload)
        self.assertEqual(res.status_code, 200)
        verdict = res.json()
        self.assertEqual(verdict.get("risk_tier"), "HOLD")
        self.assertFalse(verdict.get("payout_eligible"))
        self.assertTrue(verdict.get("hitl_required"))

    # ── Section 5: HITL Resolution & Guardrails ──────────────────────────────

    def test_09_block_payout_on_frozen_hold(self):
        res = requests.post(
            f"{BASE_URL}/api/invoices/INV-2026-BEC-E2E/pay",
            json={"payment_method": "STRIPE_CONNECT"},
            headers=ADMIN_HEADERS
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("Payment Blocked", res.json().get("detail", ""))

    def test_10_hitl_manual_release(self):
        res = requests.post(
            f"{BASE_URL}/api/invoices/INV-2026-BEC-E2E/hitl",
            json={"action": "APPROVE", "actor": "Senior AP Controller", "notes": "Verified via voice callback"},
            headers=ADMIN_HEADERS
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json().get("updated_status"), "APPROVED")

    # ── Section 6: One-Click Payout & Webhook Listeners ───────────────────────

    def test_11_one_click_payout_execution(self):
        res = requests.post(
            f"{BASE_URL}/api/invoices/INV-2026-CLEAN-E2E/pay",
            json={"payment_method": "STRIPE_CONNECT", "actor": "AP Finance Director"},
            headers=ADMIN_HEADERS
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("status"), "success")
        self.assertTrue(data.get("payout_tx_id", "").startswith("payout_stripe_connect_"))

    def test_12_stripe_webhook_listener(self):
        evt = {
            "type": "payout.paid",
            "data": {
                "object": {
                    "id": "payout_stripe_e2e_test",
                    "metadata": {"invoice_id": "INV-2026-CLEAN-E2E"}
                }
            }
        }
        res = requests.post(f"{BASE_URL}/api/webhooks/stripe", json=evt)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json().get("status"), "success")

    def test_13_razorpayx_webhook_listener(self):
        evt = {
            "event": "payout.failed",
            "payload": {
                "payout": {
                    "entity": {
                        "id": "payout_rzp_e2e_fail",
                        "status_details": {"description": "Beneficiary account closed"}
                    }
                }
            }
        }
        res = requests.post(f"{BASE_URL}/api/webhooks/razorpayx", json=evt)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json().get("status"), "handled_failure")

    # ── Section 7: IMAP Email Sync & Audit Logs ──────────────────────────────

    def test_14_email_sync_trigger(self):
        res = requests.post(f"{BASE_URL}/api/email/sync", headers=ADMIN_HEADERS)
        self.assertEqual(res.status_code, 200)

    def test_15_email_logs_query(self):
        res = requests.get(f"{BASE_URL}/api/email/logs")
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), list)

    def test_16_admin_telemetry_query(self):
        res = requests.get(f"{BASE_URL}/api/admin/telemetry", headers=ADMIN_HEADERS)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("engine", data)
        self.assertIn("metrics", data)


if __name__ == "__main__":
    unittest.main()
