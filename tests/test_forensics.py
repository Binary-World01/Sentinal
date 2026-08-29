"""
AP Payment Fraud Sentinel — Forensic Rules Unit Tests (SSOT)
=============================================================
Tests deterministic algorithms in backend/forensics.py:
1. Levenshtein edit distance
2. Homoglyph normalization & Typosquatting detection
3. ISO 7064 MOD-97 IBAN checksum validation
4. US ABA Federal Reserve Routing checksum validation
5. Amount velocity & smurfing detection
6. run_deterministic_forensics pre-flight synthesizer
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import unittest
from backend.forensics import (
    levenshtein_distance,
    normalize_domain_homoglyphs,
    detect_domain_typosquat,
    validate_iban_mod97,
    validate_aba_routing,
    analyze_amount_velocity,
    run_deterministic_forensics,
)



class TestForensicEngine(unittest.TestCase):

    def test_levenshtein_distance(self):
        self.assertEqual(levenshtein_distance("acme", "acme"), 0)
        self.assertEqual(levenshtein_distance("acme", "acm3"), 1)
        self.assertEqual(levenshtein_distance("globaltech", "g1obaltech"), 1)

    def test_homoglyph_normalization(self):
        self.assertEqual(normalize_domain_homoglyphs("acme-c0rp.com"), normalize_domain_homoglyphs("acmecorp.com"))
        self.assertEqual(normalize_domain_homoglyphs("g1obaltech.com"), normalize_domain_homoglyphs("globaltech.com"))
        self.assertEqual(normalize_domain_homoglyphs("micros0ft.com"), normalize_domain_homoglyphs("microsoft.com"))

    def test_detect_domain_typosquat(self):
        known = ["acme-corp.com", "globaltech-supplies.com", "vertex-office.com"]
        
        # Exact match -> Not typosquat
        is_typo, target, sim = detect_domain_typosquat("acme-corp.com", known)
        self.assertFalse(is_typo)

        # Typosquat (0 instead of o)
        is_typo, target, sim = detect_domain_typosquat("acme-c0rp.com", known)
        self.assertTrue(is_typo)
        self.assertEqual(target, "acme-corp.com")

        # Typosquat (1 instead of l)
        is_typo, target, sim = detect_domain_typosquat("g1obaltech-supplies.com", known)
        self.assertTrue(is_typo)
        self.assertEqual(target, "globaltech-supplies.com")

    def test_validate_iban_mod97(self):
        # Valid GB IBAN structure
        valid_iban = "GB82WEST12345698765432"
        ok, err = validate_iban_mod97(valid_iban)
        self.assertTrue(ok)

        # Invalid checksum
        invalid_iban = "GB00WEST12345698765432"
        ok, err = validate_iban_mod97(invalid_iban)
        self.assertFalse(ok)

    def test_validate_aba_routing(self):
        # Valid Federal Reserve ABA routing: Chase 021000021 -> (3*0 + 7*2 + 1*1 + 3*0 + 7*0 + 1*0 + 3*0 + 7*2 + 1*1 = 14+1+14+1 = 30 -> mod 10 == 0)
        ok, err = validate_aba_routing("021000021")
        self.assertTrue(ok)

        # Invalid routing checksum
        ok, err = validate_aba_routing("123456789")
        self.assertFalse(ok)

    def test_analyze_amount_velocity(self):
        # Normal amount
        res = analyze_amount_velocity(5000.0, 5000.0, 10000.0)
        self.assertFalse(res["velocity_spike"])
        self.assertFalse(res["exceeds_max_historical"])

        # Velocity spike (+200%)
        res_spike = analyze_amount_velocity(15000.0, 5000.0, 10000.0)
        self.assertTrue(res_spike["velocity_spike"])
        self.assertTrue(res_spike["exceeds_max_historical"])
        self.assertEqual(res_spike["deviation_pct"], 200.0)

    def test_run_deterministic_forensics(self):
        vendor_master = {
            "vendor_name": "Acme Corp",
            "known_domains": ["acme-corp.com"],
            "bank_account_number": "123456789",
            "routing_number": "021000021",
            "avg_invoice_amount": 5000.0,
            "status": "ACTIVE"
        }

        # Clean invoice
        clean_inv = {
            "sender_domain": "acme-corp.com",
            "bank_account_number": "123456789",
            "routing_number": "021000021",
            "invoice_amount": 4500.0
        }
        findings_clean = run_deterministic_forensics(clean_inv, vendor_master)
        self.assertEqual(findings_clean["deterministic_score_penalty"], 0.0)
        self.assertFalse(findings_clean["bank_account_changed"])

        # BEC Attack: Changed bank account + typosquatted domain
        bec_inv = {
            "sender_domain": "acme-c0rp.com",
            "bank_account_number": "999888777",
            "routing_number": "021000021",
            "invoice_amount": 84500.0
        }
        findings_bec = run_deterministic_forensics(bec_inv, vendor_master)
        self.assertTrue(findings_bec["bank_account_changed"])
        self.assertTrue(findings_bec["typosquat"]["detected"])
        self.assertTrue(findings_bec["velocity"]["velocity_spike"])
        self.assertGreaterEqual(findings_bec["deterministic_score_penalty"], 0.60)


if __name__ == "__main__":
    unittest.main()
