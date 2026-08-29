"""
AP Fraud Sentinel — Unified RocketRide Pipeline Manager
========================================================
Manages the lifecycle of the consolidated 3-stage RocketRide pipeline (master_ap_sentinel.pipe):
  - Generates runtime pipe files with injected Groq and Gemini API keys
  - Connects to RocketRide local (ws://localhost:5565) or cloud engine
  - Processes invoices through the 3-agent pipeline via client.send()
  - Automatic runtime Groq → Gemini failover upon rate limits or provider errors
  - Guarantees clean session teardown (no orphaned sessions)
"""

import os
import re
import json
import time
import logging
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
from typing import Optional, Dict, Any

from backend.supabase_db import (
    get_vendor_by_domain,
    get_vendor_by_email,
    check_sender_authorization,
    get_all_vendors,
)
from backend.forensics import run_deterministic_forensics

load_dotenv()
log = logging.getLogger("rocketride_runner")

SEEN_INVOICE_NUMBERS: set = set()


def enrich_invoice_payload(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pre-enrich invoice payload with authoritative Vendor Master Registry data,
    algorithmic SSOT forensics, and sender spoofing / authorization analysis.
    """
    domain = (record.get("sender_domain") or "").lower().strip()
    sender_email = (record.get("sender_email") or record.get("vendor_email") or "").lower().strip()

    # 1. Lookup Vendor Record
    master_vendor = get_vendor_by_domain(domain)
    if not master_vendor and sender_email:
        master_vendor = get_vendor_by_email(sender_email)

    all_registered_vendors = get_all_vendors()
    all_registered_domains = [v.get("verified_domain") for v in all_registered_vendors if v.get("verified_domain")]

    # If domain not directly matched, check if it typosquats an existing vendor
    if not master_vendor and domain:
        from backend.forensics import detect_domain_typosquat
        is_typo, target_dom, sim = detect_domain_typosquat(domain, all_registered_domains)
        if is_typo and target_dom:
            master_vendor = get_vendor_by_domain(target_dom)

    if master_vendor:
        known_doms = [master_vendor.get("verified_domain") or master_vendor.get("domain")]
        if domain and domain not in known_doms:
            known_doms.append(domain)
        record["_vendor_master"] = {
            "id": master_vendor.get("id"),
            "vendor_id": master_vendor.get("vendor_id"),
            "vendor_name": master_vendor.get("vendor_name") or master_vendor.get("name"),
            "primary_email": master_vendor.get("primary_email"),
            "finance_email": master_vendor.get("finance_email"),
            "verified_domain": master_vendor.get("verified_domain") or master_vendor.get("domain"),
            "known_domains": [master_vendor.get("verified_domain") or master_vendor.get("domain")],
            "bank_account_number": master_vendor.get("bank_account_number"),
            "bank_routing_code": master_vendor.get("bank_routing_code") or master_vendor.get("routing_number"),
            "iban": master_vendor.get("iban", ""),
            "contact_phone": master_vendor.get("contact_phone", ""),
            "avg_invoice_amount": float(master_vendor.get("avg_invoice_amount", 0.0) or 0.0),
            "max_invoice_ever": float(master_vendor.get("max_invoice_ever", 0.0) or 0.0),
            "status": master_vendor.get("status", "ACTIVE"),
        }
    else:
        record["_vendor_master"] = {
            "status": "NEW_VENDOR",
            "vendor_name": record.get("vendor_name", "Unknown Vendor"),
            "verified_domain": domain,
            "known_domains": [],
            "bank_account_number": None,
            "bank_routing_code": None,
            "contact_phone": None,
            "avg_invoice_amount": None,
        }


    # 2. Sender Authorization & Identity Verification
    sender_auth = check_sender_authorization(sender_email, domain)
    record["_sender_auth"] = sender_auth

    # 3. Algorithmic Forensics SSOT
    record["_deterministic_forensics"] = run_deterministic_forensics(record, record.get("_vendor_master"))

    # 4. Duplicate Invoice Detection
    inv_no = record.get("invoice_number", "").strip()
    record["_duplicate_invoice"] = bool(inv_no and inv_no in SEEN_INVOICE_NUMBERS)
    if inv_no:
        SEEN_INVOICE_NUMBERS.add(inv_no)

    return record



def generate_runtime_pipe(
    template_path: str = "master_ap_sentinel.pipe",
    output_path: str = "master_runtime.pipe",
    use_gemini: bool = False,
) -> str:
    """
    Inject runtime credentials into master_ap_sentinel.pipe template.
    """
    if use_gemini:
        model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        base_url = os.environ.get("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai")
        api_key = os.environ.get("GEMINI_API_KEY", "")
        provider = "Gemini"
    else:
        model = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")
        base_url = os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
        api_key = os.environ.get("GROQ_API_KEY", "")
        provider = "Groq"

    template = Path(template_path).read_text(encoding="utf-8")
    runtime = (
        template.replace("{{GROQ_MODEL}}", model)
        .replace("{{GROQ_BASE_URL}}", base_url)
        .replace("{{GROQ_API_KEY}}", api_key)
        .replace("{{GEMINI_MODEL}}", model)
        .replace("{{GEMINI_BASE_URL}}", base_url)
        .replace("{{GEMINI_API_KEY}}", api_key)
    )

    Path(output_path).write_text(runtime, encoding="utf-8")
    log.info(f"Generated unified runtime pipe → {output_path} ({provider})")
    return output_path


class SentinelPipeline:
    """
    Manages live RocketRide pipeline sessions with Groq primary and Gemini failover.
    """

    def __init__(self):
        self.client = None
        self.groq_token = None
        self.gemini_token = None
        self.available = False
        self.provider_name = "RocketRide/Groq"
        self._cm = None

    async def startup(self):
        """Connect to RocketRide WebSocket and launch master pipelines."""
        groq_key = os.environ.get("GROQ_API_KEY", "")
        gemini_key = os.environ.get("GEMINI_API_KEY", "")
        uri = os.environ.get("ROCKETRIDE_URI", "ws://localhost:5565")
        auth = os.environ.get("ROCKETRIDE_APIKEY", "local")

        if not groq_key or groq_key == "your_groq_api_key_here":
            log.error("GROQ_API_KEY is not configured.")
            return

        try:
            from rocketride import RocketRideClient
        except ImportError:
            log.error("rocketride library is not installed.")
            return

        try:
            groq_pipe = generate_runtime_pipe(output_path="master_runtime.pipe", use_gemini=False)
            has_gemini = bool(gemini_key and gemini_key != "your_gemini_api_key_here")
            gemini_pipe = (
                generate_runtime_pipe(output_path="master_gemini_rt.pipe", use_gemini=True)
                if has_gemini
                else None
            )

            self._cm = RocketRideClient(uri=uri, auth=auth)
            self.client = await self._cm.__aenter__()

            # Launch primary Groq pipeline
            res = await self.client.use(filepath=groq_pipe)
            self.groq_token = res["token"]
            self.available = True
            log.info(f"✅ RocketRide Master/Groq pipeline active — session: {self.groq_token[:12]}...")

            # Launch fallback Gemini pipeline
            if gemini_pipe:
                try:
                    res_gem = await self.client.use(filepath=gemini_pipe)
                    self.gemini_token = res_gem["token"]
                    log.info(f"✅ RocketRide Master/Gemini failover active — session: {self.gemini_token[:12]}...")
                except Exception as gem_err:
                    log.warning(f"RocketRide Gemini failover failed to initialize: {gem_err}")

        except Exception as e:
            self.available = False
            log.warning(f"⚠️ RocketRide engine unavailable ({e}). Server will utilize zero-downtime direct API fallback.")

    async def shutdown(self):
        """Terminate all pipeline sessions cleanly."""
        if self.client:
            for token, name in [(self.groq_token, "Groq"), (self.gemini_token, "Gemini")]:
                if token:
                    try:
                        await self.client.terminate(token)
                        log.info(f"Terminated RocketRide {name} pipeline session.")
                    except Exception as e:
                        log.warning(f"Error terminating {name} session: {e}")
        if self._cm:
            try:
                await self._cm.__aexit__(None, None, None)
            except Exception:
                pass

    async def process_invoice(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process invoice through the RocketRide 3-agent pipeline with automatic failover.
        """
        invoice_id = record.get("invoice_id", "UNKNOWN")
        start = time.perf_counter()

        # Pre-enrichment & identity guard
        record = enrich_invoice_payload(record)

        # ── Primary Execution: Groq ──
        try:
            raw = await self.client.send(
                self.groq_token,
                json.dumps(record),
                objinfo={"name": f"{invoice_id}.json"},
                mimetype="application/json",
            )
            verdict = self._parse_verdict(raw)
            verdict["_provider"] = "RocketRide/Groq"
            verdict["_latency_ms"] = round((time.perf_counter() - start) * 1000)
            return self._finalize_verdict(record, verdict)

        except Exception as groq_err:
            err_str = str(groq_err).lower()
            is_rate_limit = any(s in err_str for s in ["429", "rate_limit", "rate limit", "too many", "timeout"])

            if is_rate_limit and self.gemini_token:
                log.warning(f"⚡ Groq rate-limited for {invoice_id}. Instant failover to Gemini pipeline...")
                try:
                    raw = await self.client.send(
                        self.gemini_token,
                        json.dumps(record),
                        objinfo={"name": f"{invoice_id}.json"},
                        mimetype="application/json",
                    )
                    verdict = self._parse_verdict(raw)
                    verdict["_provider"] = "RocketRide/Gemini (Failover)"
                    verdict["_latency_ms"] = round((time.perf_counter() - start) * 1000)
                    return self._finalize_verdict(record, verdict)
                except Exception as gem_err:
                    return self._error_verdict(record, start, str(gem_err), "BOTH_PIPELINES_FAILED")
            else:
                return self._error_verdict(record, start, str(groq_err), "PIPELINE_ERROR")

    def _parse_verdict(self, raw: Any) -> Dict[str, Any]:
        """Normalize JSON verdict from LLM output."""
        if isinstance(raw, dict):
            return raw
        text = str(raw).strip()
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE).rstrip("`").strip()
        try:
            return json.loads(text)
        except Exception:
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                return json.loads(match.group(0))
            raise ValueError(f"Unable to parse verdict JSON: {text[:200]}")

    def _finalize_verdict(self, record: Dict[str, Any], verdict: Dict[str, Any]) -> Dict[str, Any]:
        """Apply tier threshold validation, payout eligibility, and enforce HITL logic."""
        raw_tier = str(verdict.get("risk_tier", "ELEVATED")).upper()
        if "HOLD" in raw_tier:
            verdict["risk_tier"] = "HOLD"
        elif "ELEVATED" in raw_tier or "REVIEW" in raw_tier:
            verdict["risk_tier"] = "ELEVATED"
        elif "CLEAN" in raw_tier or "APPROVE" in raw_tier:
            verdict["risk_tier"] = "CLEAN"
        else:
            score = float(verdict.get("risk_score", 0.5) or 0.5)
            if score >= 0.61:
                verdict["risk_tier"] = "HOLD"
            elif score >= 0.26:
                verdict["risk_tier"] = "ELEVATED"
            else:
                verdict["risk_tier"] = "CLEAN"

        tier = verdict["risk_tier"]
        verdict["hitl_required"] = tier in ("ELEVATED", "HOLD")
        verdict["auto_approve_safe"] = tier == "CLEAN"
        verdict["payout_eligible"] = tier == "CLEAN"

        # Sender spoofing override
        sender_auth = record.get("_sender_auth", {})
        if sender_auth.get("status") == "DOMAIN_MISMATCH_SPOOFED":
            verdict["risk_tier"] = "HOLD"
            verdict["threat_type"] = "SENDER_SPOOFED"
            verdict["hitl_required"] = True
            verdict["payout_eligible"] = False
            verdict["key_risk_factors"] = verdict.get("key_risk_factors", []) + [
                "Sender Spoofing Alert: Incoming sender email domain does not match verified vendor domain."
            ]

        # Ensure out of band action for HOLD
        if verdict["risk_tier"] == "HOLD" and not verdict.get("out_of_band_action"):
            vendor_name = record.get("vendor_name", "the vendor")
            phone = record.get("_vendor_master", {}).get("contact_phone") or "official registry phone"
            verdict["out_of_band_action"] = (
                f"Call {vendor_name} on {phone} from the master vendor registry. "
                f"DO NOT use any phone number or email found in the suspicious invoice."
            )

        verdict.update({
            "_invoice_id": record.get("invoice_id", "UNKNOWN"),
            "_timestamp": datetime.utcnow().isoformat(),
            "_status": "SUCCESS",
            "_invoice_amount": float(record.get("invoice_amount", 0.0) or 0.0),
            "_vendor_name": record.get("vendor_name", "Unknown Vendor"),
            "_vendor_domain": record.get("sender_domain", ""),
        })
        return verdict

    def _error_verdict(self, record: Dict[str, Any], start: float, error: str, status: str) -> Dict[str, Any]:
        return {
            "_invoice_id": record.get("invoice_id", "UNKNOWN"),
            "_latency_ms": round((time.perf_counter() - start) * 1000),
            "_timestamp": datetime.utcnow().isoformat(),
            "_status": status,
            "_error": error[:200],
            "_provider": "ERROR",
            "_invoice_amount": float(record.get("invoice_amount", 0.0) or 0.0),
            "_vendor_name": record.get("vendor_name", "Unknown Vendor"),
            "_vendor_domain": record.get("sender_domain", ""),
            "risk_score": 0.5,
            "risk_tier": "ELEVATED",
            "threat_type": "PROCESSING_ERROR",
            "confidence": 0.0,
            "key_risk_factors": [f"Pipeline error: {status}"],
            "recommendation": "SECONDARY_REVIEW",
            "out_of_band_action": "Manual audit required due to processing error.",
            "verified_vendor_phone": None,
            "auto_approve_safe": False,
            "hitl_required": True,
            "payout_eligible": False,
            "audit_summary": f"Execution error ({status}) — flagged for manual analyst review.",
        }
