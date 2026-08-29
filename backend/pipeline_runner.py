"""
AP Fraud Sentinel — RocketRide Pipeline Manager
================================================
Manages the full lifecycle of the RocketRide multi-agent pipeline:
  - Generates runtime .pipe file with API keys injected from environment
  - Connects to RocketRide engine (local or cloud)
  - Processes invoices through the 3-agent pipeline via client.send()
  - Handles Groq→Gemini fallback at the pipeline level
  - Always terminates pipelines (no orphans)
"""

import os
import re
import json
import time
import logging
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger("rocketride_runner")

# ─── Vendor Master Registry ────────────────────────────────────────────────────
# Pre-enriched into every invoice payload before RocketRide receives it.
# Agents read _vendor_master from the payload — no custom tool needed.
VENDOR_MASTER = {
    "acme-corp.com": {
        "vendor_name": "Acme Corp",
        "bank_account_number": "123456789",
        "routing_number": "021000021",
        "iban": "GB29NWBK60161331926819",
        "contact_phone": "+1-800-555-0100",
        "avg_invoice_amount": 4500.00,
        "known_domains": ["acme-corp.com"],
        "payment_countries": ["US"],
        "status": "ACTIVE",
    },
    "globaltech-supplies.com": {
        "vendor_name": "GlobalTech Supplies",
        "bank_account_number": "987654321",
        "routing_number": "026009593",
        "iban": "DE89370400440532013000",
        "contact_phone": "+1-800-555-0200",
        "avg_invoice_amount": 12000.00,
        "known_domains": ["globaltech-supplies.com"],
        "payment_countries": ["US", "DE"],
        "status": "ACTIVE",
    },
    "vertex-office.com": {
        "vendor_name": "Vertex Office Supplies",
        "bank_account_number": "456123789",
        "routing_number": "122105155",
        "iban": None,
        "contact_phone": "+1-800-555-0300",
        "avg_invoice_amount": 800.00,
        "known_domains": ["vertex-office.com"],
        "payment_countries": ["US"],
        "status": "ACTIVE",
    },
    "pinnacle-services.com": {
        "vendor_name": "Pinnacle Services",
        "bank_account_number": "741852963",
        "routing_number": "031201360",
        "iban": None,
        "contact_phone": "+1-800-555-0400",
        "avg_invoice_amount": 2200.00,
        "known_domains": ["pinnacle-services.com"],
        "payment_countries": ["US"],
        "status": "ACTIVE",
    },
}

SEEN_INVOICE_NUMBERS: set = set()


def enrich_with_vendor_master(record: dict) -> dict:
    """Pre-enrich invoice payload with vendor registry data before sending to pipeline."""
    domain = record.get("sender_domain", "")
    record["_vendor_master"] = VENDOR_MASTER.get(domain, {
        "status": "NEW_VENDOR",
        "known_domains": [],
        "avg_invoice_amount": None,
        "contact_phone": None,
    })
    inv_no = record.get("invoice_number", "")
    record["_duplicate_invoice"] = inv_no in SEEN_INVOICE_NUMBERS
    if inv_no:
        SEEN_INVOICE_NUMBERS.add(inv_no)
    return record


# ─── Runtime pipe generator ────────────────────────────────────────────────────
def generate_runtime_pipe(
    template_path: str = "ap_sentinel_groq.pipe",
    output_path: str   = "ap_sentinel_runtime.pipe",
    use_gemini: bool   = False,
) -> str:
    """
    Read the pipe template, substitute {{PLACEHOLDER}} vars with real env values,
    and write to ap_sentinel_runtime.pipe (gitignored).
    Returns the path to the generated file.
    """
    if use_gemini:
        model     = os.environ.get("GEMINI_MODEL",    "gemini-1.5-flash")
        base_url  = os.environ.get("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai")
        api_key   = os.environ.get("GEMINI_API_KEY",  "")
        provider  = "Gemini"
    else:
        model     = os.environ.get("GROQ_MODEL",    "llama-3.1-8b-instant")
        base_url  = os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
        api_key   = os.environ.get("GROQ_API_KEY",  "")
        provider  = "Groq"

    template = Path(template_path).read_text(encoding="utf-8")
    runtime  = template \
        .replace("{{GROQ_MODEL}}",    model) \
        .replace("{{GROQ_BASE_URL}}", base_url) \
        .replace("{{GROQ_API_KEY}}",  api_key) \
        .replace("{{GEMINI_MODEL}}",    model) \
        .replace("{{GEMINI_BASE_URL}}", base_url) \
        .replace("{{GEMINI_API_KEY}}",  api_key)

    Path(output_path).write_text(runtime, encoding="utf-8")
    log.info(f"Generated runtime pipe → {output_path} ({provider})")
    return output_path


# ─── RocketRide Pipeline Manager ──────────────────────────────────────────────
class SentinelPipeline:
    """
    Manages a live RocketRide pipeline session.
    Call startup() once at server start, shutdown() at server stop.
    Use process_invoice() for each invoice.
    """

    def __init__(self):
        self.client        = None
        self.groq_token    = None
        self.gemini_token  = None
        self.available     = False
        self.provider_name = "RocketRide/Groq"
        self._cm           = None

    async def startup(self):
        """Connect to RocketRide, start Groq pipeline + optional Gemini fallback."""
        groq_key   = os.environ.get("GROQ_API_KEY", "")
        gemini_key = os.environ.get("GEMINI_API_KEY", "")
        uri        = os.environ.get("ROCKETRIDE_URI",   "ws://localhost:5565")
        auth       = os.environ.get("ROCKETRIDE_APIKEY", "local")

        if not groq_key or groq_key == "your_groq_api_key_here":
            log.error("GROQ_API_KEY not set — RocketRide pipeline cannot start")
            return

        try:
            from rocketride import RocketRideClient
        except ImportError:
            log.error("rocketride package not installed — pip install rocketride")
            return

        try:
            # Generate runtime pipes with API keys injected
            groq_pipe_path   = generate_runtime_pipe(use_gemini=False)
            has_gemini       = bool(gemini_key and gemini_key != "your_gemini_api_key_here")
            gemini_pipe_path = generate_runtime_pipe(
                template_path = "ap_sentinel_gemini.pipe",
                output_path   = "ap_sentinel_gemini_runtime.pipe",
                use_gemini    = True,
            ) if has_gemini else None

            self._cm     = RocketRideClient(uri=uri, auth=auth)
            self.client  = await self._cm.__aenter__()

            # Start Groq pipeline
            groq_result      = await self.client.use(filepath=groq_pipe_path)
            self.groq_token  = groq_result["token"]
            self.available   = True
            log.info(f"✅ RocketRide/Groq pipeline ready  — token: {self.groq_token[:12]}...")

            # Start Gemini fallback pipeline if available
            if gemini_pipe_path:
                try:
                    gem_result        = await self.client.use(filepath=gemini_pipe_path)
                    self.gemini_token = gem_result["token"]
                    log.info(f"✅ RocketRide/Gemini fallback ready — token: {self.gemini_token[:12]}...")
                except Exception as e:
                    log.warning(f"Gemini fallback pipeline failed to start: {e}")

        except Exception as e:
            log.warning(f"⚠️  RocketRide not available ({e}) — server will use direct API fallback")
            self.available = False

    async def shutdown(self):
        """Terminate all pipelines and disconnect cleanly."""
        if self.client:
            for token, name in [(self.groq_token, "Groq"), (self.gemini_token, "Gemini")]:
                if token:
                    try:
                        await self.client.terminate(token)
                        log.info(f"   {name} pipeline terminated.")
                    except Exception as e:
                        log.warning(f"   {name} terminate error: {e}")
        if self._cm:
            try:
                await self._cm.__aexit__(None, None, None)
            except Exception:
                pass

    async def process_invoice(self, record: dict) -> dict:
        """
        Send one enriched invoice through the RocketRide multi-agent pipeline.
        Groq primary → Gemini fallback on rate-limit → error verdict if both fail.
        """
        invoice_id = record.get("invoice_id", "UNKNOWN")
        start      = time.perf_counter()

        # Pre-enrich with vendor master registry data
        record = enrich_with_vendor_master(record)

        # ── Try Groq pipeline ──
        try:
            raw = await self.client.send(
                self.groq_token,
                json.dumps(record),
                objinfo={"name": f"{invoice_id}.json"},
                mimetype="application/json",
            )
            verdict = self._parse_verdict(raw)
            verdict["_provider"] = "RocketRide/Groq"
            log.info(f"  ✅ {invoice_id} → {verdict.get('risk_tier')} via Groq ({round((time.perf_counter()-start)*1000)}ms)")

        except Exception as groq_err:
            err_str = str(groq_err).lower()
            is_rate_limit = any(s in err_str for s in ["429", "rate_limit", "rate limit", "too many"])

            if is_rate_limit and self.gemini_token:
                log.warning(f"  ⚡ Groq rate-limited for {invoice_id} — retrying on Gemini...")
                try:
                    raw = await self.client.send(
                        self.gemini_token,
                        json.dumps(record),
                        objinfo={"name": f"{invoice_id}.json"},
                        mimetype="application/json",
                    )
                    verdict = self._parse_verdict(raw)
                    verdict["_provider"] = "RocketRide/Gemini"
                    log.info(f"  ✅ {invoice_id} → {verdict.get('risk_tier')} via Gemini fallback")
                except Exception as gem_err:
                    return self._error_verdict(record, start, str(gem_err), "BOTH_PIPELINES_FAILED")
            else:
                return self._error_verdict(record, start, str(groq_err), "PIPELINE_ERROR")

        latency_ms = round((time.perf_counter() - start) * 1000)
        verdict["_invoice_id"]     = invoice_id
        verdict["_latency_ms"]     = latency_ms
        verdict["_timestamp"]      = datetime.utcnow().isoformat()
        verdict["_status"]         = "SUCCESS"
        verdict["_invoice_amount"] = record.get("invoice_amount", 0)
        verdict["_vendor_name"]    = record.get("vendor_name", "Unknown")
        verdict["_vendor_domain"]  = record.get("sender_domain", "")
        return verdict

    def _parse_verdict(self, raw) -> dict:
        """Parse LLM output — strip markdown fences if present."""
        if not isinstance(raw, str):
            return raw if isinstance(raw, dict) else {}
        text = raw.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?", "", text).rstrip("```").strip()
        return json.loads(text)

    def _error_verdict(self, record: dict, start: float, error: str, status: str) -> dict:
        """Structured error verdict — never crashes the batch."""
        return {
            "_invoice_id":     record.get("invoice_id", "UNKNOWN"),
            "_latency_ms":     round((time.perf_counter() - start) * 1000),
            "_timestamp":      datetime.utcnow().isoformat(),
            "_status":         status,
            "_error":          error[:200],
            "_provider":       "ERROR",
            "_invoice_amount": record.get("invoice_amount", 0),
            "_vendor_name":    record.get("vendor_name", "Unknown"),
            "_vendor_domain":  record.get("sender_domain", ""),
            "risk_score":      0.5,
            "risk_tier":       "ELEVATED",
            "fraud_type":      None,
            "confidence":      0.0,
            "key_risk_factors": [f"Processing error: {status}"],
            "recommendation":  "SECONDARY_REVIEW",
            "out_of_band_action": "Manual verification required — pipeline error during analysis.",
            "verified_vendor_phone": None,
            "auto_approve_safe": False,
            "hitl_required":   True,
            "audit_summary":   f"Processing error ({status}) — escalated to manual review.",
        }
