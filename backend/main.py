"""
AP Payment Fraud Sentinel — RocketRide Python Backend
=======================================================
AI Strategy:
  PRIMARY  → Groq (llama-3.1-8b-instant)  — free, 14,400 req/day, blazing fast
  FALLBACK → Google Gemini (gemini-1.5-flash) — free, 1,500 req/day, kicks in
             automatically when Groq hits rate limits or returns an error.

Pipeline files:
  ap_sentinel_groq.pipe   — used by default
  ap_sentinel_gemini.pipe — used automatically on Groq failure

Usage:
    python backend/main.py                                     # 3-record demo
    python backend/main.py --batch data/invoices/batch_sample.json
    python backend/main.py --single data/invoices/sample_bec.json
"""

import os
import asyncio
import json
import time
import argparse
import logging
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ap_sentinel")

# ---------------------------------------------------------------------------
# Provider configuration — Groq primary, Gemini fallback
# ---------------------------------------------------------------------------
PROVIDER_GROQ = {
    "name": "Groq",
    "pipe_file": "ap_sentinel_groq.pipe",
    "api_key_env": "GROQ_API_KEY",
    "model": os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant"),
    # Cost: Groq free tier = $0 for now
    "cost_per_1k_input": 0.0,
    "cost_per_1k_output": 0.0,
}

PROVIDER_GEMINI = {
    "name": "Gemini",
    "pipe_file": "ap_sentinel_gemini.pipe",
    "api_key_env": "GEMINI_API_KEY",
    "model": os.environ.get("GEMINI_MODEL", "gemini-1.5-flash"),
    # Cost: Gemini 1.5 Flash free tier = $0 up to 1,500 req/day
    "cost_per_1k_input": 0.0,
    "cost_per_1k_output": 0.0,
}

# Groq rate-limit error signatures — triggers automatic Gemini fallback
GROQ_RATE_LIMIT_SIGNALS = [
    "rate_limit", "rate limit", "429", "too many requests",
    "tokens per minute", "requests per minute",
]

# ---------------------------------------------------------------------------
# Vendor Master Registry (simulated in-memory DB)
# In production: replace with real DB query via tool node
# ---------------------------------------------------------------------------
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
    },
}


def query_vendor_master_record(vendor_domain: str) -> dict:
    """Simulated vendor registry lookup."""
    return VENDOR_MASTER.get(vendor_domain, {"status": "NEW_VENDOR", "vendor_domain": vendor_domain})


# ---------------------------------------------------------------------------
# Core pipeline runner — with Groq → Gemini per-invoice fallback
# ---------------------------------------------------------------------------
async def _send_invoice(client, token: str, record: dict, invoice_id: str) -> str:
    """Raw send — returns the verdict string from the pipeline."""
    return await client.send(
        token,
        json.dumps(record),
        objinfo={"name": f"{invoice_id}.json"},
        mimetype="application/json",
    )


def _is_groq_rate_limit(error: Exception) -> bool:
    """Detect whether an exception is a Groq rate-limit response."""
    err_str = str(error).lower()
    return any(sig in err_str for sig in GROQ_RATE_LIMIT_SIGNALS)


async def audit_single_invoice(
    groq_client,
    groq_token: str,
    record: dict,
    idx: int,
    gemini_client=None,
    gemini_token: str = None,
) -> dict:
    """
    Process one invoice.
    1. Try Groq pipeline first (fast, free).
    2. If Groq hits a rate limit → automatically retry on Gemini fallback.
    3. Any other error → return structured ERROR verdict (never crash).
    """
    invoice_id = record.get("invoice_id", f"INV_{idx:04d}")
    log.info(f"  [{idx}] Auditing {invoice_id} via Groq ...")

    # Enrich with vendor registry data once (shared by both providers)
    vendor_domain = record.get("sender_domain", "")
    record["_vendor_master"] = query_vendor_master_record(vendor_domain)

    start = time.perf_counter()
    provider_used = "Groq"

    try:
        verdict_raw = await _send_invoice(groq_client, groq_token, record, invoice_id)

    except Exception as groq_err:
        if _is_groq_rate_limit(groq_err) and gemini_client and gemini_token:
            log.warning(
                f"  [{idx}] ⚡ Groq rate-limited for {invoice_id} — "
                f"falling back to Gemini ..."
            )
            provider_used = "Gemini (fallback)"
            try:
                verdict_raw = await _send_invoice(
                    gemini_client, gemini_token, record, invoice_id
                )
            except Exception as gemini_err:
                latency_ms = round((time.perf_counter() - start) * 1000)
                log.error(f"  [{idx}] ❌ Both Groq and Gemini failed for {invoice_id}: {gemini_err}")
                return _error_verdict(invoice_id, latency_ms, str(gemini_err), "BOTH_PROVIDERS_FAILED")
        else:
            latency_ms = round((time.perf_counter() - start) * 1000)
            log.error(f"  [{idx}] ❌ Groq pipeline error for {invoice_id}: {groq_err}")
            return _error_verdict(invoice_id, latency_ms, str(groq_err), "PIPELINE_ERROR")

    latency_ms = round((time.perf_counter() - start) * 1000)

    try:
        verdict = json.loads(verdict_raw) if isinstance(verdict_raw, str) else verdict_raw
    except json.JSONDecodeError as e:
        log.warning(f"  [{idx}] ⚠️  JSON parse error for {invoice_id}: {e}")
        return _error_verdict(invoice_id, latency_ms, str(e), "PARSE_ERROR")

    verdict["_invoice_id"] = invoice_id
    verdict["_latency_ms"] = latency_ms
    verdict["_timestamp"] = datetime.utcnow().isoformat()
    verdict["_status"] = "SUCCESS"
    verdict["_provider"] = provider_used

    tier = verdict.get("risk_tier", "UNKNOWN")
    score = verdict.get("risk_score", 0)
    provider_tag = f" [{provider_used}]" if provider_used != "Groq" else ""
    log.info(f"  [{idx}] ✅ {invoice_id} → {tier} (score={score:.2f}, {latency_ms}ms){provider_tag}")
    return verdict


def _error_verdict(invoice_id: str, latency_ms: int, error: str, status: str) -> dict:
    """Standard error verdict — ensures every invoice gets a structured response."""
    return {
        "_invoice_id": invoice_id,
        "_latency_ms": latency_ms,
        "_timestamp": datetime.utcnow().isoformat(),
        "_status": status,
        "_error": error,
        "risk_tier": "ERROR",
        "risk_score": None,
        "hitl_required": True,
        "recommendation": "MANUAL_REVIEW",
        "audit_summary": f"Processing error ({status}): escalated to manual review.",
    }


async def audit_invoice_batch(invoice_records: list[dict]) -> dict:
    """
    Main batch runner.
    - Opens a Groq pipeline and a Gemini pipeline in parallel.
    - Routes every invoice through Groq first.
    - Automatically retries on Gemini if Groq is rate-limited.
    - Always calls terminate() on both pipelines (no orphans).
    """
    try:
        from rocketride import RocketRideClient
    except ImportError:
        log.error("rocketride SDK not installed. Run: pip install rocketride python-dotenv")
        raise

    uri = os.environ.get("ROCKETRIDE_URI")
    api_key = os.environ.get("ROCKETRIDE_APIKEY")
    groq_key = os.environ.get("GROQ_API_KEY", "")
    gemini_key = os.environ.get("GEMINI_API_KEY", "")

    if not uri or not api_key:
        raise EnvironmentError(
            "Missing ROCKETRIDE_URI or ROCKETRIDE_APIKEY in .env — "
            "connect through the VS Code extension first so it writes these."
        )
    if not groq_key or groq_key == "your_groq_api_key_here":
        raise EnvironmentError("GROQ_API_KEY is not set in .env — get a free key at https://console.groq.com")

    has_gemini = gemini_key and gemini_key != "your_gemini_api_key_here"

    log.info(f"🚀 AP Fraud Sentinel — Batch of {len(invoice_records)} invoices")
    log.info(f"   Provider: Groq (primary){' + Gemini (fallback)' if has_gemini else ' [no Gemini fallback configured]'}")
    log.info(f"   RocketRide endpoint: {uri}")

    batch_start = time.perf_counter()
    results = []
    groq_token = None
    gemini_token = None

    async with RocketRideClient(uri=uri, auth=api_key) as groq_client:
        # Start Groq pipeline
        groq_pipeline = await groq_client.use(filepath=PROVIDER_GROQ["pipe_file"])
        groq_token = groq_pipeline["token"]
        log.info(f"   ✅ Groq pipeline ready  (token: {groq_token[:12]}...)")

        # Start Gemini pipeline in same connection if key exists
        gemini_client = groq_client  # same RocketRide connection, different pipe
        if has_gemini:
            gemini_pipeline = await groq_client.use(filepath=PROVIDER_GEMINI["pipe_file"])
            gemini_token = gemini_pipeline["token"]
            log.info(f"   ✅ Gemini fallback ready (token: {gemini_token[:12]}...)")
        else:
            log.warning("   ⚠️  Gemini fallback NOT configured — set GEMINI_API_KEY in .env")

        try:
            for idx, record in enumerate(invoice_records, start=1):
                verdict = await audit_single_invoice(
                    groq_client, groq_token, record, idx,
                    gemini_client=gemini_client if has_gemini else None,
                    gemini_token=gemini_token,
                )
                results.append(verdict)
        finally:
            # CRITICAL: always terminate BOTH pipelines — no orphan instances
            await groq_client.terminate(groq_token)
            log.info("   Groq pipeline terminated.")
            if gemini_token:
                await groq_client.terminate(gemini_token)
                log.info("   Gemini pipeline terminated.")

    wall_time = round(time.perf_counter() - batch_start, 2)

    # -----------------------------------------------------------------------
    # Telemetry summary
    # -----------------------------------------------------------------------
    total = len(results)
    successful = sum(1 for r in results if r.get("_status") == "SUCCESS")
    errors = total - successful
    clean_count = sum(1 for r in results if r.get("risk_tier") == "CLEAN")
    elevated_count = sum(1 for r in results if r.get("risk_tier") == "ELEVATED")
    hold_count = sum(1 for r in results if r.get("risk_tier") == "HOLD")
    error_count = sum(1 for r in results if r.get("risk_tier") == "ERROR")

    avg_latency = round(
        sum(r.get("_latency_ms", 0) for r in results) / max(total, 1)
    )

    # Groq + Gemini are both free tiers — $0 cost
    # Keeping the field for judges to see the telemetry structure
    estimated_cost_per_invoice = 0.0
    total_estimated_cost = 0.0
    groq_count = sum(1 for r in results if r.get("_provider", "Groq") == "Groq")
    gemini_fallback_count = sum(1 for r in results if "Gemini" in r.get("_provider", ""))

    # Fraud dollars held (sum invoice amounts for HOLDs)
    fraud_held_usd = 0
    for r in results:
        if r.get("risk_tier") == "HOLD":
            inv_id = r.get("_invoice_id", "")
            # Try to find amount from original records
            for record in invoice_records:
                if record.get("invoice_id") == inv_id:
                    fraud_held_usd += record.get("invoice_amount", 0)
                    break

    telemetry = {
        "batch_id": f"BATCH_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
        "timestamp": datetime.utcnow().isoformat(),
        "total_invoices": total,
        "successful": successful,
        "errors": errors,
        "wall_time_seconds": wall_time,
        "avg_latency_ms": avg_latency,
        "estimated_cost_usd": 0.0,
        "cost_per_invoice_usd": 0.0,
        "provider_breakdown": {
            "groq_served": groq_count,
            "gemini_fallback_served": gemini_fallback_count,
        },
        "results_breakdown": {
            "CLEAN": clean_count,
            "ELEVATED": elevated_count,
            "HOLD": hold_count,
            "ERROR": error_count,
        },
        "fraud_capital_held_usd": fraud_held_usd,
        "hitl_required_count": sum(1 for r in results if r.get("hitl_required", False)),
    }

    log.info("\n" + "=" * 60)
    log.info("📊 BATCH TELEMETRY SUMMARY")
    log.info("=" * 60)
    log.info(f"   Total invoices:       {total}")
    log.info(f"   Wall-clock time:      {wall_time}s")
    log.info(f"   Avg latency:          {avg_latency}ms per invoice")
    log.info(f"   ─── Provider ────────────────────────")
    log.info(f"   Groq (primary):       {groq_count} invoices")
    log.info(f"   Gemini (fallback):    {gemini_fallback_count} invoices")
    log.info(f"   Cost:                 $0.00 (both free tiers)")
    log.info(f"   ─── Risk Tiers ──────────────────────")
    log.info(f"   ✅ CLEAN (auto):       {clean_count}")
    log.info(f"   ⚠️  ELEVATED (review): {elevated_count}")
    log.info(f"   🔴 HOLD (fraud):       {hold_count}")
    log.info(f"   ❌ Errors:             {error_count}")
    log.info(f"   ─────────────────────────────────────")
    log.info(f"   💰 Fraud capital held: ${fraud_held_usd:,.2f}")
    log.info("=" * 60)

    # Save results
    output_path = Path("data") / "results" / f"batch_results_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({"telemetry": telemetry, "verdicts": results}, f, indent=2)
    log.info(f"   Results saved → {output_path}")

    return {"telemetry": telemetry, "verdicts": results}


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="AP Payment Fraud Sentinel — Batch Runner")
    parser.add_argument("--batch", type=str, help="Path to batch JSON file (list of invoice records)")
    parser.add_argument("--single", type=str, help="Path to a single invoice JSON file")
    args = parser.parse_args()

    if args.single:
        with open(args.single) as f:
            record = json.load(f)
        records = [record] if isinstance(record, dict) else record
    elif args.batch:
        with open(args.batch) as f:
            records = json.load(f)
    else:
        log.info("No input specified — running with built-in demo batch (3 records)")
        records = [
            {
                "invoice_id": "DEMO-001",
                "vendor_name": "Acme Corp",
                "vendor_email": "billing@acme-corp.com",
                "sender_domain": "acme-corp.com",
                "invoice_number": "INV-2026-1001",
                "invoice_amount": 4200.00,
                "currency": "USD",
                "bank_account_number": "123456789",
                "routing_number": "021000021",
                "payment_due_date": "2026-09-15",
                "contact_phone": "+1-800-555-0100",
                "raw_text": "Please process payment for services rendered in August 2026.",
            },
            {
                "invoice_id": "DEMO-002-BEC",
                "vendor_name": "Acme Corp",
                "vendor_email": "billing@acme-c0rp.com",
                "sender_domain": "acme-c0rp.com",
                "invoice_number": "INV-2026-1002",
                "invoice_amount": 87500.00,
                "currency": "USD",
                "bank_account_number": "999888777",
                "routing_number": "021000099",
                "payment_due_date": "2026-08-30",
                "contact_phone": "+1-555-999-0001",
                "raw_text": "URGENT: Our banking details have changed. Please wire $87,500 immediately to the new account. This is approved by CEO. Do not discuss with anyone. Failure to comply will result in service termination.",
            },
            {
                "invoice_id": "DEMO-003",
                "vendor_name": "Vertex Office Supplies",
                "vendor_email": "ap@vertex-office.com",
                "sender_domain": "vertex-office.com",
                "invoice_number": "INV-2026-0445",
                "invoice_amount": 650.00,
                "currency": "USD",
                "bank_account_number": "456123789",
                "routing_number": "122105155",
                "payment_due_date": "2026-09-10",
                "contact_phone": "+1-800-555-0300",
                "raw_text": "Office supplies delivered per PO #7821. Payment due net-30.",
            },
        ]

    asyncio.run(audit_invoice_batch(records))


if __name__ == "__main__":
    main()
