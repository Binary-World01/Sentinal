"""
Supabase Database & Local Registry Integration for AP Fraud Sentinel
====================================================================
Handles persistent storage of Vendor Master records and Audit Logs.
Directly integrates with Supabase PostgreSQL & Auth with local SQLite fallback.
"""

import os
import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

log = logging.getLogger("sentinel_supabase")

DB_PATH = Path("data") / "audit.db"

# Supabase Client Singleton
_supabase_client = None

def get_supabase_config() -> Dict[str, Any]:
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_ANON_KEY", os.environ.get("SUPABASE_KEY", "")).strip()
    service_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    return {
        "url": url,
        "anon_key": key,
        "service_key": service_key,
        "is_configured": bool(url and (key or service_key))
    }

def get_supabase_client():
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    config = get_supabase_config()
    if config["is_configured"]:
        try:
            from supabase import create_client, Client
            key_to_use = config["service_key"] if config["service_key"] else config["anon_key"]
            _supabase_client = create_client(config["url"], key_to_use)
            log.info(f"Connected to Supabase project at {config['url']}")
            return _supabase_client
        except Exception as e:
            log.warning(f"Failed to initialize Supabase client ({e}). Using local database.")
            return None
    return None

def reset_supabase_client():
    global _supabase_client
    _supabase_client = None
    return get_supabase_client()


# ─── SQLite Local Registry Init & Seed ────────────────────────────────────────

def init_vendor_tables():
    """Ensure SQLite vendor and audit tables exist."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    
    # Vendor Master Table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vendors (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_id           TEXT UNIQUE NOT NULL,
            name                TEXT NOT NULL,
            domain              TEXT NOT NULL,
            known_domains       TEXT DEFAULT '[]',
            bank_account_number TEXT NOT NULL,
            routing_number      TEXT NOT NULL,
            iban                TEXT DEFAULT '',
            contact_phone       TEXT DEFAULT '',
            contact_email       TEXT DEFAULT '',
            avg_invoice_amount  REAL DEFAULT 0.0,
            max_invoice_ever    REAL DEFAULT 0.0,
            min_invoice_ever    REAL DEFAULT 0.0,
            status              TEXT DEFAULT 'ACTIVE',
            category            TEXT DEFAULT 'General',
            notes               TEXT DEFAULT '',
            created_at          TEXT
        )
    """)
    conn.commit()

    # If empty, seed with initial realistic vendor master data from JSON if available
    cursor = conn.execute("SELECT COUNT(*) FROM vendors")
    count = cursor.fetchone()[0]
    if count == 0:
        json_path = Path("data") / "vendors" / "vendor_master.json"
        if json_path.exists():
            try:
                data = json.loads(json_path.read_text(encoding="utf-8"))
                for domain, v in data.items():
                    conn.execute("""
                        INSERT INTO vendors (
                            vendor_id, name, domain, known_domains,
                            bank_account_number, routing_number, iban,
                            contact_phone, contact_email, avg_invoice_amount,
                            max_invoice_ever, min_invoice_ever, status, category,
                            notes, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        v.get("vendor_id", f"VEND-{int(datetime.utcnow().timestamp())}"),
                        v.get("vendor_name", domain.split(".")[0].title()),
                        domain,
                        json.dumps(v.get("known_domains", [domain])),
                        v.get("bank_account_number", ""),
                        v.get("routing_number", ""),
                        v.get("iban", ""),
                        v.get("contact_phone", ""),
                        v.get("verified_email", f"ap@{domain}"),
                        float(v.get("avg_invoice_amount", 0.0)),
                        float(v.get("max_invoice_ever", 0.0)),
                        float(v.get("min_invoice_ever", 0.0)),
                        v.get("status", "ACTIVE"),
                        v.get("category", "Technology / SaaS"),
                        "Pre-configured verified master vendor.",
                        datetime.utcnow().isoformat()
                    ))
                conn.commit()
                log.info(f"Seeded {len(data)} vendors into local database.")
            except Exception as e:
                log.warning(f"Failed to seed initial vendor data: {e}")

    conn.close()


# ─── Vendor CRUD Operations ───────────────────────────────────────────────────

def get_all_vendors() -> List[Dict[str, Any]]:
    """Retrieve all vendors from Supabase or local SQLite."""
    supabase = get_supabase_client()
    if supabase:
        try:
            res = supabase.table("vendors").select("*").order("name").execute()
            if res.data:
                vendors = []
                for item in res.data:
                    # Normalize known_domains if string or list
                    kd = item.get("known_domains", [])
                    if isinstance(kd, str):
                        try: kd = json.loads(kd)
                        except Exception: kd = [kd] if kd else []
                    item["known_domains"] = kd
                    vendors.append(item)
                return vendors
        except Exception as e:
            log.warning(f"Supabase get_all_vendors failed ({e}). Falling back to SQLite.")

    # Local SQLite Fallback
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM vendors ORDER BY name ASC").fetchall()
    conn.close()

    vendors = []
    for r in rows:
        d = dict(r)
        try:
            d["known_domains"] = json.loads(d.get("known_domains") or "[]")
        except Exception:
            d["known_domains"] = [d.get("domain")] if d.get("domain") else []
        vendors.append(d)
    return vendors


def get_vendor_by_domain(domain: str) -> Optional[Dict[str, Any]]:
    """Lookup a vendor by primary domain or known alias domains."""
    if not domain:
        return None
    domain = domain.lower().strip()
    vendors = get_all_vendors()
    for v in vendors:
        v_domain = (v.get("domain") or "").lower().strip()
        known = [kd.lower().strip() for kd in v.get("known_domains", [])]
        if domain == v_domain or domain in known:
            return v
    return None


def create_vendor(data: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new vendor in Supabase and/or SQLite."""
    now_iso = datetime.utcnow().isoformat()
    vendor_id = data.get("vendor_id") or f"VEND-{int(datetime.utcnow().timestamp()*1000)%1000000}"
    name = data.get("name", "").strip()
    domain = data.get("domain", "").lower().strip()
    
    # Process known domains
    known_domains = data.get("known_domains", [])
    if isinstance(known_domains, str):
        known_domains = [d.strip() for d in known_domains.split(",") if d.strip()]
    if domain and domain not in known_domains:
        known_domains.append(domain)

    record = {
        "vendor_id": vendor_id,
        "name": name,
        "domain": domain,
        "known_domains": known_domains,
        "bank_account_number": data.get("bank_account_number", "").strip(),
        "routing_number": data.get("routing_number", "").strip(),
        "iban": data.get("iban", "").strip(),
        "contact_phone": data.get("contact_phone", "").strip(),
        "contact_email": data.get("contact_email", "").strip(),
        "avg_invoice_amount": float(data.get("avg_invoice_amount", 0.0) or 0.0),
        "max_invoice_ever": float(data.get("max_invoice_ever", 0.0) or 0.0),
        "min_invoice_ever": float(data.get("min_invoice_ever", 0.0) or 0.0),
        "status": data.get("status", "ACTIVE").upper(),
        "category": data.get("category", "General").strip(),
        "notes": data.get("notes", "").strip(),
        "created_at": now_iso
    }

    # Try inserting to Supabase
    supabase = get_supabase_client()
    if supabase:
        try:
            supabase_record = {**record, "known_domains": json.dumps(known_domains)}
            res = supabase.table("vendors").insert(supabase_record).execute()
            if res.data:
                log.info(f"Vendor {name} saved to Supabase ({vendor_id})")
        except Exception as e:
            log.warning(f"Failed to insert vendor to Supabase: {e}")

    # Always persist to SQLite
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        INSERT OR REPLACE INTO vendors (
            vendor_id, name, domain, known_domains,
            bank_account_number, routing_number, iban,
            contact_phone, contact_email, avg_invoice_amount,
            max_invoice_ever, min_invoice_ever, status, category,
            notes, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        record["vendor_id"],
        record["name"],
        record["domain"],
        json.dumps(record["known_domains"]),
        record["bank_account_number"],
        record["routing_number"],
        record["iban"],
        record["contact_phone"],
        record["contact_email"],
        record["avg_invoice_amount"],
        record["max_invoice_ever"],
        record["min_invoice_ever"],
        record["status"],
        record["category"],
        record["notes"],
        record["created_at"]
    ))
    conn.commit()
    conn.close()

    return record


def update_vendor(vendor_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Update an existing vendor by vendor_id."""
    existing = None
    vendors = get_all_vendors()
    for v in vendors:
        if v.get("vendor_id") == vendor_id:
            existing = v
            break
    if not existing:
        return None

    # Merge fields
    for k, val in data.items():
        if k in existing:
            existing[k] = val

    if isinstance(existing.get("known_domains"), str):
        existing["known_domains"] = [d.strip() for d in existing["known_domains"].split(",") if d.strip()]

    # Try Supabase update
    supabase = get_supabase_client()
    if supabase:
        try:
            update_payload = {**existing, "known_domains": json.dumps(existing["known_domains"])}
            supabase.table("vendors").update(update_payload).eq("vendor_id", vendor_id).execute()
        except Exception as e:
            log.warning(f"Supabase vendor update failed: {e}")

    # Update SQLite
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        UPDATE vendors SET
            name = ?, domain = ?, known_domains = ?,
            bank_account_number = ?, routing_number = ?, iban = ?,
            contact_phone = ?, contact_email = ?, avg_invoice_amount = ?,
            max_invoice_ever = ?, min_invoice_ever = ?, status = ?,
            category = ?, notes = ?
        WHERE vendor_id = ?
    """, (
        existing["name"],
        existing["domain"],
        json.dumps(existing["known_domains"]),
        existing["bank_account_number"],
        existing["routing_number"],
        existing.get("iban", ""),
        existing.get("contact_phone", ""),
        existing.get("contact_email", ""),
        float(existing.get("avg_invoice_amount", 0.0) or 0.0),
        float(existing.get("max_invoice_ever", 0.0) or 0.0),
        float(existing.get("min_invoice_ever", 0.0) or 0.0),
        existing.get("status", "ACTIVE"),
        existing.get("category", "General"),
        existing.get("notes", ""),
        vendor_id
    ))
    conn.commit()
    conn.close()

    return existing


def delete_vendor(vendor_id: str) -> bool:
    """Delete a vendor by vendor_id."""
    supabase = get_supabase_client()
    if supabase:
        try:
            supabase.table("vendors").delete().eq("vendor_id", vendor_id).execute()
        except Exception as e:
            log.warning(f"Supabase delete failed: {e}")

    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.execute("DELETE FROM vendors WHERE vendor_id = ?", (vendor_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


# ─── Supabase SQL Schema Generator ────────────────────────────────────────────

def get_supabase_sql_schema() -> str:
    """Returns SQL DDL to easily configure Supabase tables & Row-Level Security."""
    return """-- ============================================================
-- AP FRAUD SENTINEL — SUPABASE DATABASE SCHEMA
-- Run this in Supabase SQL Editor: https://supabase.com/dashboard/project/_/sql
-- ============================================================

-- 1. Vendors Master Table
CREATE TABLE IF NOT EXISTS public.vendors (
    id BIGSERIAL PRIMARY KEY,
    vendor_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    domain TEXT NOT NULL,
    known_domains JSONB DEFAULT '[]'::jsonb,
    bank_account_number TEXT NOT NULL,
    routing_number TEXT NOT NULL,
    iban TEXT DEFAULT '',
    contact_phone TEXT DEFAULT '',
    contact_email TEXT DEFAULT '',
    avg_invoice_amount NUMERIC(14,2) DEFAULT 0.00,
    max_invoice_ever NUMERIC(14,2) DEFAULT 0.00,
    min_invoice_ever NUMERIC(14,2) DEFAULT 0.00,
    status TEXT DEFAULT 'ACTIVE',
    category TEXT DEFAULT 'General',
    notes TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for instant domain searches
CREATE INDEX IF NOT EXISTS idx_vendors_domain ON public.vendors(domain);
CREATE INDEX IF NOT EXISTS idx_vendors_vendor_id ON public.vendors(vendor_id);

-- 2. Audit Log Table (Stores all live AI fraud detection verdicts)
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id BIGSERIAL PRIMARY KEY,
    batch_id TEXT,
    invoice_id TEXT,
    vendor_name TEXT,
    vendor_domain TEXT,
    invoice_amount NUMERIC(14,2),
    risk_tier TEXT,
    risk_score NUMERIC(5,4),
    fraud_type TEXT,
    provider TEXT,
    latency_ms INTEGER,
    hitl_required BOOLEAN DEFAULT FALSE,
    hitl_action TEXT DEFAULT NULL,
    hitl_actor TEXT DEFAULT NULL,
    hitl_at TIMESTAMPTZ DEFAULT NULL,
    audit_summary TEXT,
    raw_verdict JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_invoice_id ON public.audit_logs(invoice_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_risk_tier ON public.audit_logs(risk_tier);

-- 3. Row Level Security (RLS)
ALTER TABLE public.vendors ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- Allow authenticated and anon access for full operational control
CREATE POLICY "Allow public read access on vendors" ON public.vendors FOR SELECT USING (true);
CREATE POLICY "Allow public insert on vendors" ON public.vendors FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow public update on vendors" ON public.vendors FOR UPDATE USING (true);
CREATE POLICY "Allow public delete on vendors" ON public.vendors FOR DELETE USING (true);

CREATE POLICY "Allow public read on audit_logs" ON public.audit_logs FOR SELECT USING (true);
CREATE POLICY "Allow public insert on audit_logs" ON public.audit_logs FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow public update on audit_logs" ON public.audit_logs FOR UPDATE USING (true);
"""
