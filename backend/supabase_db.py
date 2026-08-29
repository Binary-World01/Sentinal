"""
Supabase Database & Local Multi-Tenant Registry for AP Fraud Sentinel
======================================================================
Unified persistence engine supporting:
  - Multi-tenant User Profiles (`users`)
  - Granular Master Vendor Registry (`vendors`)
  - Invoice Lifecycle & Audit Logs (`invoices`)
  - Automated Email Ingestion & Audit Logs (`email_logs`)
  - Local SQLite fallback with Supabase PostgreSQL cloud synchronization
"""

import os
import json
import uuid
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

log = logging.getLogger("sentinel_supabase")

DB_PATH = Path("data") / "audit.db"
DEFAULT_USER_ID = "00000000-0000-0000-0000-000000000001"
DEFAULT_USER_EMAIL = "admin@sentinel.finance"
DEFAULT_NOTIF_EMAIL = os.environ.get("ALERT_EMAIL", "ap-security@company.com")

_supabase_client = None


def get_supabase_config() -> Dict[str, Any]:
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_ANON_KEY", os.environ.get("SUPABASE_KEY", "")).strip()
    service_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    return {
        "url": url,
        "anon_key": key,
        "service_key": service_key,
        "is_configured": bool(url and (key or service_key)),
    }


def get_supabase_client():
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    config = get_supabase_config()
    if config["is_configured"]:
        try:
            from supabase import create_client
            key_to_use = config["service_key"] if config["service_key"] else config["anon_key"]
            _supabase_client = create_client(config["url"], key_to_use)
            log.info(f"Connected to Supabase project at {config['url']}")
            return _supabase_client
        except Exception as e:
            log.warning(f"Failed to initialize Supabase client ({e}). Using local SQLite database.")
            return None
    return None


def reset_supabase_client():
    global _supabase_client
    _supabase_client = None
    return get_supabase_client()


# ─── SQLite Local Schema Init & Migration ─────────────────────────────────────

def init_vendor_tables():
    """Ensure SQLite tables exist mirroring the full Supabase schema."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))

    # Migration check for old table versions
    cols = [r[1] for r in conn.execute("PRAGMA table_info(vendors)").fetchall()]
    if cols and "vendor_name" not in cols:
        conn.execute("DROP TABLE IF EXISTS vendors")

    inv_cols = [r[1] for r in conn.execute("PRAGMA table_info(invoices)").fetchall()]
    if inv_cols and "extracted_amount" not in inv_cols:
        conn.execute("DROP TABLE IF EXISTS invoices")

    # 1. Users Table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id                 TEXT PRIMARY KEY,
            auth_email         TEXT NOT NULL UNIQUE,
            notification_email TEXT NOT NULL,
            full_name          TEXT,
            created_at         TEXT
        )
    """)

    # 2. Vendors Table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vendors (
            id                  TEXT PRIMARY KEY,
            user_id             TEXT,
            vendor_id           TEXT UNIQUE,
            vendor_name         TEXT NOT NULL,
            primary_email       TEXT NOT NULL,
            finance_email       TEXT,
            verified_domain     TEXT NOT NULL,
            bank_account_number TEXT NOT NULL,
            bank_routing_code   TEXT NOT NULL,
            can_add_vendor      INTEGER DEFAULT 0,
            iban                TEXT DEFAULT '',
            contact_phone       TEXT DEFAULT '',
            avg_invoice_amount  REAL DEFAULT 0.0,
            max_invoice_ever    REAL DEFAULT 0.0,
            min_invoice_ever    REAL DEFAULT 0.0,
            status              TEXT DEFAULT 'ACTIVE',
            category            TEXT DEFAULT 'General',
            notes               TEXT DEFAULT '',
            created_at          TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)


    # 3. Invoices Table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS invoices (
            id                     TEXT PRIMARY KEY,
            user_id                TEXT,
            vendor_id              TEXT,
            invoice_number         TEXT,
            file_name              TEXT NOT NULL,
            file_url               TEXT NOT NULL,
            extracted_amount       REAL,
            extracted_bank_details TEXT,
            risk_score             REAL NOT NULL,
            threat_type            TEXT,
            status                 TEXT NOT NULL,
            payout_tx_id           TEXT,
            paid_at                TEXT,
            hitl_actor             TEXT,
            hitl_at                TEXT,
            raw_payload            TEXT,
            created_at             TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (vendor_id) REFERENCES vendors(id)
        )
    """)

    # 4. Email Logs Table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS email_logs (
            id                   TEXT PRIMARY KEY,
            user_id              TEXT,
            sender_email         TEXT NOT NULL,
            subject              TEXT,
            is_read              INTEGER DEFAULT 0,
            attachment_processed INTEGER DEFAULT 0,
            status               TEXT DEFAULT 'PROCESSED',
            details              TEXT,
            created_at           TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Seed Default User if absent
    user_row = conn.execute("SELECT id FROM users WHERE id = ?", (DEFAULT_USER_ID,)).fetchone()
    if not user_row:
        conn.execute("""
            INSERT INTO users (id, auth_email, notification_email, full_name, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            DEFAULT_USER_ID,
            DEFAULT_USER_EMAIL,
            DEFAULT_NOTIF_EMAIL,
            "AP Security Administrator",
            datetime.utcnow().isoformat()
        ))

    # Seed Default Verified Vendors if empty
    vendor_count = conn.execute("SELECT COUNT(*) FROM vendors").fetchone()[0]
    if vendor_count == 0:
        seed_vendors = [
            {
                "id": str(uuid.uuid4()),
                "user_id": DEFAULT_USER_ID,
                "vendor_id": "VEND-001",
                "vendor_name": "Acme Corp",
                "primary_email": "invoices@acme-corp.com",
                "finance_email": "billing@acme-corp.com",
                "verified_domain": "acme-corp.com",
                "bank_account_number": "123456789",
                "bank_routing_code": "021000021",
                "can_add_vendor": 1,
                "iban": "GB29NWBK60161331926819",
                "contact_phone": "+1-800-555-0100",
                "avg_invoice_amount": 4500.00,
                "max_invoice_ever": 15000.00,
                "status": "ACTIVE",
                "category": "Enterprise Software",
                "notes": "Verified SaaS partner.",
            },
            {
                "id": str(uuid.uuid4()),
                "user_id": DEFAULT_USER_ID,
                "vendor_id": "VEND-002",
                "vendor_name": "GlobalTech Supplies",
                "primary_email": "accounts@globaltech-supplies.com",
                "finance_email": "dispatch@globaltech-supplies.com",
                "verified_domain": "globaltech-supplies.com",
                "bank_account_number": "987654321",
                "bank_routing_code": "026009593",
                "can_add_vendor": 0,
                "iban": "DE89370400440532013000",
                "contact_phone": "+1-800-555-0200",
                "avg_invoice_amount": 12000.00,
                "max_invoice_ever": 45000.00,
                "status": "ACTIVE",
                "category": "Hardware & Cloud Infrastructure",
                "notes": "Hardware procurement vendor.",
            },
            {
                "id": str(uuid.uuid4()),
                "user_id": DEFAULT_USER_ID,
                "vendor_id": "VEND-003",
                "vendor_name": "Vertex Office Supplies",
                "primary_email": "orders@vertex-office.com",
                "finance_email": "finance@vertex-office.com",
                "verified_domain": "vertex-office.com",
                "bank_account_number": "456123789",
                "bank_routing_code": "122105155",
                "can_add_vendor": 0,
                "iban": "",
                "contact_phone": "+1-800-555-0300",
                "avg_invoice_amount": 800.00,
                "max_invoice_ever": 2500.00,
                "status": "ACTIVE",
                "category": "Office Logistics",
                "notes": "Standard supplies vendor.",
            },
            {
                "id": str(uuid.uuid4()),
                "user_id": DEFAULT_USER_ID,
                "vendor_id": "VEND-004",
                "vendor_name": "Pinnacle Services",
                "primary_email": "billing@pinnacle-services.com",
                "finance_email": "ap@pinnacle-services.com",
                "verified_domain": "pinnacle-services.com",
                "bank_account_number": "741852963",
                "bank_routing_code": "031201360",
                "can_add_vendor": 0,
                "iban": "",
                "contact_phone": "+1-800-555-0400",
                "avg_invoice_amount": 2200.00,
                "max_invoice_ever": 8000.00,
                "status": "ACTIVE",
                "category": "Facilities & Security",
                "notes": "Contracted facilities vendor.",
            }
        ]
        now_str = datetime.utcnow().isoformat()
        for v in seed_vendors:
            conn.execute("""
                INSERT INTO vendors (
                    id, user_id, vendor_id, vendor_name, primary_email, finance_email,
                    verified_domain, bank_account_number, bank_routing_code, can_add_vendor,
                    iban, contact_phone, avg_invoice_amount, max_invoice_ever, status,
                    category, notes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                v["id"], v["user_id"], v["vendor_id"], v["vendor_name"], v["primary_email"],
                v["finance_email"], v["verified_domain"], v["bank_account_number"],
                v["bank_routing_code"], v["can_add_vendor"], v["iban"], v["contact_phone"],
                v["avg_invoice_amount"], v["max_invoice_ever"], v["status"], v["category"],
                v["notes"], now_str
            ))
        log.info(f"Seeded {len(seed_vendors)} verified master vendors into SQLite.")

    conn.commit()
    conn.close()


# ─── User Operations ─────────────────────────────────────────────────────────

def get_default_user() -> Dict[str, Any]:
    """Retrieve or create default admin user record."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM users WHERE id = ?", (DEFAULT_USER_ID,)).fetchone()
    conn.close()
    if row:
        return dict(row)
    return {
        "id": DEFAULT_USER_ID,
        "auth_email": DEFAULT_USER_EMAIL,
        "notification_email": DEFAULT_NOTIF_EMAIL,
        "full_name": "AP Security Administrator"
    }


# ─── Vendor Operations ────────────────────────────────────────────────────────

def get_all_vendors(user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve all vendors from Supabase or local SQLite."""
    supabase = get_supabase_client()
    if supabase:
        try:
            query = supabase.table("vendors").select("*").order("vendor_name")
            if user_id:
                query = query.eq("user_id", user_id)
            res = query.execute()
            if res.data:
                vendors = []
                for item in res.data:
                    item["name"] = item.get("vendor_name")
                    item["domain"] = item.get("verified_domain")
                    item["routing_number"] = item.get("bank_routing_code")
                    item["known_domains"] = [item.get("verified_domain")] if item.get("verified_domain") else []
                    vendors.append(item)
                return vendors
        except Exception as e:
            log.warning(f"Supabase get_all_vendors failed ({e}). Falling back to SQLite.")

    # SQLite fallback
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    sql = "SELECT * FROM vendors ORDER BY vendor_name ASC"
    rows = conn.execute(sql).fetchall()
    conn.close()

    vendors = []
    for r in rows:
        d = dict(r)
        d["name"] = d.get("vendor_name")
        d["domain"] = d.get("verified_domain")
        d["routing_number"] = d.get("bank_routing_code")
        d["known_domains"] = [d.get("verified_domain")] if d.get("verified_domain") else []
        vendors.append(d)
    return vendors


def get_vendor_by_domain(domain: str) -> Optional[Dict[str, Any]]:
    """Lookup vendor by verified domain."""
    if not domain:
        return None
    domain = domain.lower().strip()
    for v in get_all_vendors():
        if (v.get("verified_domain") or "").lower().strip() == domain:
            return v
        if (v.get("domain") or "").lower().strip() == domain:
            return v
    return None


def get_vendor_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Lookup vendor by primary_email or finance_email."""
    if not email:
        return None
    email = email.lower().strip()
    for v in get_all_vendors():
        if (v.get("primary_email") or "").lower().strip() == email:
            return v
        if (v.get("finance_email") or "").lower().strip() == email:
            return v
    return None


def check_sender_authorization(sender_email: str, claimed_domain: str) -> Dict[str, Any]:
    """
    Evaluates whether the sender email is authorized for the given vendor domain.
    Flags sender spoofing or unverified billing senders.
    """
    sender_email = (sender_email or "").lower().strip()
    claimed_domain = (claimed_domain or "").lower().strip()

    vendor = get_vendor_by_domain(claimed_domain)
    if not vendor:
        return {
            "authorized": False,
            "status": "UNKNOWN_VENDOR",
            "message": f"No master vendor record found for domain '{claimed_domain}'.",
            "vendor": None
        }

    primary = (vendor.get("primary_email") or "").lower().strip()
    finance = (vendor.get("finance_email") or "").lower().strip()
    verified_domain = (vendor.get("verified_domain") or "").lower().strip()

    # Extract actual domain from sender_email
    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""

    if sender_domain != verified_domain:
        return {
            "authorized": False,
            "status": "DOMAIN_MISMATCH_SPOOFED",
            "message": f"Sender domain '{sender_domain}' does not match verified vendor domain '{verified_domain}'.",
            "vendor": vendor
        }

    if sender_email in [primary, finance] or not primary:
        return {
            "authorized": True,
            "status": "VERIFIED_SENDER",
            "message": "Sender is registered in the official vendor master registry.",
            "vendor": vendor
        }

    return {
        "authorized": True,
        "status": "DOMAIN_MATCH_UNLISTED_EMAIL",
        "message": f"Sender domain matches verified '{verified_domain}', but email '{sender_email}' is not the primary dispatch email.",
        "vendor": vendor
    }


def create_vendor(data: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new vendor in Supabase and SQLite."""
    now_iso = datetime.utcnow().isoformat()
    record_id = data.get("id") or str(uuid.uuid4())
    vendor_id = data.get("vendor_id") or f"VEND-{int(datetime.utcnow().timestamp()*1000)%1000000}"
    vendor_name = data.get("vendor_name") or data.get("name", "").strip()
    domain = (data.get("verified_domain") or data.get("domain", "")).lower().strip()
    primary_email = (data.get("primary_email") or data.get("contact_email") or f"invoices@{domain}").lower().strip()
    finance_email = (data.get("finance_email") or primary_email).lower().strip()
    bank_account_number = data.get("bank_account_number", "").strip()
    bank_routing_code = (data.get("bank_routing_code") or data.get("routing_number", "")).strip()

    record = {
        "id": record_id,
        "user_id": data.get("user_id", DEFAULT_USER_ID),
        "vendor_id": vendor_id,
        "vendor_name": vendor_name,
        "primary_email": primary_email,
        "finance_email": finance_email,
        "verified_domain": domain,
        "bank_account_number": bank_account_number,
        "bank_routing_code": bank_routing_code,
        "can_add_vendor": int(bool(data.get("can_add_vendor", False))),
        "iban": data.get("iban", "").strip(),
        "contact_phone": data.get("contact_phone", "").strip(),
        "avg_invoice_amount": float(data.get("avg_invoice_amount", 0.0) or 0.0),
        "max_invoice_ever": float(data.get("max_invoice_ever", 0.0) or 0.0),
        "min_invoice_ever": float(data.get("min_invoice_ever", 0.0) or 0.0),
        "status": data.get("status", "ACTIVE").upper(),
        "category": data.get("category", "General").strip(),
        "notes": data.get("notes", "").strip(),
        "created_at": now_iso,
    }

    # Supabase Insert
    supabase = get_supabase_client()
    if supabase:
        try:
            supabase.table("vendors").insert(record).execute()
            log.info(f"Vendor '{vendor_name}' inserted into Supabase.")
        except Exception as e:
            log.warning(f"Supabase vendor insert error: {e}")

    # SQLite Insert
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        INSERT OR REPLACE INTO vendors (
            id, user_id, vendor_id, vendor_name, primary_email, finance_email,
            verified_domain, bank_account_number, bank_routing_code, can_add_vendor,
            iban, contact_phone, avg_invoice_amount, max_invoice_ever, min_invoice_ever,
            status, category, notes, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        record["id"], record["user_id"], record["vendor_id"], record["vendor_name"],
        record["primary_email"], record["finance_email"], record["verified_domain"],
        record["bank_account_number"], record["bank_routing_code"], record["can_add_vendor"],
        record["iban"], record["contact_phone"], record["avg_invoice_amount"],
        record["max_invoice_ever"], record["min_invoice_ever"], record["status"],
        record["category"], record["notes"], record["created_at"]
    ))
    conn.commit()
    conn.close()

    # Add normalized fields for response compatibility
    record["name"] = record["vendor_name"]
    record["domain"] = record["verified_domain"]
    record["routing_number"] = record["bank_routing_code"]
    return record


def update_vendor(vendor_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Update vendor by id or vendor_id."""
    vendors = get_all_vendors()
    target = None
    for v in vendors:
        if v.get("id") == vendor_id or v.get("vendor_id") == vendor_id:
            target = v
            break
    if not target:
        return None

    # Merge incoming data
    for k, val in data.items():
        if val is not None:
            target[k] = val

    vendor_name = target.get("vendor_name") or target.get("name", "")
    domain = target.get("verified_domain") or target.get("domain", "")
    routing = target.get("bank_routing_code") or target.get("routing_number", "")

    supabase = get_supabase_client()
    if supabase:
        try:
            supabase.table("vendors").update({
                "vendor_name": vendor_name,
                "primary_email": target.get("primary_email"),
                "finance_email": target.get("finance_email"),
                "verified_domain": domain,
                "bank_account_number": target.get("bank_account_number"),
                "bank_routing_code": routing,
                "can_add_vendor": int(bool(target.get("can_add_vendor", False))),
                "iban": target.get("iban", ""),
                "contact_phone": target.get("contact_phone", ""),
                "avg_invoice_amount": float(target.get("avg_invoice_amount", 0.0) or 0.0),
                "max_invoice_ever": float(target.get("max_invoice_ever", 0.0) or 0.0),
                "status": target.get("status", "ACTIVE"),
                "category": target.get("category", "General"),
                "notes": target.get("notes", "")
            }).eq("id", target["id"]).execute()
        except Exception as e:
            log.warning(f"Supabase update vendor error: {e}")

    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        UPDATE vendors SET
            vendor_name = ?, primary_email = ?, finance_email = ?,
            verified_domain = ?, bank_account_number = ?, bank_routing_code = ?,
            can_add_vendor = ?, iban = ?, contact_phone = ?, avg_invoice_amount = ?,
            max_invoice_ever = ?, status = ?, category = ?, notes = ?
        WHERE id = ? OR vendor_id = ?
    """, (
        vendor_name, target.get("primary_email"), target.get("finance_email"),
        domain, target.get("bank_account_number"), routing,
        int(bool(target.get("can_add_vendor", False))), target.get("iban", ""),
        target.get("contact_phone", ""), float(target.get("avg_invoice_amount", 0.0) or 0.0),
        float(target.get("max_invoice_ever", 0.0) or 0.0), target.get("status", "ACTIVE"),
        target.get("category", "General"), target.get("notes", ""),
        target["id"], target.get("vendor_id")
    ))
    conn.commit()
    conn.close()

    target["name"] = vendor_name
    target["domain"] = domain
    target["routing_number"] = routing
    return target


def delete_vendor(vendor_id: str) -> bool:
    """Delete vendor by id or vendor_id."""
    supabase = get_supabase_client()
    if supabase:
        try:
            supabase.table("vendors").delete().or_(f"id.eq.{vendor_id},vendor_id.eq.{vendor_id}").execute()
        except Exception as e:
            log.warning(f"Supabase delete vendor error: {e}")

    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.execute("DELETE FROM vendors WHERE id = ? OR vendor_id = ?", (vendor_id, vendor_id))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


# ─── Invoice & Audit Operations ──────────────────────────────────────────────

def insert_invoice_record(invoice_data: Dict[str, Any]) -> Dict[str, Any]:
    """Persist invoice record into invoices table (Supabase + SQLite)."""
    now_iso = datetime.utcnow().isoformat()
    record_id = invoice_data.get("id") or str(uuid.uuid4())
    raw_payload = invoice_data.get("raw_payload", {})
    if isinstance(raw_payload, dict):
        raw_payload_str = json.dumps(raw_payload)
    else:
        raw_payload_str = str(raw_payload)

    # Resolve vendor UUID for Supabase foreign key integrity
    vendor_uuid = None
    vid = invoice_data.get("vendor_id")
    if vid:
        try:
            uuid.UUID(str(vid))
            vendor_uuid = str(vid)
        except ValueError:
            v = get_vendor_by_domain(invoice_data.get("sender_domain", ""))
            if v and v.get("id"):
                try:
                    uuid.UUID(str(v["id"]))
                    vendor_uuid = str(v["id"])
                except ValueError:
                    vendor_uuid = None

    record = {
        "id": record_id,
        "user_id": invoice_data.get("user_id", DEFAULT_USER_ID),
        "vendor_id": vendor_uuid,
        "invoice_number": invoice_data.get("invoice_number", f"INV-{record_id[:8]}"),
        "file_name": invoice_data.get("file_name", "invoice_upload.json"),
        "file_url": invoice_data.get("file_url", f"/invoices/{record_id}"),
        "extracted_amount": float(invoice_data.get("extracted_amount", 0.0) or 0.0),
        "extracted_bank_details": str(invoice_data.get("extracted_bank_details", "")),
        "risk_score": float(invoice_data.get("risk_score", 0.0) or 0.0),
        "threat_type": invoice_data.get("threat_type"),
        "status": invoice_data.get("status", "CLEAN").upper(),
        "payout_tx_id": invoice_data.get("payout_tx_id"),
        "paid_at": invoice_data.get("paid_at"),
        "hitl_actor": invoice_data.get("hitl_actor"),
        "hitl_at": invoice_data.get("hitl_at"),
        "raw_payload": raw_payload_str,
        "created_at": now_iso
    }

    supabase = get_supabase_client()
    if supabase:
        supabase_data = {
            "id": record["id"],
            "user_id": record["user_id"],
            "vendor_id": record["vendor_id"],
            "invoice_number": record["invoice_number"],
            "file_name": record["file_name"],
            "file_url": record["file_url"],
            "extracted_amount": record["extracted_amount"],
            "extracted_bank_details": {"bank_account": record["extracted_bank_details"]},
            "risk_score": record["risk_score"],
            "threat_type": record["threat_type"],
            "status": record["status"],
            "payout_tx_id": record["payout_tx_id"],
            "paid_at": record["paid_at"],
            "hitl_actor": record["hitl_actor"],
            "hitl_at": record["hitl_at"],
            "raw_payload": raw_payload if isinstance(raw_payload, dict) else (json.loads(raw_payload_str) if raw_payload_str.startswith("{") else {}),
            "created_at": record["created_at"]
        }
        try:
            supabase.table("invoices").insert(supabase_data).execute()
        except Exception as e:
            if "vendor_id_fkey" in str(e).lower() or "foreign key constraint" in str(e).lower():
                try:
                    supabase_data["vendor_id"] = None
                    supabase.table("invoices").insert(supabase_data).execute()
                except Exception as e2:
                    log.warning(f"Supabase invoice insert retry error: {e2}")
            else:
                log.warning(f"Supabase invoice insert error: {e}")


    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        INSERT OR REPLACE INTO invoices (
            id, user_id, vendor_id, invoice_number, file_name, file_url,
            extracted_amount, extracted_bank_details, risk_score, threat_type,
            status, payout_tx_id, paid_at, hitl_actor, hitl_at, raw_payload, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        record["id"], record["user_id"], record["vendor_id"], record["invoice_number"],
        record["file_name"], record["file_url"], record["extracted_amount"],
        record["extracted_bank_details"], record["risk_score"], record["threat_type"],
        record["status"], record["payout_tx_id"], record["paid_at"],
        record["hitl_actor"], record["hitl_at"], record["raw_payload"], record["created_at"]
    ))
    conn.commit()
    conn.close()

    return record



def update_invoice_status(invoice_id: str, status: str, hitl_actor: Optional[str] = None) -> bool:
    """Update status of an invoice (e.g. APPROVED, REJECTED, PAID)."""
    now_iso = datetime.utcnow().isoformat()
    supabase = get_supabase_client()
    if supabase:
        try:
            supabase.table("invoices").update({
                "status": status,
                "hitl_actor": hitl_actor,
                "hitl_at": now_iso
            }).eq("id", invoice_id).execute()
        except Exception as e:
            log.warning(f"Supabase invoice status update error: {e}")

    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.execute("""
        UPDATE invoices SET status = ?, hitl_actor = ?, hitl_at = ?
        WHERE id = ? OR invoice_number = ?
    """, (status, hitl_actor, now_iso, invoice_id, invoice_id))
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return updated


def mark_invoice_paid(invoice_id: str, payout_tx_id: str) -> Optional[Dict[str, Any]]:
    """Marks an invoice as PAID with a payment gateway transaction ID."""
    now_iso = datetime.utcnow().isoformat()
    supabase = get_supabase_client()
    if supabase:
        try:
            supabase.table("invoices").update({
                "status": "PAID",
                "payout_tx_id": payout_tx_id,
                "paid_at": now_iso
            }).eq("id", invoice_id).execute()
        except Exception as e:
            log.warning(f"Supabase mark paid error: {e}")

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        UPDATE invoices SET status = 'PAID', payout_tx_id = ?, paid_at = ?
        WHERE id = ? OR invoice_number = ?
    """, (payout_tx_id, now_iso, invoice_id, invoice_id))
    conn.commit()
    row = conn.execute("SELECT * FROM invoices WHERE id = ? OR invoice_number = ?", (invoice_id, invoice_id)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_invoice_payout_status(
    payout_tx_id: str,
    new_status: str,
    event_data: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    """
    Updates invoice status and webhook audit metadata when a Stripe or RazorpayX
    webhook notification arrives (e.g. payout.paid, payout.failed, payout.reversed).
    """
    now_iso = datetime.utcnow().isoformat()
    supabase = get_supabase_client()
    if supabase:
        try:
            supabase.table("invoices").update({
                "status": new_status,
                "hitl_at": now_iso
            }).or_(f"payout_tx_id.eq.{payout_tx_id},id.eq.{payout_tx_id},invoice_number.eq.{payout_tx_id}").execute()
        except Exception as e:
            log.warning(f"Supabase update payout status error: {e}")

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        UPDATE invoices SET status = ?, hitl_at = ?
        WHERE payout_tx_id = ? OR id = ? OR invoice_number = ?
    """, (new_status, now_iso, payout_tx_id, payout_tx_id, payout_tx_id))
    conn.commit()

    row = conn.execute(
        "SELECT * FROM invoices WHERE payout_tx_id = ? OR id = ? OR invoice_number = ?",
        (payout_tx_id, payout_tx_id, payout_tx_id)
    ).fetchone()
    conn.close()
    return dict(row) if row else None



def get_all_invoices(limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieve recent invoices from Supabase or SQLite."""
    supabase = get_supabase_client()
    if supabase:
        try:
            res = supabase.table("invoices").select("*, vendors(vendor_name, verified_domain, bank_account_number, bank_routing_code)").order("created_at", desc=True).limit(limit).execute()
            if res.data:
                return res.data
        except Exception as e:
            log.warning(f"Supabase get_all_invoices error: {e}")

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT i.*, v.vendor_name, v.verified_domain, v.bank_account_number as verified_bank_account, v.bank_routing_code as verified_routing
        FROM invoices i
        LEFT JOIN vendors v ON i.vendor_id = v.id
        ORDER BY i.created_at DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()

    results = []
    for r in rows:
        d = dict(r)
        if d.get("raw_payload"):
            try:
                d["raw_payload"] = json.loads(d["raw_payload"])
            except Exception:
                pass
        results.append(d)
    return results


# ─── Email Log Operations ─────────────────────────────────────────────────────

def log_email_transaction(
    sender_email: str,
    subject: str,
    attachment_processed: bool = False,
    status: str = "PROCESSED",
    details: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Store email ingestion attempt and audit log."""
    now_iso = datetime.utcnow().isoformat()
    record_id = str(uuid.uuid4())
    details_str = json.dumps(details or {})

    record = {
        "id": record_id,
        "user_id": DEFAULT_USER_ID,
        "sender_email": sender_email,
        "subject": subject,
        "is_read": 1,
        "attachment_processed": int(attachment_processed),
        "status": status,
        "details": details_str,
        "created_at": now_iso
    }

    supabase = get_supabase_client()
    if supabase:
        try:
            supabase.table("email_logs").insert({
                **record,
                "is_read": True,
                "attachment_processed": attachment_processed,
                "details": details or {}
            }).execute()
        except Exception as e:
            log.warning(f"Supabase email_log insert error: {e}")

    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        INSERT INTO email_logs (
            id, user_id, sender_email, subject, is_read, attachment_processed, status, details, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        record["id"], record["user_id"], record["sender_email"], record["subject"],
        record["is_read"], record["attachment_processed"], record["status"],
        record["details"], record["created_at"]
    ))
    conn.commit()
    conn.close()

    return record


def get_email_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve recent email processing logs from Supabase or SQLite."""
    supabase = get_supabase_client()
    if supabase:
        try:
            res = supabase.table("email_logs").select("*").order("created_at", desc=True).limit(limit).execute()
            if res.data:
                return res.data
        except Exception as e:
            log.warning(f"Supabase get_email_logs error: {e}")

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM email_logs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()

    logs = []
    for r in rows:
        d = dict(r)
        if d.get("details"):
            try:
                d["details"] = json.loads(d["details"])
            except Exception:
                pass
        logs.append(d)
    return logs



# ─── Supabase SQL Migration Script ───────────────────────────────────────────

def get_supabase_sql_schema() -> str:
    """Returns the comprehensive SQL migration script as defined in Phase 3."""
    return """-- ============================================================================
-- AP PAYMENT FRAUD SENTINEL — MULTI-TENANT SUPABASE DATABASE SCHEMA
-- Run this script in the Supabase SQL Editor:
-- https://supabase.com/dashboard/project/_/sql
-- ============================================================================

-- 1. Users Table (Supabase Auth Integration)
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    auth_email TEXT NOT NULL UNIQUE,
    notification_email TEXT NOT NULL,
    full_name TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- 2. Vendors Table (Linked to Users with Granular Privileges)
CREATE TABLE IF NOT EXISTS public.vendors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    vendor_name TEXT NOT NULL,
    primary_email TEXT NOT NULL,           -- Official invoice sender mail
    finance_email TEXT,                    -- Accounts/finance dispatch mail
    verified_domain TEXT NOT NULL,         -- e.g., acme-corp.com
    bank_account_number TEXT NOT NULL,     -- Encrypted storage reference
    bank_routing_code TEXT NOT NULL,       -- IFSC / SWIFT / Sort Code
    can_add_vendor BOOLEAN DEFAULT FALSE,  -- Privilege flag for role controls
    avg_invoice_amount NUMERIC(12, 2) DEFAULT 0.00,
    max_invoice_ever NUMERIC(12, 2) DEFAULT 0.00,
    status TEXT DEFAULT 'ACTIVE',
    category TEXT DEFAULT 'General',
    notes TEXT DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- 3. Invoices & Audit Logs Table
CREATE TABLE IF NOT EXISTS public.invoices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    vendor_id UUID REFERENCES public.vendors(id) ON DELETE SET NULL,
    invoice_number TEXT,
    file_name TEXT NOT NULL,
    file_url TEXT NOT NULL,                -- Supabase Storage URL
    extracted_amount NUMERIC(12, 2),
    extracted_bank_details TEXT,
    risk_score NUMERIC(3, 2) NOT NULL,     -- 0.00 to 1.00
    threat_type TEXT,                      -- e.g., 'BEC', 'DOMAIN_TYPOSQUAT', 'UNKNOWN_SENDER'
    status TEXT NOT NULL,                  -- 'CLEAN', 'ELEVATED', 'HOLD', 'PAID'
    payout_tx_id TEXT,                     -- Payment Gateway Payout Ref
    paid_at TIMESTAMP WITH TIME ZONE,
    hitl_actor TEXT,
    hitl_at TIMESTAMP WITH TIME ZONE,
    raw_payload JSONB,                     -- Complete multi-agent breakdown
    created_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- 4. Email Logs & Audit Tracking Table
CREATE TABLE IF NOT EXISTS public.email_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    sender_email TEXT NOT NULL,
    subject TEXT,
    is_read BOOLEAN DEFAULT FALSE,
    attachment_processed BOOLEAN DEFAULT FALSE,
    status TEXT DEFAULT 'PROCESSED',
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- Indexes for lightning queries
CREATE INDEX IF NOT EXISTS idx_vendors_domain ON public.vendors(verified_domain);
CREATE INDEX IF NOT EXISTS idx_invoices_status ON public.invoices(status);
CREATE INDEX IF NOT EXISTS idx_invoices_user ON public.invoices(user_id);
CREATE INDEX IF NOT EXISTS idx_email_logs_sender ON public.email_logs(sender_email);

-- Row Level Security (RLS) Configuration
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vendors ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can access their own profile" ON public.users FOR ALL USING (auth.uid() = id);
CREATE POLICY "Users can manage their vendors" ON public.vendors FOR ALL USING (auth.uid() = user_id OR auth.role() = 'service_role');
CREATE POLICY "Users can view and manage their invoices" ON public.invoices FOR ALL USING (auth.uid() = user_id OR auth.role() = 'service_role');
CREATE POLICY "Users can view their email logs" ON public.email_logs FOR ALL USING (auth.uid() = user_id OR auth.role() = 'service_role');
"""
