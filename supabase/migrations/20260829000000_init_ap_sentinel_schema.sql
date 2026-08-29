-- ==============================================================================
-- AP Payment Fraud Sentinel — Complete PostgreSQL Schema with Multi-Tenancy & RLS
-- Project Reference: zoixzkvakuiqoebpwodv (https://zoixzkvakuiqoebpwodv.supabase.co)
-- ==============================================================================

-- 1. Users Table (Tenant Profiles & Fraud Alert Receivers)
CREATE TABLE IF NOT EXISTS public.users (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_email         TEXT NOT NULL UNIQUE,
    notification_email TEXT NOT NULL,
    full_name          TEXT,
    created_at         TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Vendors Table (Granular Master Registry)
CREATE TABLE IF NOT EXISTS public.vendors (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID REFERENCES public.users(id) ON DELETE CASCADE,
    vendor_id           TEXT UNIQUE,
    vendor_name         TEXT NOT NULL,
    primary_email       TEXT NOT NULL,
    finance_email       TEXT,
    verified_domain     TEXT NOT NULL,
    bank_account_number TEXT NOT NULL,
    bank_routing_code   TEXT NOT NULL,
    can_add_vendor      BOOLEAN DEFAULT FALSE,
    iban                TEXT DEFAULT '',
    contact_phone       TEXT DEFAULT '',
    avg_invoice_amount  NUMERIC(12, 2) DEFAULT 0.00,
    max_invoice_ever    NUMERIC(12, 2) DEFAULT 0.00,
    min_invoice_ever    NUMERIC(12, 2) DEFAULT 0.00,
    status              TEXT DEFAULT 'ACTIVE',
    category            TEXT DEFAULT 'General',
    notes               TEXT DEFAULT '',
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Invoices Table (Universal Ingestion, Forensics & Payout Lifecycles)
CREATE TABLE IF NOT EXISTS public.invoices (
    id                     TEXT PRIMARY KEY,
    user_id                UUID REFERENCES public.users(id) ON DELETE CASCADE,
    vendor_id              UUID REFERENCES public.vendors(id) ON DELETE SET NULL,
    invoice_number         TEXT,
    file_name              TEXT NOT NULL DEFAULT 'manual_entry.json',
    file_url               TEXT NOT NULL DEFAULT 'local://manual_entry',
    extracted_amount       NUMERIC(12, 2) DEFAULT 0.00,
    extracted_bank_details JSONB,
    risk_score             NUMERIC(4, 3) NOT NULL,
    threat_type            TEXT,
    status                 TEXT NOT NULL,
    payout_tx_id           TEXT,
    paid_at                TIMESTAMPTZ,
    hitl_actor             TEXT,
    hitl_at                TIMESTAMPTZ,
    raw_payload            JSONB,
    created_at             TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Email Logs Table (Automated IMAP Audits & Ingestion Trail)
CREATE TABLE IF NOT EXISTS public.email_logs (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              UUID REFERENCES public.users(id) ON DELETE CASCADE,
    sender_email         TEXT NOT NULL,
    subject              TEXT,
    is_read              BOOLEAN DEFAULT FALSE,
    attachment_processed BOOLEAN DEFAULT FALSE,
    status               TEXT DEFAULT 'PROCESSED',
    details              JSONB,
    created_at           TIMESTAMPTZ DEFAULT NOW()
);

-- ── Indexes for Sub-Millisecond Forensic Verification ─────────────────────────
CREATE INDEX IF NOT EXISTS idx_vendors_domain ON public.vendors(verified_domain);
CREATE INDEX IF NOT EXISTS idx_vendors_bank ON public.vendors(bank_account_number);
CREATE INDEX IF NOT EXISTS idx_invoices_status ON public.invoices(status);
CREATE INDEX IF NOT EXISTS idx_invoices_payout_tx ON public.invoices(payout_tx_id);
CREATE INDEX IF NOT EXISTS idx_invoices_created ON public.invoices(created_at DESC);

-- ── Row Level Security (RLS) Policies ─────────────────────────────────────────
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vendors ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_logs ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    -- users policies
    DROP POLICY IF EXISTS "Allow public read on users" ON public.users;
    DROP POLICY IF EXISTS "Allow public insert on users" ON public.users;
    DROP POLICY IF EXISTS "Allow public update on users" ON public.users;
    CREATE POLICY "Allow public read on users" ON public.users FOR SELECT TO anon, authenticated USING (true);
    CREATE POLICY "Allow public insert on users" ON public.users FOR INSERT TO anon, authenticated WITH CHECK (true);
    CREATE POLICY "Allow public update on users" ON public.users FOR UPDATE TO anon, authenticated USING (true);

    -- vendors policies
    DROP POLICY IF EXISTS "Allow public read on vendors" ON public.vendors;
    DROP POLICY IF EXISTS "Allow public insert on vendors" ON public.vendors;
    DROP POLICY IF EXISTS "Allow public update on vendors" ON public.vendors;
    DROP POLICY IF EXISTS "Allow public delete on vendors" ON public.vendors;
    CREATE POLICY "Allow public read on vendors" ON public.vendors FOR SELECT TO anon, authenticated USING (true);
    CREATE POLICY "Allow public insert on vendors" ON public.vendors FOR INSERT TO anon, authenticated WITH CHECK (true);
    CREATE POLICY "Allow public update on vendors" ON public.vendors FOR UPDATE TO anon, authenticated USING (true);
    CREATE POLICY "Allow public delete on vendors" ON public.vendors FOR DELETE TO anon, authenticated USING (true);

    -- invoices policies
    DROP POLICY IF EXISTS "Allow public read on invoices" ON public.invoices;
    DROP POLICY IF EXISTS "Allow public insert on invoices" ON public.invoices;
    DROP POLICY IF EXISTS "Allow public update on invoices" ON public.invoices;
    DROP POLICY IF EXISTS "Allow public delete on invoices" ON public.invoices;
    CREATE POLICY "Allow public read on invoices" ON public.invoices FOR SELECT TO anon, authenticated USING (true);
    CREATE POLICY "Allow public insert on invoices" ON public.invoices FOR INSERT TO anon, authenticated WITH CHECK (true);
    CREATE POLICY "Allow public update on invoices" ON public.invoices FOR UPDATE TO anon, authenticated USING (true);
    CREATE POLICY "Allow public delete on invoices" ON public.invoices FOR DELETE TO anon, authenticated USING (true);

    -- email_logs policies
    DROP POLICY IF EXISTS "Allow public read on email_logs" ON public.email_logs;
    DROP POLICY IF EXISTS "Allow public insert on email_logs" ON public.email_logs;
    CREATE POLICY "Allow public read on email_logs" ON public.email_logs FOR SELECT TO anon, authenticated USING (true);
    CREATE POLICY "Allow public insert on email_logs" ON public.email_logs FOR INSERT TO anon, authenticated WITH CHECK (true);
END $$;

GRANT ALL ON public.users TO anon, authenticated, service_role;
GRANT ALL ON public.vendors TO anon, authenticated, service_role;
GRANT ALL ON public.invoices TO anon, authenticated, service_role;
GRANT ALL ON public.email_logs TO anon, authenticated, service_role;
