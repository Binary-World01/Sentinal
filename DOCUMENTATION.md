# AP Payment Fraud Sentinel — Complete Technical Documentation

> **System Version:** 2.5 Enterprise  
> **Repository:** AP Payment Fraud Sentinel  
> **Engine:** RocketRide Multi-Agent AI Framework + Groq & Gemini Failover

---

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [End-to-End System Architecture](#2-end-to-end-system-architecture)
3. [Multi-Agent Pipeline Topology & Prompts](#3-multi-agent-pipeline-topology--prompts)
4. [Deterministic Forensics Engine (`backend/forensics.py`)](#4-deterministic-forensics-engine)
5. [Human-in-the-Loop (HITL) Safety Gate](#5-human-in-the-loop-hitl-safety-gate)
6. [Complete REST API & Streaming Specification](#6-complete-rest-api--streaming-specification)
7. [Master Vendor Registry & Data Layer](#7-master-vendor-registry--data-layer)
8. [Database Schema & Persistence (`data/audit.db`)](#8-database-schema--persistence)
9. [Frontend Dashboard & Explainability Inspector](#9-frontend-dashboard--explainability-inspector)
10. [Dual Provider Fallback & Cost Transparency](#10-dual-provider-fallback--cost-transparency)
11. [Testing, Validation & Operations](#11-testing-validation--operations)

---

## 1. Executive Summary

Accounts Payable (AP) departments are high-value targets for financial cybercrime. **Business Email Compromise (BEC)**, account takeover (ATO), typosquatted vendor domains, duplicate billing, and velocity spikes cost mid-size organizations hundreds of thousands of dollars annually.

**AP Payment Fraud Sentinel** intercepts incoming invoices in real time, pre-enriches them with authoritative master vendor data, processes them through a sequential **3-agent RocketRide AI pipeline**, and enforces a mandatory **Human-in-the-Loop (HITL)** approval gate for any suspicious activity.

### Key Metrics
- **Cost per Invoice:** **$0.00** (Runs on Groq `llama-3.1-8b-instant` and Google Gemini `gemini-3.5-flash` free tiers).
- **Inference Speed:** ~500ms to 2.5s per invoice.
- **Failover:** Automatic runtime failover on HTTP 429 / 403 / 503 rate limits.
- **Explainability:** Full multi-agent step-by-step forensic trace for every scored transaction.

---

## 2. End-to-End System Architecture

```
                    ┌───────────────────────────────┐
                    │ Raw Invoice (JSON / Webhook)  │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ Ingestion & Pre-Enrichment Layer (backend/server.py)                      │
│ • Lookup sender domain in Vendor Master Registry (data/vendors/)          │
│ • Calculate live historical payment averages & max amounts                │
│ • Run Deterministic Pre-Screen (Levenshtein, IBAN Checksum, Velocity)     │
└───────────────────────────────────┬───────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ RocketRide 3-Agent Sequential Pipeline (ap_sentinel_groq.pipe)            │
│                                                                           │
│  [Agent 1: OCR Parser Agent]                                              │
│  • Extracts amounts, bank/routing, IBAN, contact info, due dates          │
│  • Flags urgency keywords ('wire today', 'confidential', 'asap')          │
│  • Flags claimed C-Suite executive overrides & bank change requests       │
│                                   │ (Data Lane: 'text')                   │
│                                   ▼                                       │
│  [Agent 2: Anomaly & Delta Detection Agent]                               │
│  • Cross-references fields against Vendor Master Registry                 │
│  • Detects domain typosquats (homoglyphs, edit distance <= 2)             │
│  • Flags bank account & routing changes, duplicate invoices, velocity     │
│                                   │ (Data Lane: 'text')                   │
│                                   ▼                                       │
│  [Agent 3: Forensic Fraud Scorer]                                         │
│  • Synthesizes multi-agent signals into an aggregated risk score (0.0–1.0)│
│  • Classifies threat type (BEC, Account Takeover, Duplicate, Impersonation│
│  • Formulates mandatory Out-of-Band verification instructions             │
└───────────────────────────────────┬───────────────────────────────────────┘
                                    │
           ┌────────────────────────┼────────────────────────┐
           ▼                        ▼                        ▼
    ✅ CLEAN (0.00–0.25)     ⚠️ ELEVATED (0.26–0.60)   🔴 HOLD (0.61–1.00)
     Auto-Approve             Secondary Review         Payment Frozen
     Sync to ERP              Analyst Queue            HITL Desk & Email
```

---

## 3. Multi-Agent Pipeline Topology & Prompts

The multi-agent topology is defined in `.pipe` files and orchestrated by `RocketRideClient`:

### Agent 1: OCR Parser Agent (`ocr_parser_agent`)
- **Provider:** `llm_openai` (Groq `llama-3.1-8b-instant` / Gemini `gemini-3.5-flash`)
- **Input Lane:** `invoice_payload` (from `invoice_in`)
- **Output:** Extracted financial payload JSON with confidence scores, urgency flags, and executive override flags.

### Agent 2: Anomaly & Delta Agent (`anomaly_delta_agent`)
- **Provider:** `llm_openai`
- **Input Lane:** `text` (from `ocr_parser_agent`)
- **Output:** Discrepancy analysis comparing invoice fields to `_vendor_master` and `_forensics`.

### Agent 3: Forensic Scorer Agent (`forensic_fraud_agent`)
- **Provider:** `llm_openai`
- **Input Lane:** `text` (from `anomaly_delta_agent`)
- **Scoring Weights:**
  - `Bank Changed + Urgency Language`: **+0.40** (Classic BEC Pattern)
  - `Domain Typosquat Detected`: **+0.35** (Vendor Impersonation)
  - `Bank Changed Alone`: **+0.30** (Account Takeover)
  - `Executive Override Claimed`: **+0.25** (Social Engineering)
  - `Duplicate Invoice Number`: **+0.20** (Duplicate Fraud)
  - `Velocity Spike (>150% Historical Avg)`: **+0.15** (Amount Anomaly)
- **Output:** Final verdict JSON with risk tier, threat type, key risk factors, and out-of-band verification requirements.

---

## 4. Deterministic Forensics Engine (`backend/forensics.py`)

To ensure mathematical guarantees alongside generative AI reasoning, the pre-screening engine runs 4 algorithmic validations:

### 1. Levenshtein Distance & Homoglyph Normalization
- Calculates the minimum single-character edits required to transform the sender domain into known vendor domains.
- Normalizes deceptive homoglyphs: `0` $\leftrightarrow$ `o`, `1` $\leftrightarrow$ `l`, `rn` $\leftrightarrow$ `m`, `vv` $\leftrightarrow$ `w`, `cl` $\leftrightarrow$ `d`.
- Catches typosquats like `acme-c0rp.com` or `globaltech-supplies.co`.

### 2. ISO 7064 MOD-97-10 IBAN Checksum
- Implements the official international standard: moves country prefix to the end, replaces letters with $(ord(c) - 55)$, and computes $N \pmod{97} = 1$.
- Immediately rejects corrupt or synthetically generated IBANs.

### 3. US Federal Reserve ABA Routing Transit Checksum
- Calculates 9-digit weighted modulus check:
  $$ig(3(d_1 + d_4 + d_7) + 7(d_2 + d_5 + d_8) + 1(d_3 + d_6 + d_9)ig) \pmod{10} = 0$$

### 4. Velocity Spikes & Smurfing Detection
- Evaluates invoice amount against historical payment distribution ($ar{x}$, $max$).
- Detects split invoicing / smurfing (invoices positioned within 10% below standard corporate approval thresholds such as \$10,000, \$25,000, and \$50,000).

---

## 5. Human-in-the-Loop (HITL) Safety Gate

**Zero Unverified Releases:** No payment flagged as `HOLD` can ever be auto-released by software.

### Protocol Steps:
1. **Payment Frozen:** In SQLite, the transaction is marked with `hitl_action = NULL`.
2. **Out-of-Band Contact Generation:** The system pulls the verified phone number from the **Master Vendor Registry**.
3. **Scam Prevention Banner:** Explicitly displays:  
   `⛔ DO NOT call any phone number or email found in the suspicious invoice or message.`
4. **Analyst Action:**
   - **`POST /api/hitl/release/{id}`**: Marks `RELEASED`, logging timestamp and analyst actor.
   - **`POST /api/hitl/reject/{id}`**: Marks `REJECTED`, blacklisting the vendor and canceling payment.

---

## 6. Complete REST API & Streaming Specification

| Endpoint | Method | Input | Output | Description |
|---|---|---|---|---|
| `/` | `GET` | — | `text/html` | Serves dashboard UI |
| `/api/health` | `GET` | — | `JSON` | Health, engine status, provider state |
| `/api/audit/stream` | `POST` | `multipart/form-data` | `text/event-stream` | SSE batch processing |
| `/api/audit/single` | `POST` | `JSON` (invoice) | `JSON` (verdict) | Instant single-invoice screening |
| `/api/audit/history` | `GET` | `?limit=100` | `JSON` array | Recent SQLite audit logs |
| `/api/audit/stats` | `GET` | — | `JSON` | Cumulative totals, tiers, and savings |
| `/api/audit/clear` | `POST` | — | `JSON` | Resets audit logs for demo runs |
| `/api/vendors` | `GET` | — | `JSON` array | Lists all registered master vendors |
| `/api/vendors` | `POST` | `JSON` (vendor) | `JSON` | Adds or updates vendor master record |
| `/api/hitl/release/{id}` | `POST` | `id` in path | `JSON` | Approves and releases held payment |
| `/api/hitl/reject/{id}` | `POST` | `id` in path | `JSON` | Rejects payment and blacklists vendor |
| `/api/sample-batch` | `GET` | — | `JSON` array | 10-record demo dataset |
| `/api/large-batch` | `GET` | — | `JSON` array | 63-record stress-test dataset |

---

## 7. Master Vendor Registry & Data Layer

- **`data/vendors/vendor_master.json`**: Authoritative ground-truth registry containing verified phone lines, authorized domains, approved bank accounts, routing numbers, and baseline payment profiles.
- **`data/vendors/invoice_history.json`**: Historical invoice records used to dynamically calculate rolling averages, standard deviations, and detect velocity spikes.
- **`data/invoices/batch_sample.json`**: 10-invoice sample dataset with realistic clean and fraudulent transactions.
- **`data/invoices/batch_large.json`**: 63-invoice comprehensive dataset covering typosquats, BEC, duplicate invoices, synthetic vendors, and velocity spikes.

---

## 8. Database Schema & Persistence (`data/audit.db`)

SQLite database auto-created on application startup:

```sql
CREATE TABLE audit_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id         TEXT,
    invoice_id       TEXT,
    vendor_name      TEXT,
    vendor_domain    TEXT,
    invoice_amount   REAL,
    risk_tier        TEXT,
    risk_score       REAL,
    fraud_type       TEXT,
    provider         TEXT,
    latency_ms       INTEGER,
    hitl_required    INTEGER,
    hitl_action      TEXT DEFAULT NULL,
    hitl_actor       TEXT DEFAULT NULL,
    hitl_at          TEXT DEFAULT NULL,
    audit_summary    TEXT,
    timestamp        TEXT,
    raw_verdict      TEXT
);

CREATE TABLE batch_runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id       TEXT UNIQUE,
    started_at     TEXT,
    completed_at   TEXT,
    total          INTEGER,
    clean          INTEGER,
    elevated       INTEGER,
    hold           INTEGER,
    errors         INTEGER,
    fraud_held_usd REAL,
    wall_time_s    REAL,
    provider       TEXT,
    cost_usd       REAL DEFAULT 0.0
);
```

---

## 9. Frontend Dashboard & Explainability Inspector

- **Auto-Loading History:** On initial browser load, historical metrics and past audit logs are fetched from SQLite.
- **Search & Filter Controls:** Real-time client-side search across invoice numbers, vendor names, and domains, with filter pills for `All`, `🔴 Holds`, `⚠️ Elevated`, and `✅ Clean`.
- **Explainability Tabs in Detail Modal:**
  - 📋 **Summary:** Overall risk score, decision tier, classification, and out-of-band contacts.
  - 🔍 **Agent 1 (OCR):** Extracted entities, urgency indicators, and executive override detection.
  - 🗄️ **Agent 2 (Anomaly):** Master registry deltas, typosquat target, IBAN validity, velocity deviation.
  - 🧠 **Agent 3 (Forensic):** Multi-factor score weighting and audit justification.
  - `{ }` **Raw Payload:** Full raw JSON object.
- **Vendor Master Drawer:** Interactive UI to browse registered suppliers and register new vendors.
- **Single-Invoice Sandbox:** Form to screen one-off suspicious invoices.
- **CSV & JSON Exporter:** Downloads formatted audit logs for finance teams.

---

## 10. Dual Provider Fallback & Cost Transparency

| Engine | Primary Provider | Fallback Provider | Emergency Direct Fallback |
|---|---|---|---|
| **RocketRide Multi-Agent** | Groq `llama-3.1-8b-instant` | Google Gemini `gemini-3.5-flash` | Direct REST API (if RocketRide daemon offline) |
| **Cost per 1,000 Invoices** | **$0.00** (Free Tier) | **$0.00** (Free Tier) | **$0.00** |

Fallback triggers automatically on HTTP 429 (rate limits), 403, 503, or connection timeouts. Every verdict records the exact `_provider` used.

---

## 11. Testing, Validation & Operations

### Running the Test Suite
An automated 10-case test suite is available in `scratch/test_server_endpoints.py`:
```powershell
python -c "import sys, os; sys.path.insert(0, os.getcwd()); from scratch.test_server_endpoints import run_tests; run_tests()"
```

### Starting the Server
```powershell
python -m uvicorn backend.server:app --reload --port 8000
```
Open **`http://localhost:8000`** in your browser.
