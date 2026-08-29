# AP Payment Fraud Sentinel — Architecture & Operations Manual

> **Version:** 2.5 Enterprise  
> **Target Audience:** Accounts Payable Teams, Security Engineers, and Developers

---

## 1. System Overview & Problem Statement

Accounts Payable (AP) departments face sophisticated fraud schemes including **Business Email Compromise (BEC)**, synthetic vendor onboarding, unauthorized bank account modifications, invoice duplication, and approval limit dodging (smurfing). BEC attacks alone average **$130,000 in direct loss per incident**.

**AP Fraud Sentinel** provides real-time, zero-cost, multi-agent AI screening with strict **Human-in-the-Loop (HITL)** controls, ensuring no suspicious invoice can be released without out-of-band verification against an authoritative master registry.

---

## 2. Multi-Agent Pipeline Topology

The core pipeline is defined in `ap_sentinel_groq.pipe` (with automatic failover to `ap_sentinel_gemini.pipe`). It executes three specialist agents in sequence:

```
                  ┌───────────────────────────────┐
                  │ 1. Ingest & Forensic Pre-Check│
                  └──────────────┬────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ [Agent 1: OCR & Extraction Specialist]                          │
│ • Extracts vendor name, invoice number, amounts, bank accounts  │
│ • Detects urgency keywords ('wire today', 'confidential', etc.) │
│ • Flags claimed C-Suite/CEO overrides & bank change requests    │
└────────────────────────────────┬────────────────────────────────┘
                                 │ Data Lane: 'text'
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ [Agent 2: Anomaly & Delta Detection Agent]                      │
│ • Compares domain against master registry (Levenshtein distance)│
│ • Checks bank account & ABA routing against payment history     │
│ • Validates ISO 7064 MOD-97 IBAN checksums                      │
│ • Flags velocity spikes (>150% historical avg) and smurfing     │
└────────────────────────────────┬────────────────────────────────┘
                                 │ Data Lane: 'text'
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ [Agent 3: Forensic Fraud Scorer]                                │
│ • Aggregates multi-agent signals into a weighted risk score     │
│ • Assigns final Decision Tier: CLEAN, ELEVATED, or HOLD         │
│ • Formulates mandatory Out-of-Band verification protocols       │
└────────────────────────────────┬────────────────────────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          ▼                      ▼                      ▼
   ✅ CLEAN (0.00–0.25)   ⚠️ ELEVATED (0.26–0.60) 🔴 HOLD (0.61–1.00)
    Auto-Approved          Secondary Queue        Payment Frozen
    ERP Sync               Analyst Review         HITL Approval Required
```

---

## 3. Deterministic Forensic Rules (`backend/forensics.py`)

To complement LLM inference with mathematical precision, the system executes deterministic pre-flight checks:

| Module | Algorithm / Technique | Purpose |
|---|---|---|
| **Domain Typosquatting** | Levenshtein Edit Distance + Homoglyph normalization (`0` $\leftrightarrow$ `o`, `rn` $\leftrightarrow$ `m`, `vv` $\leftrightarrow$ `w`, `.co` $\leftrightarrow$ `.com`) | Detects lookalike domains (e.g. `acme-c0rp.com` targeting `acme-corp.com`) |
| **IBAN Integrity** | ISO 7064 MOD-97-10 Checksum Algorithm | Immediately catches synthetic or corrupted IBAN numbers |
| **ABA Transit Integrity** | Federal Reserve 9-Digit Checksum | Validates US bank routing transit integrity |
| **Velocity & Smurfing** | Rolling mean deviation + Threshold proximity ($\pm 10\%$ of \$10k, \$25k, \$50k) | Identifies split invoices intended to bypass approval limits |

---

## 4. Human-in-the-Loop (HITL) Gate Protocol

Every invoice classified as **HOLD (Risk Score $\ge 0.61$)** triggers the following mandatory workflow:

1. **Immediate Payment Freeze**: The transaction is held in SQLite with `hitl_action = NULL`.
2. **Out-of-Band Verification Notice**: The dashboard displays the verified phone number extracted strictly from the master vendor registry.
3. **Scam Contact Warning**: Analysts are explicitly instructed:  
   `⛔ DO NOT call any phone number or email listed in the suspicious invoice.`
4. **Action Requirement**: The analyst must complete the out-of-band phone verification and click either:
   - **`✅ Release Payment`**: Logs approval to SQLite with timestamp and analyst ID.
   - **`🚫 Reject & Blacklist`**: Permanently rejects the payment and flags the vendor profile.

---

## 5. API Reference

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Web dashboard UI |
| `GET` | `/api/health` | Service health, engine mode, vendor registry count |
| `POST` | `/api/audit/stream` | Real-time SSE streaming batch processing |
| `POST` | `/api/audit/single` | Instant single-invoice screening with full explainability trace |
| `GET` | `/api/audit/history` | Retrieves recent audit logs from SQLite (supports `?limit=N`) |
| `GET` | `/api/audit/stats` | Aggregated metrics (total, clean, elevated, hold, fraud held USD) |
| `POST` | `/api/audit/clear` | Clears audit logs and resets duplicate tracking for demo runs |
| `GET` | `/api/vendors` | Retrieves all registered master vendors |
| `POST` | `/api/vendors` | Registers or updates a vendor master record |
| `POST` | `/api/hitl/release/{id}` | Releases a held payment (logged to SQLite) |
| `POST` | `/api/hitl/reject/{id}` | Rejects and blacklists a held payment (logged to SQLite) |
| `GET` | `/api/sample-batch` | 10-invoice sample demo dataset |
| `GET` | `/api/large-batch` | 63-invoice comprehensive stress-test dataset |

---

## 6. Deployment & Operations

### Prerequisites
- Python 3.10+
- Groq API Key (Free tier at [console.groq.com](https://console.groq.com))
- Google Gemini API Key (Free tier at [aistudio.google.com](https://aistudio.google.com))

### Environment Configuration (`.env`)
```bash
# RocketRide Engine
ROCKETRIDE_URI=ws://localhost:5565
ROCKETRIDE_APIKEY=local

# Primary LLM Provider
GROQ_API_KEY=gsk_...
GROQ_BASE_URL=https://api.groq.com/openai/v1
GROQ_MODEL=llama-3.1-8b-instant

# Fallback LLM Provider
GEMINI_API_KEY=AIzaSy...
GEMINI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
GEMINI_MODEL=gemini-3.5-flash

# Optional Email Alerts
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=ap-team@yourcompany.com
SMTP_PASS=app_password
ALERT_EMAIL=security-desk@yourcompany.com
```

### Running the Server
```powershell
python -m uvicorn backend.server:app --reload --port 8000
```
Open **`http://localhost:8000`** in your browser.
