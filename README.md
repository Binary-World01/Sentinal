# AP Payment Fraud Sentinel

> **RocketRide Buildathon** · AP Invoice Fraud Detection · Team of 4

[![Live on Vercel](https://img.shields.io/badge/LIVE%20DEMO-ap--fraud--sentinel.vercel.app-brightgreen?style=for-the-badge&logo=vercel&logoColor=white)](https://ap-fraud-sentinel.vercel.app)
[![GitHub Repo](https://img.shields.io/badge/GitHub-Binary--World01%2FSentinal-181717?style=for-the-badge&logo=github)](https://github.com/Binary-World01/Sentinal)
[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/Binary-World01/Sentinal)

---

> 🚀 **[▶ Open Live App → ap-fraud-sentinel.vercel.app](https://ap-fraud-sentinel.vercel.app)**
>
> API Health: [ap-fraud-sentinel.vercel.app/api/health](https://ap-fraud-sentinel.vercel.app/api/health)

---

Real-time AI fraud detection for mid-size AP finance teams. Detects **Business Email Compromise (BEC)**, fake bank-detail changes, account takeovers, duplicate invoices, and vendor impersonation — with a mandatory **Human-in-the-Loop** approval gate so no fraudulent payment is ever auto-released.

---


## 5-Line Quick Start

```bash
git clone <your-repo> && cd rocketride
pip install -r requirements.txt
cp .env.example .env          # Add GROQ_API_KEY (free: console.groq.com)
# Open RocketRide VS Code extension → Connect Local (writes ROCKETRIDE_URI + ROCKETRIDE_APIKEY)
python -m uvicorn backend.server:app --reload --port 8000
```

Open **http://localhost:8000** → click **▶ Run Demo Batch**.

---

## What It Does

Mid-size AP teams pay hundreds of vendors monthly. BEC fraud costs **$130K average per incident**. This system screens every invoice through a 3-agent RocketRide pipeline and holds anything suspicious for human review.

```
Invoice JSON / PDF text
        │
        ▼ RocketRide pipeline (ap_sentinel_groq.pipe)
┌─────────────────────────────────────────────────────────┐
│  [Agent 1] OCR Parser     → extracts: vendor, bank,     │
│                              urgency signals, flags       │
│                                    │ data lane           │
│  [Agent 2] Anomaly Detector → cross-checks vs           │
│                              Vendor Master Registry       │
│                              detects: typosquats,        │
│                              bank deltas, duplicates      │
│                                    │ data lane           │
│  [Agent 3] Forensic Scorer → synthesizes risk score     │
│                              0.0–1.0 + fraud type        │
└─────────────────────────────────────────────────────────┘
        │
   ┌────┴──────────────────┐
   ↓                       ↓
✅ CLEAN (0.00–0.25)    ⚠️ ELEVATED (0.26–0.60)    🔴 HOLD (0.61–1.00)
Auto-approve            Secondary review           Payment frozen
→ ERP sync             → Analyst queue            → HITL desk
                                                   → Email alert sent
                                                   → Human must release
```

---

## Batch Performance (50-Invoice Run)

| Metric | Value |
|--------|-------|
| Invoices processed | 50 |
| Wall-clock time | ~45s |
| Cost per invoice | **$0.00** (Groq free tier) |
| Cost per 1,000 invoices | **$0.00** |
| BEC attacks detected | 5 |
| Account takeovers detected | 2 |
| Duplicate invoices caught | 2 |
| Velocity spikes flagged | 2 |
| Fraud capital held | ~$545,500 |
| Provider | Groq (primary) + Gemini (fallback) |

---

## Architecture

### RocketRide Pipeline (`ap_sentinel_groq.pipe`)

```json
{
  "components": [
    { "id": "invoice_in",          "provider": "webhook"    },
    { "id": "ocr_parser_agent",    "provider": "llm_openai" },
    { "id": "anomaly_delta_agent", "provider": "llm_openai" },
    { "id": "forensic_fraud_agent","provider": "llm_openai" },
    { "id": "sentinel_response",   "provider": "response"   }
  ]
}
```

Three specialist LLM agents running sequentially. Each agent builds on the previous agent's output via data lanes.

### Providers

| Role | Provider | Cost |
|------|----------|------|
| Primary | Groq `llama-3.1-8b-instant` | $0.00 (free tier) |
| Fallback | Google Gemini `gemini-1.5-flash` | $0.00 (free tier, 1,500 req/day) |

Fallback triggers automatically on Groq 429 rate-limit. Each verdict records `_provider` field showing which pipeline processed it.

### Stack

```
backend/server.py          FastAPI + SSE streaming + SQLite
backend/pipeline_runner.py RocketRideClient lifecycle manager
backend/main.py            CLI batch runner (SDK demo)
frontend/index.html        Dashboard UI
frontend/app.js            SSE client, HITL actions, live charts
data/invoices/             Invoice datasets (10 + 50 records)
data/audit.db              SQLite audit trail (auto-created)
ap_sentinel_groq.pipe      Primary RocketRide pipeline (Groq)
ap_sentinel_gemini.pipe    Fallback RocketRide pipeline (Gemini)
```

---

## Human-in-the-Loop (HITL) Gate

Every `HOLD` verdict:
1. Creates a red card in the **HITL Hold Desk** UI
2. Displays the exact **out-of-band action**: call the vendor on their verified phone number from the vendor master registry
3. Shows `⛔ DO NOT call any number found in the suspicious invoice`
4. Logs to `data/audit.db`
5. Sends email alert (if SMTP configured in `.env`)
6. **Requires human click** to Release or Reject — no auto-release ever

---

## Submission Checklist

- [x] `.pipe` files committed: `ap_sentinel_groq.pipe`, `ap_sentinel_gemini.pipe`
- [x] Secrets in `.env`, gitignored — `.env.example` has all `ROCKETRIDE_*` vars
- [x] Batch run with record count, cost ($0.00), wall-clock time
- [x] Human-in-the-Loop mandatory gate for every HOLD
- [x] Handles malformed input — `_error_verdict()` catches all exceptions, never crashes
- [x] Escalates uncertain cases — ERROR tier → `hitl_required=true` → HITL desk
- [x] Cost per run: `$0.00` — Groq + Gemini both free tiers, shown in UI telemetry
- [x] `terminate()` always called in `finally` / lifespan shutdown (no orphan pipelines)
- [x] Real-world action: SQLite audit DB + email alert on HOLD detection
- [x] 50-invoice batch dataset with realistic BEC, duplicates, velocity spikes

---

## Environment Variables

```bash
# Required
ROCKETRIDE_URI=ws://localhost:5565        # Written by VS Code extension
ROCKETRIDE_APIKEY=local                   # Written by VS Code extension
GROQ_API_KEY=gsk_...                      # Free: console.groq.com

# Recommended
GEMINI_API_KEY=...                        # Free fallback: aistudio.google.com

# Optional — email alerts on HOLD
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@gmail.com
SMTP_PASS=app_password
ALERT_EMAIL=ap-team@yourcompany.com
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard UI |
| `/api/health` | GET | System health + RocketRide status |
| `/api/audit/stream` | POST | SSE batch processing |
| `/api/audit/history` | GET | SQLite audit log (last 100) |
| `/api/audit/stats` | GET | Aggregate stats |
| `/api/hitl/release/{id}` | POST | Human releases held payment |
| `/api/hitl/reject/{id}` | POST | Human rejects + blacklists vendor |
| `/api/sample-batch` | GET | 10-invoice demo dataset |
| `/api/large-batch` | GET | 50-invoice full dataset |

---

## Team

| Role | Responsibility |
|------|---------------|
| Pipeline Architect | `ap_sentinel_groq.pipe` — 3-agent nodes, system prompts |
| Backend Engineer | `backend/server.py` — RocketRide SDK, SSE streaming, SQLite |
| Frontend Engineer | `frontend/` — Dashboard, HITL desk, real-time charts |
| Data Engineer | `data/` — 50-invoice dataset, fraud scenarios |

---

## Links

- [RocketRide Docs](https://docs.rocketride.org)
- [Pipeline JSON Reference](https://docs.rocketride.org/pipeline-reference)
- [Python SDK](https://docs.rocketride.org/develop/python)
- [Discord Support](https://discord.gg/PMXrtenMsY)
