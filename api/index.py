"""
Vercel Python Serverless Entry Point
=====================================
AP Payment Fraud Sentinel — FastAPI app wrapped with Mangum ASGI adapter
for Vercel's serverless Python runtime.
"""

import sys
import os
from pathlib import Path

# ── Ensure repo root is on sys.path so backend.* imports resolve ─────────────
ROOT = Path(__file__).parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ── Override FRONTEND_DIR for Vercel's file system layout ───────────────────
# On Vercel, files are at /var/task/<path>; frontend is at ROOT/frontend
os.environ.setdefault("FRONTEND_DIR_OVERRIDE", str(ROOT / "frontend"))

from backend.server import app
from mangum import Mangum

# Mangum wraps the FastAPI ASGI app as an AWS Lambda / Vercel handler
handler = Mangum(app, lifespan="off")
