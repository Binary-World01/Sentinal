# ══════════════════════════════════════════════════════════════════════════════
# AP Payment Fraud Sentinel — Production Container Image
# Multi-Stage, High-Performance Multi-Agent Forensic AI & Ingestion Engine
# ══════════════════════════════════════════════════════════════════════════════

FROM python:3.11-slim as base

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    HOST=0.0.0.0

WORKDIR /app

# Install minimal OS dependencies for PDF, OCR, and document parsing
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    tesseract-ocr \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application codebase
COPY . .

# Create non-root user for security compliance
RUN useradd -m -u 1001 sentineluser && \
    mkdir -p /app/data && \
    chown -R sentineluser:sentineluser /app

USER sentineluser

# Expose FastAPI HTTP Port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Start Uvicorn Server with background worker
CMD ["python", "-m", "uvicorn", "backend.server:app", "--host", "0.0.0.0", "--port", "8000"]
