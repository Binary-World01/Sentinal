"""
AP Fraud Sentinel — Embedded RocketRide DAP Engine Daemon (Port 5565)
======================================================================
Implements the complete RocketRide DAP protocol on ws://0.0.0.0:5565
supporting:
  - login / auth
  - execute / use (pipeline instantiation)
  - rrext_process (open, write [with DAP binary header+payload], close)
  - send / chat (direct execution)
  - terminate (clean session teardown)
"""

import os
import json
import uuid
import time
import asyncio
import logging
import urllib.request
import re
from typing import Dict, Any, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
import uvicorn

log = logging.getLogger("rocketride_engine")

app = FastAPI(title="RocketRide DAP Engine", version="1.2.0")

# Active pipeline sessions and data pipes
ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = {}
ACTIVE_PIPES: Dict[str, Dict[str, Any]] = {}

GROQ_KEY = os.environ.get("GROQ_API_KEY", "").strip()
GROQ_URL = os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1").strip()
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant").strip()

GEMINI_KEY = os.environ.get("GEMINI_API_KEY", "").strip()


def _llm_infer(system_prompt: str, user_payload: dict, use_gemini: bool = False) -> dict:
    """Executes inference for an agent node in the pipeline."""
    if use_gemini and GEMINI_KEY:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={GEMINI_KEY}"
        body = json.dumps({
            "contents": [{"parts": [{"text": f"{system_prompt}\n\nInput Data:\n{json.dumps(user_payload, indent=2)}"}]}],
            "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"}
        }).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        resp = urllib.request.urlopen(req, timeout=8)
        data = json.loads(resp.read().decode("utf-8"))
        content = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        if content.startswith("```"):
            content = re.sub(r"^```(?:json)?\s*", "", content, flags=re.IGNORECASE).rstrip("`").strip()
        return json.loads(content)

    if GROQ_KEY and not GROQ_KEY.startswith("your_"):
        url = GROQ_URL + "/chat/completions"
        body = json.dumps({
            "model": GROQ_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Input Data:\n{json.dumps(user_payload, indent=2)}"}
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"}
        }).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json"},
            method="POST"
        )
        resp = urllib.request.urlopen(req, timeout=8)
        data = json.loads(resp.read().decode("utf-8"))
        msg = data["choices"][0]["message"]
        content = msg.get("content") or ""
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
        if content.startswith("```"):
            content = re.sub(r"^```(?:json)?\s*", "", content, flags=re.IGNORECASE).rstrip("`").strip()
        return json.loads(content)

    # Local deterministic evaluator SSOT
    from backend.forensics import run_deterministic_forensics
    findings = run_deterministic_forensics(user_payload, user_payload.get("_vendor_master"))
    score = findings.get("deterministic_score_penalty", 0.05)
    tier = "HOLD" if score >= 0.61 else ("ELEVATED" if score >= 0.26 else "CLEAN")
    threat = "BEC" if findings.get("bank_account_changed") else (findings.get("typosquat", {}).get("target") and "DOMAIN_TYPOSQUAT")
    return {
        "risk_score": score,
        "risk_tier": tier,
        "threat_type": threat,
        "confidence": 0.98,
        "key_risk_factors": findings.get("risk_flags", ["Vendor verified in master registry; coordinates match."]),
        "recommendation": "PAYMENT_HOLD" if tier == "HOLD" else "AUTO_APPROVE",
        "out_of_band_action": "Call verified vendor contact before payment." if tier == "HOLD" else None,
        "verified_vendor_phone": user_payload.get("_vendor_master", {}).get("contact_phone", "+1-800-555-0199"),
        "auto_approve_safe": tier == "CLEAN",
        "hitl_required": tier != "CLEAN",
        "payout_eligible": tier == "CLEAN",
        "audit_summary": f"Forensic rule analysis: {threat or 'Verified clean transaction'} (Risk Score: {score:.2f})"
    }


async def execute_multi_agent_pipeline(session_info: dict, input_data: dict) -> dict:
    """Executes the 3-stage multi-agent pipeline DAG."""
    pipeline_config = session_info.get("pipeline", {})
    components = pipeline_config.get("components", [])
    use_gemini = session_info.get("use_gemini", False)

    # 1. OCR Parser Agent
    ocr_prompt = "You are a Document OCR and Extraction Specialist for AP fraud detection. Extract and return JSON with vendor_name, vendor_email, sender_domain, invoice_number, invoice_amount, bank_account_number, routing_number, urgency_language_detected, bank_change_request, executive_override_claimed, sender_spoofing_suspected."
    for c in components:
        if c.get("id") == "ocr_parser_agent":
            ocr_prompt = c.get("config", {}).get("system_prompt", ocr_prompt)

    try:
        ocr_result = _llm_infer(ocr_prompt, input_data, use_gemini=use_gemini)
    except Exception as e:
        ocr_result = input_data

    # 2. Anomaly Delta Agent
    delta_prompt = "You are an Anomaly Detection and Delta Analysis Agent for AP fraud prevention. Compare invoice fields against _vendor_master. Return JSON with bank_account_changed, routing_changed, sender_domain_matches_vendor, sender_spoofing_detected, domain_typosquat_detected, invoice_number_duplicate, anomalies_detected, anomaly_severity."
    for c in components:
        if c.get("id") == "anomaly_delta_agent":
            delta_prompt = c.get("config", {}).get("system_prompt", delta_prompt)

    delta_input = {**input_data, "extracted": ocr_result}
    try:
        delta_result = _llm_infer(delta_prompt, delta_input, use_gemini=use_gemini)
    except Exception as e:
        delta_result = {"anomalies_detected": [str(e)], "anomaly_severity": "medium"}

    # 3. Chief Forensic Auditor Agent
    forensic_prompt = "You are a Forensic AP Fraud Auditor and final risk scorer. Synthesize all signals into a final fraud verdict. Output JSON with risk_score (0.0-1.0), risk_tier (CLEAN|ELEVATED|HOLD), threat_type, confidence, key_risk_factors, recommendation (AUTO_APPROVE|SECONDARY_REVIEW|PAYMENT_HOLD), out_of_band_action, verified_vendor_phone, verified_bank_account, auto_approve_safe, hitl_required, payout_eligible, audit_summary."
    for c in components:
        if c.get("id") == "forensic_fraud_agent":
            forensic_prompt = c.get("config", {}).get("system_prompt", forensic_prompt)

    forensic_input = {**input_data, "anomalies": delta_result}
    try:
        verdict = _llm_infer(forensic_prompt, forensic_input, use_gemini=use_gemini)
    except Exception:
        from backend.forensics import run_deterministic_forensics
        findings = run_deterministic_forensics(input_data, input_data.get("_vendor_master"))
        score = findings.get("deterministic_score_penalty", 0.05)
        tier = "HOLD" if score >= 0.61 else ("ELEVATED" if score >= 0.26 else "CLEAN")
        threat = "BEC" if findings.get("bank_account_changed") else (findings.get("typosquat", {}).get("target") and "DOMAIN_TYPOSQUAT")
        verdict = {
            "risk_score": score,
            "risk_tier": tier,
            "threat_type": threat,
            "confidence": 0.98,
            "key_risk_factors": findings.get("risk_flags", ["Vendor verified in master registry"]),
            "recommendation": "PAYMENT_HOLD" if tier == "HOLD" else "AUTO_APPROVE",
            "out_of_band_action": "Call verified vendor contact." if tier == "HOLD" else None,
            "verified_vendor_phone": input_data.get("_vendor_master", {}).get("contact_phone", "+1-800-555-0199"),
            "auto_approve_safe": tier == "CLEAN",
            "hitl_required": tier != "CLEAN",
            "payout_eligible": tier == "CLEAN",
            "audit_summary": f"Forensic analysis: {threat or 'Verified clean transaction'} (Risk Score: {score:.2f})"
        }

    return verdict



@app.get("/health")
@app.get("/status")
@app.get("/api/v1/info")
async def health():
    return {
        "status": "ok",
        "service": "RocketRide Local DAP Engine",
        "version": "1.2.0",
        "port": 5565,
        "active_sessions": len(ACTIVE_SESSIONS)
    }


@app.websocket("/")
@app.websocket("/task/service")
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    log.info("RocketRide client connected to WebSocket.")

    try:
        while True:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                break

            text = message.get("text")
            data_bytes = message.get("bytes")
            binary_payload = None

            if text:
                try:
                    msg = json.loads(text)
                except Exception:
                    continue
            elif data_bytes:
                # DAP binary format: JSON_HEADER + b'\n' + BINARY_PAYLOAD
                if b"\n" in data_bytes:
                    header_bytes, binary_payload = data_bytes.split(b"\n", 1)
                    try:
                        msg = json.loads(header_bytes.decode("utf-8"))
                    except Exception:
                        continue
                else:
                    try:
                        msg = json.loads(data_bytes.decode("utf-8", errors="ignore"))
                    except Exception:
                        continue
            else:
                continue

            seq = msg.get("seq", 0)
            msg_type = msg.get("type", "request")
            command = msg.get("command", "")
            args = msg.get("arguments", {}) or msg.get("args", {})
            token = msg.get("token") or args.get("token")

            # 1. Login / Authentication
            if command in ("login", "auth", "identify", "initialize"):
                credential = args.get("credential") or args.get("auth") or "local"
                log.info(f"Client authenticated successfully (auth: {credential}).")
                resp = {
                    "seq": seq + 1,
                    "type": "response",
                    "request_seq": seq,
                    "command": command,
                    "success": True,
                    "body": {
                        "authenticated": True,
                        "token": f"auth_tok_{uuid.uuid4().hex[:10]}",
                        "user": {"id": "local_dev_user", "email": "admin@sentinel.finance"},
                        "server": {"version": "1.2.0", "engine": "RocketRide Standalone DAP Server"}
                    }
                }
                await websocket.send_text(json.dumps(resp))

            # 2. Execute / Use Pipeline
            elif command in ("execute", "use"):
                pipe_config = args.get("pipeline", {})
                task_token = args.get("token") or f"tok_rr_{uuid.uuid4().hex[:12]}"
                name = args.get("name", "master_ap_sentinel")
                use_gemini = "gemini" in str(name).lower()

                ACTIVE_SESSIONS[task_token] = {
                    "token": task_token,
                    "pipeline": pipe_config,
                    "created_at": time.time(),
                    "use_gemini": use_gemini
                }
                log.info(f"Pipeline session initialized: {task_token} (Gemini: {use_gemini})")

                resp = {
                    "seq": seq + 1,
                    "type": "response",
                    "request_seq": seq,
                    "command": command,
                    "success": True,
                    "body": {
                        "token": task_token,
                        "status": "active",
                        "project_id": pipe_config.get("project_id", "b3e359b5-ef11-43cb-964c-744f1f7676d8"),
                        "threads": 4
                    }
                }
                await websocket.send_text(json.dumps(resp))

            # 3. Data Pipe Processing: rrext_process (open, write, close)
            elif command == "rrext_process":
                subcommand = args.get("subcommand", "")

                if subcommand == "open":
                    pipe_id = f"pipe_{uuid.uuid4().hex[:8]}"
                    ACTIVE_PIPES[pipe_id] = {
                        "pipe_id": pipe_id,
                        "token": token,
                        "buffer": bytearray(),
                        "object": args.get("object", {}),
                        "mimeType": args.get("mimeType", "application/json")
                    }
                    resp = {
                        "seq": seq + 1,
                        "type": "response",
                        "request_seq": seq,
                        "command": command,
                        "success": True,
                        "body": {
                            "pipe_id": pipe_id,
                            "status": "opened"
                        }
                    }
                    await websocket.send_text(json.dumps(resp))

                elif subcommand == "write":
                    pipe_id = args.get("pipe_id")
                    data_chunk = binary_payload or args.get("data")
                    if pipe_id in ACTIVE_PIPES and data_chunk:
                        if isinstance(data_chunk, str):
                            data_chunk = data_chunk.encode("utf-8")
                        elif isinstance(data_chunk, list):
                            data_chunk = bytes(data_chunk)
                        ACTIVE_PIPES[pipe_id]["buffer"].extend(data_chunk)

                    resp = {
                        "seq": seq + 1,
                        "type": "response",
                        "request_seq": seq,
                        "command": command,
                        "success": True,
                        "body": {"status": "written"}
                    }
                    await websocket.send_text(json.dumps(resp))

                elif subcommand == "close":
                    pipe_id = args.get("pipe_id")
                    pipe_info = ACTIVE_PIPES.get(pipe_id, {})
                    task_token = pipe_info.get("token") or token
                    buffer_bytes = bytes(pipe_info.get("buffer", b""))

                    try:
                        input_payload = json.loads(buffer_bytes.decode("utf-8", errors="ignore"))
                    except Exception:
                        input_payload = {"raw_data": buffer_bytes.decode("utf-8", errors="ignore")}

                    session_info = ACTIVE_SESSIONS.get(task_token, {"pipeline": {}, "use_gemini": False})
                    verdict = await execute_multi_agent_pipeline(session_info, input_payload)

                    if pipe_id in ACTIVE_PIPES:
                        del ACTIVE_PIPES[pipe_id]

                    resp = {
                        "seq": seq + 1,
                        "type": "response",
                        "request_seq": seq,
                        "command": command,
                        "success": True,
                        "body": {
                            "text": json.dumps(verdict),
                            "answers": [json.dumps(verdict)],
                            "status": "COMPLETED",
                            "records_count": 1,
                            **verdict
                        }
                    }
                    await websocket.send_text(json.dumps(resp))

            # 4. Direct Send / Data
            elif command in ("send", "data", "pipe", "process", "chat"):
                data_raw = args.get("data") or args.get("payload") or args.get("question") or {}
                if isinstance(data_raw, (bytes, bytearray)):
                    data_raw = data_raw.decode("utf-8", errors="ignore")
                if isinstance(data_raw, str):
                    try:
                        input_payload = json.loads(data_raw)
                    except Exception:
                        input_payload = {"raw_text": data_raw}
                else:
                    input_payload = data_raw

                session_info = ACTIVE_SESSIONS.get(token, {"pipeline": {}, "use_gemini": False})
                verdict = await execute_multi_agent_pipeline(session_info, input_payload)

                resp = {
                    "seq": seq + 1,
                    "type": "response",
                    "request_seq": seq,
                    "command": command,
                    "success": True,
                    "body": {
                        "text": json.dumps(verdict),
                        "answers": [json.dumps(verdict)],
                        "status": "COMPLETED",
                        "records_count": 1,
                        **verdict
                    }
                }
                await websocket.send_text(json.dumps(resp))

            # 5. Terminate Pipeline Session
            elif command in ("terminate", "disconnect", "close"):
                task_token = args.get("token") or token
                if task_token and task_token in ACTIVE_SESSIONS:
                    del ACTIVE_SESSIONS[task_token]
                    log.info(f"Pipeline session terminated: {task_token}")

                resp = {
                    "seq": seq + 1,
                    "type": "response",
                    "request_seq": seq,
                    "command": command,
                    "success": True,
                    "body": {"status": "terminated"}
                }
                await websocket.send_text(json.dumps(resp))

            # 6. Set Events / Monitors / Ping
            elif command in ("set_events", "add_monitor", "clear_all_monitors", "ping", "heartbeat"):
                resp = {
                    "seq": seq + 1,
                    "type": "response",
                    "request_seq": seq,
                    "command": command,
                    "success": True,
                    "body": {"pong": True, "status": "ok", "timestamp": time.time()}
                }
                await websocket.send_text(json.dumps(resp))

            else:
                resp = {
                    "seq": seq + 1,
                    "type": "response",
                    "request_seq": seq,
                    "command": command,
                    "success": True,
                    "body": {"status": "acknowledged"}
                }
                await websocket.send_text(json.dumps(resp))

    except WebSocketDisconnect:
        log.info("RocketRide client disconnected.")
    except Exception as e:
        log.warning(f"WebSocket error: {e}")


def run_standalone():
    """Runs the engine on port 5565."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    log.info("🚀 Starting RocketRide Local DAP Engine Daemon on 0.0.0.0:5565...")
    uvicorn.run(app, host="0.0.0.0", port=5565, log_level="info")


if __name__ == "__main__":
    run_standalone()
