"""
AP Payment Fraud Sentinel — Forensic Rules & Deterministic Pre-Screening Engine
================================================================================
Provides fast, exact algorithmic checks that complement multi-agent LLM analysis:
1. Levenshtein & Homoglyph Typosquatting Detection (rn->m, 0->o, vv->w, character flips)
2. ISO 7064 MOD-97 IBAN Checksum Verification
3. US ABA Routing Transit Number Checksum Verification
4. Amount Velocity & Split-Invoice / Smurfing Pattern Analysis
5. Comprehensive Pre-Flight Risk Indicators
"""

import re
from typing import Optional, Dict, Any, List, Tuple


# ─── 1. Typosquatting & Domain Similarity ─────────────────────────────────────

def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    s1, s2 = s1.lower(), s2.lower()
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def normalize_domain_homoglyphs(domain: str) -> str:
    """Normalize common typosquatting substitutions for canonical comparison."""
    d = domain.lower().strip()
    subs = [
        ("0", "o"),
        ("1", "l"),
        ("rn", "m"),
        ("vv", "w"),
        ("cl", "d"),
        ("-", ""),
        ("_", ""),
    ]
    for old, new in subs:
        d = d.replace(old, new)
    return d


def detect_domain_typosquat(sender_domain: str, known_domains: List[str]) -> Tuple[bool, Optional[str], Optional[float]]:
    """
    Check if sender_domain is an impersonation/typosquat of known vendor domains.
    Returns: (is_typosquat, matched_domain, similarity_ratio)
    """
    if not sender_domain or not known_domains:
        return False, None, None

    sender_clean = sender_domain.lower().strip()
    if sender_clean in [k.lower().strip() for k in known_domains]:
        return False, sender_clean, 1.0

    sender_norm = normalize_domain_homoglyphs(sender_clean)

    for kd in known_domains:
        kd_clean = kd.lower().strip()
        kd_norm = normalize_domain_homoglyphs(kd_clean)

        # Homoglyph or normalization exact match (e.g. acme-c0rp.com vs acme-corp.com)
        if sender_norm == kd_norm:
            return True, kd_clean, 0.95

        # Levenshtein distance check
        dist = levenshtein_distance(sender_clean, kd_clean)
        max_len = max(len(sender_clean), len(kd_clean))
        similarity = 1.0 - (dist / max_len)

        # Distance of 1 or 2 on a domain is a strong typosquat indicator
        if dist <= 2 and similarity >= 0.75:
            return True, kd_clean, round(similarity, 3)

        # TLD substitution (e.g. acme-corp.co or acme-corp.net instead of acme-corp.com)
        sender_base = sender_clean.rsplit(".", 1)[0]
        kd_base = kd_clean.rsplit(".", 1)[0]
        if sender_base == kd_base and sender_clean != kd_clean:
            return True, kd_clean, 0.90

    return False, None, None


# ─── 2. Banking Detail Verification ──────────────────────────────────────────

def validate_iban_mod97(iban: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Validate IBAN format and ISO 7064 MOD-97-10 checksum algorithm.
    Returns: (is_valid, error_reason)
    """
    if not iban:
        return True, None  # Non-IBAN payment (e.g., standard US ACH)

    clean_iban = re.sub(r"\s+", "", iban).upper()
    if len(clean_iban) < 14 or len(clean_iban) > 34:
        return False, f"Invalid IBAN length ({len(clean_iban)} chars)"

    if not re.match(r"^[A-Z]{2}[0-9]{2}[A-Z0-9]+$", clean_iban):
        return False, "Invalid IBAN character structure"

    # Rearrange: move first 4 chars to end
    rearranged = clean_iban[4:] + clean_iban[:4]

    # Convert letters to digits (A=10, B=11, ... Z=35)
    numeric_str = ""
    for char in rearranged:
        if char.isdigit():
            numeric_str += char
        else:
            numeric_str += str(ord(char) - ord("A") + 10)

    try:
        mod97 = int(numeric_str) % 97
        if mod97 == 1:
            return True, None
        return False, f"MOD-97 checksum failed (remainder {mod97} != 1)"
    except Exception as e:
        return False, f"Checksum calculation error: {e}"


def validate_aba_routing(routing: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Validate US Federal Reserve ABA 9-digit routing transit number checksum.
    Checksum formula: (3(d1 + d4 + d7) + 7(d2 + d5 + d8) + 1(d3 + d6 + d9)) mod 10 == 0
    """
    if not routing:
        return True, None

    clean_routing = re.sub(r"\D", "", str(routing))
    if len(clean_routing) != 9:
        return False, f"Routing number must be 9 digits (got {len(clean_routing)})"

    digits = [int(d) for d in clean_routing]
    checksum = (
        3 * (digits[0] + digits[3] + digits[6])
        + 7 * (digits[1] + digits[4] + digits[7])
        + 1 * (digits[2] + digits[5] + digits[8])
    ) % 10

    if checksum == 0:
        return True, None
    return False, "ABA routing number checksum failed"


# ─── 3. Amount Velocity & Smurfing Analysis ───────────────────────────────────

def analyze_amount_velocity(
    current_amount: float,
    avg_amount: Optional[float],
    max_amount: Optional[float],
    past_invoices: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Analyze invoice amount against vendor history to detect:
    - Extreme velocity spikes (>150% of avg)
    - Smurfing / Split invoices (multiple payments clustered near approval thresholds)
    """
    result = {
        "velocity_spike": False,
        "deviation_pct": 0.0,
        "exceeds_max_historical": False,
        "split_invoice_warning": False,
        "threshold_proximity_flag": False,
    }

    if not current_amount or current_amount <= 0:
        return result

    # Check deviation vs historical average
    if avg_amount and avg_amount > 0:
        dev = ((current_amount - avg_amount) / avg_amount) * 100.0
        result["deviation_pct"] = round(dev, 1)
        if current_amount > (avg_amount * 1.5):
            result["velocity_spike"] = True

    # Check if this invoice exceeds any ever seen from this vendor
    if max_amount and current_amount > max_amount:
        result["exceeds_max_historical"] = True

    # Check for approval bypass / smurfing (e.g. $9,800 or $49,500 just under $10K/$50K gates)
    common_thresholds = [10000.0, 25000.0, 50000.0, 100000.0]
    for th in common_thresholds:
        if (th * 0.90) <= current_amount < th:
            result["threshold_proximity_flag"] = True
            break

    # Smurfing detection across recent invoices
    if past_invoices and len(past_invoices) >= 2:
        recent_amounts = [inv.get("amount", 0) for inv in past_invoices[-3:]]
        if any(abs(current_amount - a) < 50 for a in recent_amounts):
            result["split_invoice_warning"] = True

    return result


# ─── 4. Pre-Flight Forensic Screen Synthesizer ─────────────────────────────────

def run_deterministic_forensics(invoice: Dict[str, Any], vendor_master_record: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Runs full deterministic checks on an invoice before LLM synthesis.
    Returns structured deterministic findings for Agent 1 and Agent 2 context.
    """
    findings = {
        "typosquat": {"detected": False, "target": None, "similarity": None},
        "bank_account_changed": False,
        "routing_changed": False,
        "iban_valid": True,
        "iban_error": None,
        "routing_valid": True,
        "routing_error": None,
        "velocity": {},
        "risk_flags": [],
        "deterministic_score_penalty": 0.0,
    }

    sender_domain = invoice.get("sender_domain", "")
    known_domains = vendor_master_record.get("known_domains", []) if vendor_master_record else []

    # 1. Typosquatting
    if known_domains:
        is_typo, target, sim = detect_domain_typosquat(sender_domain, known_domains)
        if is_typo:
            findings["typosquat"] = {"detected": True, "target": target, "similarity": sim}
            findings["risk_flags"].append(f"Domain typosquat detected: '{sender_domain}' targets '{target}' (similarity: {sim})")
            findings["deterministic_score_penalty"] += 0.35

    # 2. Banking deltas
    if vendor_master_record and vendor_master_record.get("status") != "NEW_VENDOR":
        master_acc = vendor_master_record.get("bank_account_number")
        inv_acc = invoice.get("bank_account_number")
        if master_acc and inv_acc and str(master_acc).strip() != str(inv_acc).strip():
            findings["bank_account_changed"] = True
            findings["risk_flags"].append(f"Bank account mismatch: Invoice '{inv_acc}' != Registry '{master_acc}'")
            findings["deterministic_score_penalty"] += 0.30

        master_rt = vendor_master_record.get("routing_number")
        inv_rt = invoice.get("routing_number")
        if master_rt and inv_rt and str(master_rt).strip() != str(inv_rt).strip():
            findings["routing_changed"] = True
            findings["risk_flags"].append(f"Routing number mismatch: Invoice '{inv_rt}' != Registry '{master_rt}'")
            findings["deterministic_score_penalty"] += 0.15

    # 3. Checksums
    iban_val = invoice.get("iban")
    if iban_val:
        iban_ok, iban_err = validate_iban_mod97(iban_val)
        findings["iban_valid"] = iban_ok
        findings["iban_error"] = iban_err
        if not iban_ok:
            findings["risk_flags"].append(f"IBAN checksum failure: {iban_err}")
            findings["deterministic_score_penalty"] += 0.20

    rt_val = invoice.get("routing_number")
    if rt_val:
        rt_ok, rt_err = validate_aba_routing(str(rt_val))
        findings["routing_valid"] = rt_ok
        findings["routing_error"] = rt_err
        if not rt_ok:
            findings["risk_flags"].append(f"Routing checksum warning: {rt_err}")

    # 4. Velocity
    inv_amount = float(invoice.get("invoice_amount", 0) or 0)
    avg_amount = vendor_master_record.get("avg_invoice_amount") if vendor_master_record else None
    max_amount = vendor_master_record.get("max_invoice_ever") if vendor_master_record else None
    past_invoices = vendor_master_record.get("recent_invoices", []) if vendor_master_record else []

    vel = analyze_amount_velocity(inv_amount, avg_amount, max_amount, past_invoices)
    findings["velocity"] = vel

    if vel.get("velocity_spike"):
        findings["risk_flags"].append(f"Velocity spike: Amount ${inv_amount:,.2f} is +{vel['deviation_pct']}% above historical avg (${avg_amount:,.2f})")
        findings["deterministic_score_penalty"] += 0.15

    if vel.get("split_invoice_warning"):
        findings["risk_flags"].append("Potential split invoicing / smurfing detected across recent payments")
        findings["deterministic_score_penalty"] += 0.15

    if vel.get("threshold_proximity_flag"):
        findings["risk_flags"].append(f"Invoice amount (${inv_amount:,.2f}) positioned immediately below standard approval threshold")

    # Cap score penalty
    findings["deterministic_score_penalty"] = min(round(findings["deterministic_score_penalty"], 3), 0.90)
    return findings
