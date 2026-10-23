"""
CivicShield Backend - app.py
============================
Enterprise Flask API powering the CivicShield verification platform
and the CivicShield Cyber Threat Intelligence System.
"""

import os
import re
import json
import time
import uuid
import base64
import hashlib
import logging
import threading
import requests
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# ── Optional heavy libraries (graceful degradation) ──────────────────────────
try:
    from pypdf import PdfReader
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

try:
    from PIL import Image, ImageEnhance, ImageOps, ImageFilter
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

try:
    import pytesseract
    PYTESSERACT_AVAILABLE = True
except ImportError:
    PYTESSERACT_AVAILABLE = False

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  [%(name)s]  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("civicshield")

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__, static_folder=str(STATIC_DIR))

CORS(
    app,
    resources={r"/api/*": {"origins": "*"}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-Request-ID"],
    methods=["GET", "POST", "OPTIONS", "HEAD"],
)

MAX_MB = int(os.getenv("MAX_CONTENT_LENGTH_MB", "10"))
app.config.update(
    MAX_CONTENT_LENGTH=MAX_MB * 1024 * 1024,
    SECRET_KEY=os.getenv("SECRET_KEY", uuid.uuid4().hex),
)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "pdf", "txt"}
MAX_TEXT_PAYLOAD_CHARS = 25000

if LIMITER_AVAILABLE:
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["240 per hour"],
        storage_uri=os.getenv("RATE_LIMIT_STORAGE", "memory://"),
        headers_enabled=True,
    )
else:
    class DummyLimiter:
        def limit(self, *args, **kwargs):
            def decorator(f): return f
            return decorator
    limiter = DummyLimiter()
    log.warning("Flask-Limiter not installed — running without rate limits.")

# ═══════════════════════════════════════════════════════════════════════════
# API KEYS & CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "").strip()
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")

# ═══════════════════════════════════════════════════════════════════════════
# CORE UTILS & PREPROCESSING
# ═══════════════════════════════════════════════════════════════════════════
def get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded: return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"

def sanitize_text(text: str) -> str:
    if not text: return ""
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return cleaned[:MAX_TEXT_PAYLOAD_CHARS].strip()

@app.before_request
def _start_timer():
    g._t0 = time.perf_counter()
    g.request_id = uuid.uuid4().hex[:8]
    g.client_ip = get_client_ip()

@app.after_request
def _log_request(resp):
    dur = (time.perf_counter() - getattr(g, "_t0", time.perf_counter())) * 1000
    req_id = getattr(g, "request_id", "-")
    client_ip = getattr(g, "client_ip", "-")
    log.info("[%s] [%s] %s %s -> %s (%.1fms)", req_id, client_ip, request.method, request.path, resp.status_code, dur)
    return resp

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def sniff_real_type(path: str) -> str | None:
    try:
        with open(path, "rb") as f: head = f.read(32)
    except OSError: return None
    if head.startswith(b"%PDF-"): return "pdf"
    if head.startswith(b"\x89PNG\r\n\x1a\n"): return "png"
    if head.startswith(b"\xff\xd8\xff"): return "jpg"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP": return "webp"
    try: head.decode("utf-8"); return "txt"
    except UnicodeDecodeError: pass
    return None

def extract_text_from_pdf(filepath: str) -> str:
    if not PYPDF_AVAILABLE: return ""
    try:
        reader = PdfReader(filepath)
        if reader.is_encrypted: return ""
        return "\n".join([page.extract_text() for page in reader.pages if page.extract_text()]).strip()
    except Exception: return ""

def extract_text_from_image(filepath: str) -> str:
    if not (PILLOW_AVAILABLE and PYTESSERACT_AVAILABLE): return ""
    tess_path = os.getenv("TESSERACT_CMD")
    if tess_path: pytesseract.pytesseract.tesseract_cmd = tess_path
    
    best_text = ""
    try:
        with Image.open(filepath) as img:
            gray = ImageOps.autocontrast(img.convert("L"), cutoff=1)
            sharp = ImageEnhance.Sharpness(ImageEnhance.Contrast(gray).enhance(1.9)).enhance(1.5)
            best_text = pytesseract.image_to_string(sharp, lang="eng", config="--oem 3 --psm 3").strip()
    except Exception as e: log.warning("OCR error: %s", e)
    return best_text.strip()

# ═══════════════════════════════════════════════════════════════════════════
# FORENSIC & HEURISTIC ENGINE (WITH PHISHTANK)
# ═══════════════════════════════════════════════════════════════════════════
OFFICIAL_SUFFIXES = (".gov.in", ".nic.in", ".mil.in", ".ac.in", ".edu.in", ".res.in")
OFFICIAL_EXACT = {"gov.in", "nic.in", "cybercrime.gov.in", "incometax.gov.in", "uidai.gov.in", "parivahan.gov.in", "echallan.parivahan.gov.in", "cbi.gov.in"}
TRUSTED_PLATFORMS = {"internshala.com", "linkedin.com", "google.com", "github.com", "microsoft.com"}
GOV_BRAND_TOKENS = ["incometax", "parivahan", "echallan", "challan", "uidai", "aadhaar", "cybercrime"]
SUSPICIOUS_TLDS = (".icu", ".top", ".buzz", ".work", ".tk", ".ml", ".ga", ".cf", ".gq")
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"}

THREAT_CATEGORIES = [
    ("digital_arrest", "Digital Arrest & Virtual Extortion", r"\b(digital\s*arrest|stay\s*on\s*(?:video|skype)|video\s*interrogation)\b", 4.5, "Police NEVER conduct 'Digital Arrests'."),
    ("narcotics_courier_trap", "Parcel Interception", r"\b(?:fedex|dhl|parcel|customs)\s+.*?(?:narcotics|drugs|intercepted|arrest)\b", 4.0, "Customs do not demand money over calls."),
    ("fake_legal_coercion", "Legal Prosecution Threats", r"\b(arrest\s*warrant|cbi\s*raid|nbw|police\s*patrol\s*dispatched)\b", 3.5, "Warrants are never served over WhatsApp."),
    ("urgent_financial_coercion", "Urgent Extortion", r"\b(pay\s*now\s*to\s*avoid|transfer\s+.*?\s+to\s+(?:rbi|safe)\s*account)\b", 4.0, "Gov authorities never use 'safe custody' accounts."),
    ("coercive_deadline", "Panic Deadline", r"\b(within\s*(?:15|30)\s*minutes|within\s*(?:1|2)\s*hours|pay\s*immediately\s*to\s*avoid)\b", 2.5, "Artificial deadlines induce panic."),
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
UPI_HANDLE_PATTERN = re.compile(r"\b[a-zA-Z0-9.\-_]{2,50}@(okhdfcbank|okaxis|oksbi|okicici|ybl|paytm|upi)\b", re.IGNORECASE)

# ── PhishTank API Check ──
def check_phishtank_url(url: str, timeout: float = 3.0) -> bool:
    if not url: return False
    try:
        payload = {"url": url, "format": "json"}
        if PHISHTANK_API_KEY: payload["app_key"] = PHISHTANK_API_KEY
        resp = requests.post("https://checkurl.phishtank.com/checkurl/", data=payload, headers={"User-Agent": "CivicShield/1.0"}, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            if data and "results" in data:
                res = data["results"]
                # THE FIX: Must confirm it is both in the database AND verified as a phishing threat
                return res.get("in_database") is True and res.get("valid") is True
    except Exception: pass
    return False

# ── VirusTotal API Check ──
_VIRUSTOTAL_CACHE = {}
_VIRUSTOTAL_CACHE_LOCK = threading.Lock()

def check_virustotal_url(url: str, timeout: float = 3.5) -> dict | None:
    if not url or not VIRUSTOTAL_API_KEY: return None
    clean_url = url.strip()
    try:
        url_id = base64.urlsafe_b64encode(clean_url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        resp = requests.get(endpoint, headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=timeout)
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            return {"is_threat": malicious > 0, "malicious": malicious, "total_engines": sum(stats.values()) or 90}
    except Exception: pass
    return None

def check_virustotal_file_hash(filepath: str) -> dict | None:
    if not VIRUSTOTAL_API_KEY or not os.path.exists(filepath): return None
    try:
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536): hasher.update(chunk)
        resp = requests.get(f"https://www.virustotal.com/api/v3/files/{hasher.hexdigest()}", headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=3.5)
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"is_malicious": stats.get("malicious", 0) > 0, "malicious": stats.get("malicious", 0), "total_engines": sum(stats.values()) or 70}
    except Exception: pass
    return None

def classify_urls(text: str) -> dict:
    urls = URL_PATTERN.findall(text)
    results = {"official": [], "phishtank_threat": [], "virustotal_threat": [], "virustotal_clean": [], "trusted": [], "spoofed": [], "suspicious_infra": [], "shortener": [], "neutral": []}
    
    for url in set(urls):
        try: host = urlparse(url).hostname.lower().strip(".")
        except Exception: continue
        
        if host in OFFICIAL_EXACT or host.endswith(OFFICIAL_SUFFIXES):
            results["official"].append((url, host))
            continue
            
        # 1. Check PhishTank FIRST
        if check_phishtank_url(url):
            results["phishtank_threat"].append((url, host))
            continue
            
        # 2. Check VirusTotal
        vt_hit = check_virustotal_url(url)
        if vt_hit:
            if vt_hit.get("is_threat"):
                results["virustotal_threat"].append((url, host, vt_hit))
                continue
            else:
                results["virustotal_clean"].append((url, host, vt_hit))

        if host in TRUSTED_PLATFORMS: results["trusted"].append((url, host)); continue
        if host in URL_SHORTENERS: results["shortener"].append((url, host)); continue
        
        if any(token in host for token in GOV_BRAND_TOKENS): results["spoofed"].append((url, host)); continue
        if bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)) or any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            results["suspicious_infra"].append((url, host)); continue
            
        results["neutral"].append((url, host))

    return results

def _run_heuristic_scan(text_clean: str, filename: str | None) -> dict:
    text_lower = text_clean.lower()
    findings, detected_tags = [], []
    risk_points, trust_points = 0.0, 0.0

    # Pattern scanning
    for tag, title, pattern, weight, explanation in THREAT_CATEGORIES:
        if re.findall(pattern, text_lower):
            detected_tags.append(tag)
            findings.append({"type": "issue", "severity": "high" if weight < 4.0 else "critical", "text": f"{title}: {explanation}"})
            risk_points += weight

    # URL Scanning
    url_classes = classify_urls(text_clean)

    # PhishTank Results
    for url, host in url_classes.get("phishtank_threat", []):
        detected_tags.append("phishtank_confirmed_threat")
        findings.append({"type": "issue", "severity": "critical", "text": f"PHISHTANK ALERT: URL '{url}' is confirmed as an active phishing scam in the global PhishTank database."})
        risk_points += 9.5

    # VirusTotal Results
    for url, host, vt_info in url_classes.get("virustotal_threat", []):
        detected_tags.append("virustotal_confirmed_threat")
        findings.append({"type": "issue", "severity": "critical", "text": f"VIRUSTOTAL ALERT: URL '{url}' is malicious (flagged by {vt_info.get('malicious')} engines)."})
        risk_points += 9.5

    for url, host, vt_info in url_classes.get("virustotal_clean", []):
        trust_points += 2.0

    for url, host in url_classes["official"]:
        findings.append({"type": "good", "severity": "positive", "text": f"Authoritative domain verified: '{host}'."})
        trust_points += 3.0

    for url, host in url_classes["spoofed"]:
        detected_tags.append("spoofed_phishing_domain")
        findings.append({"type": "issue", "severity": "critical", "text": f"Typosquatting infrastructure detected: '{host}'."})
        risk_points += 8.5

    for url, host in url_classes["suspicious_infra"]:
        detected_tags.append("suspicious_url_infra")
        findings.append({"type": "issue", "severity": "critical", "text": f"Suspicious IP/TLD detected: '{host}'."})
        risk_points += 7.5

    # UPI Handles
    handles = list(set(UPI_HANDLE_PATTERN.findall(text_clean)))
    if handles:
        detected_tags.append("upi_payment_trap")
        findings.append({"type": "issue", "severity": "critical", "text": f"Fraudulent UPI handle identified: {handles[0]}."})
        risk_points += 4.5

    # ── FIXED DYNAMIC SCORING MATH ──
    raw_score = 1.0 + risk_points - (trust_points * 0.4)
    risk = max(1.0, min(10.0, raw_score))

    # Absolute Safety Ceilings
    if "phishtank_confirmed_threat" in detected_tags or "virustotal_confirmed_threat" in detected_tags:
        risk = max(9.8, risk)
    elif bool(url_classes["spoofed"] or url_classes["suspicious_infra"]):
        risk = max(7.5, risk)

    # Verdicts
    if "phishtank_confirmed_threat" in detected_tags or "virustotal_confirmed_threat" in detected_tags:
        verdict, verdict_code = "CRITICAL THREAT — CONFIRMED MALICIOUS", "danger"
        summary = "GLOBAL THREAT ALERT: Active malicious phishing threat confirmed. Do NOT proceed."
    elif risk >= 7.5:
        verdict, verdict_code = "CRITICAL THREAT — LIKELY SCAM", "danger"
        summary = "CRITICAL THREAT SIGNALS DETECTED. Extortion, impersonation, or phishing infrastructure identified."
    elif risk >= 4.0:
        verdict, verdict_code = "SUSPICIOUS — USE CAUTION", "warning"
        summary = "SECURITY ANOMALIES OBSERVED. Unverified third-party domain or unusual urgency detected."
    else:
        verdict, verdict_code = "LIKELY LEGITIMATE", "safe"
        summary = "NO THREAT DETECTED. Content verified authentic and safe."

    return {
        "verdict": verdict, "verdict_code": verdict_code, "score": round(risk, 1),
        "summary": summary, "findings": findings, "threat_tags": detected_tags,
        "trust_score": round(max(0, 100 - (risk * 10)), 1)
    }

# ═══════════════════════════════════════════════════════════════════════════
# AI CHATBOT (GROQ LLM)
# ═══════════════════════════════════════════════════════════════════════════
def _generate_deterministic_reply(query: str, history: list[dict] | None = None) -> str:
    return "### CivicShield Backup Engine\n\nNo API Key detected or network offline. Please refer to cybercrime.gov.in for immediate assistance."

def _generate_ai_reply(query: str, history: list[dict] | None = None) -> str:
    if not GROQ_API_KEY:
        return _generate_deterministic_reply(query, history)

    try:
        system_prompt = {
            "role": "system",
            "content": (
                "You are CivicShield AI, an elite, world-class cybersecurity forensic investigator. "
                "You specialize in Indian cyber law, stopping 'Digital Arrests', and exposing scams. "
                "Format responses cleanly in Markdown. If someone is losing money, urgently direct them to dial 1930."
            )
        }
        messages = [system_prompt]
        if history:
            for msg in history[-4:]: messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})
        messages.append({"role": "user", "content": query})

        resp = requests.post("https://api.groq.com/openai/v1/chat/completions", 
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}, 
            json={"model": GROQ_MODEL, "messages": messages, "temperature": 0.3, "max_tokens": 1024}, timeout=8)
        
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]
        else:
            return _generate_deterministic_reply(query, history)
    except Exception:
        return _generate_deterministic_reply(query, history)

@app.route("/api/chat", methods=["POST", "OPTIONS"])
@limiter.limit("120 per hour")
def chat():
    if request.method == "OPTIONS": return "", 204
    body = request.get_json(silent=True) or {}
    user_message = sanitize_text(body.get("message") or "")
    if not user_message: return jsonify({"error": "Message body empty."}), 400
    
    reply = _generate_ai_reply(user_message, body.get("history") or [])
    return jsonify({"reply": reply, "engine": "groq-llm-engine" if GROQ_API_KEY else "offline-heuristics", "status": "success"}), 200

# ═══════════════════════════════════════════════════════════════════════════
# SCAN ROUTE & FILE UPLOAD
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/scan", methods=["POST", "OPTIONS"])
@limiter.limit("60 per hour")
def scan():
    if request.method == "OPTIONS": return "", 204
    extracted_text = ""
    filename = None
    vt_file_hit = None

    if "file" in request.files:
        f = request.files["file"]
        if f.filename == "": return jsonify({"error": "No file selected."}), 400
        filename = secure_filename(f.filename)
        save_path = str(UPLOAD_DIR / f"{uuid.uuid4().hex}_{filename}")
        f.save(save_path)

        try:
            real_type = sniff_real_type(save_path)
            if real_type is None: return jsonify({"error": "Invalid file signature."}), 400

            vt_file_hit = check_virustotal_file_hash(save_path)

            if real_type == "pdf": extracted_text = extract_text_from_pdf(save_path)
            elif real_type == "txt":
                try: extracted_text = Path(save_path).read_text(encoding="utf-8", errors="ignore")
                except Exception: extracted_text = ""
            else: extracted_text = extract_text_from_image(save_path)
        finally:
            try: os.remove(save_path)
            except OSError: pass

    elif request.is_json:
        extracted_text = sanitize_text(request.get_json(silent=True).get("text", ""))
    elif request.form.get("text"):
        extracted_text = sanitize_text(request.form.get("text", ""))
    else:
        return jsonify({"error": "No file or text provided."}), 400

    result = _run_heuristic_scan(extracted_text, filename)

    if vt_file_hit and vt_file_hit.get("is_malicious"):
        result["score"] = 10.0
        result["verdict_code"] = "danger"
        result["verdict"] = "CRITICAL THREAT — VIRUSTOTAL DETECTED MALWARE"
        vt_msg = f"VirusTotal Malware Alert: File '{filename}' matched malicious signatures."
        result["findings"].insert(0, {"type": "issue", "severity": "critical", "text": vt_msg})
        result["summary"] = "CRITICAL MALWARE DETECTED. Do NOT open."

    return jsonify(result), 200

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
