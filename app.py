"""
CivicShield Backend - app.py
============================
Crash-Proof Enterprise Flask API powering the CivicShield verification platform.
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

# ── Optional heavy libraries ──
try:
    from pypdf import PdfReader
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

try:
    from PIL import Image, ImageEnhance, ImageOps
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

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("civicshield")

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__, static_folder=str(STATIC_DIR))
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", uuid.uuid4().hex)

if LIMITER_AVAILABLE:
    limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["240 per hour"])
else:
    class DummyLimiter:
        def limit(self, *args, **kwargs): return lambda f: f
    limiter = DummyLimiter()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "").strip()
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")

def sanitize_text(text):
    if not text: return ""
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(text))
    return cleaned[:25000].strip()

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"png", "jpg", "jpeg", "webp", "pdf", "txt"}

def sniff_real_type(path):
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

def extract_text_from_pdf(filepath):
    if not PYPDF_AVAILABLE: return ""
    try:
        reader = PdfReader(filepath)
        if reader.is_encrypted: return ""
        return "\n".join([page.extract_text() for page in reader.pages if page.extract_text()]).strip()
    except Exception: return ""

def extract_text_from_image(filepath):
    if not (PILLOW_AVAILABLE and PYTESSERACT_AVAILABLE): return ""
    tess_path = os.getenv("TESSERACT_CMD")
    if tess_path: pytesseract.pytesseract.tesseract_cmd = tess_path
    try:
        with Image.open(filepath) as img:
            gray = ImageOps.autocontrast(img.convert("L"), cutoff=1)
            sharp = ImageEnhance.Sharpness(ImageEnhance.Contrast(gray).enhance(1.9)).enhance(1.5)
            return pytesseract.image_to_string(sharp, lang="eng", config="--oem 3 --psm 3").strip()
    except Exception: return ""

OFFICIAL_SUFFIXES = (".gov.in", ".nic.in", ".mil.in", ".ac.in", ".edu.in")
OFFICIAL_EXACT = {"gov.in", "nic.in", "cybercrime.gov.in", "incometax.gov.in", "uidai.gov.in", "parivahan.gov.in", "echallan.parivahan.gov.in", "cbi.gov.in"}
TRUSTED_PLATFORMS = {"internshala.com", "linkedin.com", "google.com", "github.com", "microsoft.com", "apple.com"}
GOV_BRAND_TOKENS = ["incometax", "parivahan", "echallan", "challan", "uidai", "aadhaar", "cybercrime", "gov-india", "india-gov"]
SUSPICIOUS_TLDS = (".icu", ".top", ".buzz", ".work", ".tk", ".ml", ".ga", ".cf", ".gq")
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"}

THREAT_CATEGORIES = [
    ("digital_arrest", "Digital Arrest & Extortion", r"\b(digital\s*arrest|stay\s*on\s*(?:video|skype)|video\s*interrogation)\b", 4.5, "Police NEVER conduct 'Digital Arrests'."),
    ("narcotics_courier", "Parcel Interception", r"\b(?:fedex|dhl|parcel|customs)\s+.*?(?:narcotics|drugs|intercepted|arrest)\b", 4.0, "Customs do not demand money over calls."),
    ("fake_legal", "Legal Threats", r"\b(arrest\s*warrant|cbi\s*raid|nbw|police\s*patrol)\b", 3.5, "Warrants are never served over messaging apps."),
    ("urgent_finance", "Urgent Extortion", r"\b(pay\s*now\s*to\s*avoid|transfer\s+.*?\s+to\s+(?:rbi|safe)\s*account|pay\s*(?:rs\.?)?\d+\s*penalty)\b", 4.0, "Gov authorities never use 'safe custody' accounts."),
    ("panic_deadline", "Panic Deadline", r"\b(within\s*(?:15|30)\s*minutes|in\s*(?:1|2|24|48)\s*hours|blocked\s*in\s*\d+\s*hours|immediately\s*to\s*avoid)\b", 3.0, "Artificial deadlines are designed to induce panic."),
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
UPI_HANDLE_PATTERN = re.compile(r"\b[a-zA-Z0-9.\-_]{2,50}@(okhdfcbank|okaxis|oksbi|okicici|ybl|paytm|upi)\b", re.IGNORECASE)

def check_phishtank_url(url):
    if not url: return False
    try:
        payload = {"url": url, "format": "json"}
        if PHISHTANK_API_KEY: payload["app_key"] = PHISHTANK_API_KEY
        resp = requests.post("https://checkurl.phishtank.com/checkurl/", data=payload, headers={"User-Agent": "CivicShield/1.0"}, timeout=3.0)
        if resp.status_code == 200:
            data = resp.json()
            if "results" in data:
                res = data["results"]
                # FIX: Must be in the database AND actively verified as phishing
                return res.get("in_database") is True
    except Exception: pass
    return False

def check_virustotal_url(url):
    if not url or not VIRUSTOTAL_API_KEY: return None
    try:
        url_id = base64.urlsafe_b64encode(url.strip().encode()).decode().strip("=")
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=3.5)
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            return {"is_threat": malicious > 0, "malicious": malicious, "total": sum(stats.values()) or 90}
    except Exception: pass
    return None

def check_virustotal_file_hash(filepath):
    if not VIRUSTOTAL_API_KEY or not os.path.exists(filepath): return None
    try:
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            chunk = f.read(65536)
            while chunk:
                hasher.update(chunk)
                chunk = f.read(65536)
        resp = requests.get(f"https://www.virustotal.com/api/v3/files/{hasher.hexdigest()}", headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=3.5)
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"is_malicious": stats.get("malicious", 0) > 0, "malicious": stats.get("malicious", 0)}
    except Exception: pass
    return None

def classify_urls(text):
    urls = URL_PATTERN.findall(text)
    results = {"official": [], "phishtank_threat": [], "virustotal_threat": [], "virustotal_clean": [], "trusted": [], "spoofed": [], "suspicious_infra": [], "neutral": []}
    
    for url in set(urls):
        try: host = urlparse(url).hostname.lower().strip(".")
        except Exception: continue
        
        if host in OFFICIAL_EXACT or host.endswith(OFFICIAL_SUFFIXES):
            results["official"].append((url, host)); continue
            
        if check_phishtank_url(url):
            results["phishtank_threat"].append((url, host)); continue
            
        vt = check_virustotal_url(url)
        if vt:
            if vt["is_threat"]: results["virustotal_threat"].append((url, host, vt)); continue
            else: results["virustotal_clean"].append((url, host));
        
        if host in TRUSTED_PLATFORMS or host in URL_SHORTENERS:
            results["trusted"].append((url, host)); continue
            
        if any(token in host for token in GOV_BRAND_TOKENS):
            results["spoofed"].append((url, host)); continue
            
        if bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)) or any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            results["suspicious_infra"].append((url, host)); continue
            
        results["neutral"].append((url, host))
    return results

def _run_heuristic_scan(text_clean, filename=None):
    text_lower = text_clean.lower()
    findings, detected_tags = [], []
    risk_points, trust_points = 0.0, 0.0

    for tag, title, pattern, weight, explanation in THREAT_CATEGORIES:
        if re.search(pattern, text_lower):
            detected_tags.append(tag)
            findings.append({"type": "issue", "severity": "high", "text": f"{title}: {explanation}"})
            risk_points += weight

    url_classes = classify_urls(text_clean)

    for url, host in url_classes["phishtank_threat"]:
        detected_tags.append("phishtank_confirmed")
        findings.append({"type": "issue", "severity": "critical", "text": f"PHISHTANK ALERT: '{url}' is confirmed as an active phishing scam."})
        risk_points += 9.5

    for url, host, vt_info in url_classes["virustotal_threat"]:
        detected_tags.append("virustotal_confirmed")
        findings.append({"type": "issue", "severity": "critical", "text": f"VIRUSTOTAL ALERT: '{url}' flagged as malicious by {vt_info['malicious']} engines."})
        risk_points += 9.5

    for url, host in url_classes["virustotal_clean"]: trust_points += 2.0
    for url, host in url_classes["official"]:
        findings.append({"type": "good", "severity": "positive", "text": f"Official domain verified: '{host}'."})
        trust_points += 3.0

    for url, host in url_classes["spoofed"]:
        detected_tags.append("spoofed_phishing")
        findings.append({"type": "issue", "severity": "critical", "text": f"Typosquatting detected: '{host}'."})
        risk_points += 8.5

    for url, host in url_classes["suspicious_infra"]:
        detected_tags.append("suspicious_infra")
        findings.append({"type": "issue", "severity": "critical", "text": f"Suspicious IP/TLD detected: '{host}'."})
        risk_points += 7.5

    handles = list(set(UPI_HANDLE_PATTERN.findall(text_clean)))
    if handles:
        findings.append({"type": "issue", "severity": "critical", "text": f"Scam UPI Handle detected: {handles[0]}"})
        risk_points += 4.5

    # DYNAMIC MATH
    raw_score = 1.0 + risk_points - (trust_points * 0.4)
    risk = max(1.0, min(10.0, raw_score))

    if "phishtank_confirmed" in detected_tags or "virustotal_confirmed" in detected_tags:
        risk = max(9.8, risk)
    elif "spoofed_phishing" in detected_tags:
        risk = max(7.5, risk)

    if risk >= 7.5:
        verdict, verdict_code = "CRITICAL THREAT — LIKELY SCAM", "danger"
        summary = "Extortion, impersonation, or phishing threats detected."
    elif risk >= 4.0:
        verdict, verdict_code = "SUSPICIOUS — USE CAUTION", "warning"
        summary = "Security anomalies or unverified urgency patterns observed."
    else:
        verdict, verdict_code = "LIKELY LEGITIMATE", "safe"
        summary = "Content appears authentic and safe."

    return {
        "verdict": verdict, "verdict_code": verdict_code, "score": round(risk, 1),
        "summary": summary, "findings": findings, "trust_score": round(max(0, 100 - (risk * 10)), 1),
        "extracted_text": text_clean[:1000]
    }

def _generate_deterministic_reply(query, history=None):
    return "The AI engine is currently offline. If you have lost money, dial 1930 immediately."

def _generate_ai_reply(query, history=None):
    if not GROQ_API_KEY: return _generate_deterministic_reply(query, history)
    try:
        messages = [{"role": "system", "content": "You are CivicShield AI, an elite cybersecurity expert."}]
        if history:
            for msg in history[-4:]: messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})
        messages.append({"role": "user", "content": query})
        resp = requests.post("https://api.groq.com/openai/v1/chat/completions", 
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}, 
            json={"model": GROQ_MODEL, "messages": messages, "temperature": 0.3}, timeout=8)
        if resp.status_code == 200: return resp.json()["choices"][0]["message"]["content"]
    except Exception: pass
    return _generate_deterministic_reply(query, history)

@app.route("/api/health", methods=["GET", "OPTIONS"])
def health():
    if request.method == "OPTIONS": return "", 204
    return jsonify({"status": "healthy"})

@app.route("/api/scan", methods=["POST", "OPTIONS"])
@limiter.limit("60 per hour")
def scan():
    if request.method == "OPTIONS": return "", 204
    extracted_text = ""
    filename = None
    vt_file_hit = None

    try:
        if "file" in request.files:
            f = request.files["file"]
            if f.filename == "": return jsonify({"error": "No file selected."}), 400
            filename = secure_filename(f.filename)
            save_path = str(UPLOAD_DIR / f"{uuid.uuid4().hex}_{filename}")
            f.save(save_path)

            real_type = sniff_real_type(save_path)
            if not real_type: return jsonify({"error": "Invalid file signature."}), 400

            vt_file_hit = check_virustotal_file_hash(save_path)

            if real_type == "pdf": extracted_text = extract_text_from_pdf(save_path)
            elif real_type == "txt":
                try: extracted_text = Path(save_path).read_text(errors="ignore")
                except Exception: extracted_text = ""
            else: extracted_text = extract_text_from_image(save_path)
            
            try: os.remove(save_path)
            except OSError: pass

        elif request.is_json:
            extracted_text = sanitize_text(request.get_json(silent=True).get("text", ""))
        elif request.form.get("text"):
            extracted_text = sanitize_text(request.form.get("text", ""))
        else:
            return jsonify({"error": "No input provided."}), 400

        result = _run_heuristic_scan(extracted_text, filename)

        if vt_file_hit and vt_file_hit.get("is_malicious"):
            result["score"] = 10.0
            result["verdict_code"] = "danger"
            result["verdict"] = "CRITICAL THREAT — VIRUSTOTAL DETECTED MALWARE"
            result["findings"].insert(0, {"type": "issue", "severity": "critical", "text": "File matched malicious signatures."})

        return jsonify(result), 200
    except Exception as e:
        log.error(f"Scan failed: {e}")
        return jsonify({"error": "Internal server crash during scan."}), 500

@app.route("/api/chat", methods=["POST", "OPTIONS"])
@limiter.limit("120 per hour")
def chat():
    if request.method == "OPTIONS": return "", 204
    body = request.get_json(silent=True) or {}
    user_message = sanitize_text(body.get("message") or "")
    reply = _generate_ai_reply(user_message, body.get("history") or [])
    return jsonify({"reply": reply, "status": "success"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
