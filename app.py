"""
CivicShield Backend - app.py
============================
Enterprise Flask API powering the CivicShield verification platform
and the CivicShield AI Cyber Intelligence Assistant.

Architecture Highlights:
  • LLM Engine: Groq — openai/gpt-oss-120b (131K context, reasoning effort control)
  • Heuristic Engine: Lookalike phishing, typosquatting, UPI handle mismatch, digital arrest forensics
  • OCR Pipeline: Multi-pass PIL image enhancement (grayscale, contrast, auto-binarization)
  • Resilience: Autonomous multi-turn intelligence fallback during API rate limits or latency spikes
  • Security: Structured CORS, payload sanitization, request tracing, audit logging
"""

import os
import re
import time
import uuid
import logging
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

# ── Groq LLM client ──────────────────────────────────────────────────────────
try:
    from groq import Groq, GroqError, RateLimitError, AuthenticationError, APIConnectionError
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    # Fallback stubs so `except` clauses don't NameError
    class GroqError(Exception): ...
    class RateLimitError(GroqError): ...
    class AuthenticationError(GroqError): ...
    class APIConnectionError(GroqError): ...

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

# ── App Setup ────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__, static_folder=str(STATIC_DIR))

# Configurable CORS handling
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

# Rate limiter setup
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
            def decorator(f):
                return f
            return decorator
    limiter = DummyLimiter()
    log.warning("Flask-Limiter not installed — running without rate limits.")

# ═══════════════════════════════════════════════════════════════════════════
# GROQ LLM CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL   = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
GROQ_REASONING_EFFORT = os.getenv("GROQ_REASONING_EFFORT", "medium")  # low | medium | high
GROQ_MAX_TOKENS = int(os.getenv("GROQ_MAX_TOKENS", "2048"))
GROQ_TEMPERATURE = float(os.getenv("GROQ_TEMPERATURE", "0.4"))

SYSTEM_PROMPT = (
    "You are CivicShield AI Assistant, an elite, authoritative cybersecurity and "
    "document forensics expert specializing in Indian digital fraud prevention.\n\n"
    "Your core mandate is protecting citizens from government impersonation scams, "
    "digital arrest extortion, fake court summons, parcel courier traps (FedEx/NCB), "
    "fraudulent traffic challans, and illegal payment demands.\n\n"
    "CRITICAL PROTOCOLS TO REITERATE TO CITIZENS:\n"
    "1. No legitimate Indian law enforcement (CBI, ED, Police, Courts, NCB, NIA) ever conducts "
    "'Digital Arrests' or interrogations via Skype, WhatsApp, or video call.\n"
    "2. Police and courts NEVER demand money, bail deposits, or transfers to 'RBI verification' "
    "or 'safe custody' accounts.\n"
    "3. Government agencies NEVER collect penalties via personal UPI handles (e.g. @okhdfcbank, @paytm, @ybl).\n"
    "4. Immediate emergency reporting within India: National Cyber Helpline 1930 and portal cybercrime.gov.in.\n\n"
    "Format your responses cleanly using structured Markdown with bold headers, bullet lists, "
    "and clear action steps. Maintain a calm, professional, and authoritative tone."
)

groq_client = None
if GROQ_AVAILABLE and GROQ_API_KEY:
    try:
        groq_client = Groq(api_key=GROQ_API_KEY, timeout=12.0)
        log.info("Groq client initialised — model=%s, reasoning_effort=%s",
                 GROQ_MODEL, GROQ_REASONING_EFFORT)
    except Exception as e:
        log.warning("Groq client init failed: %s", e)
        groq_client = None
else:
    if not GROQ_API_KEY:
        log.info("No GROQ_API_KEY set — running in autonomous-heuristic mode.")
    if not GROQ_AVAILABLE:
        log.warning("groq package not installed — run: pip install groq")

# ═══════════════════════════════════════════════════════════════════════════
# REQUEST TRACING & SECURITY AUDIT TRAILS
# ═══════════════════════════════════════════════════════════════════════════

def get_client_ip() -> str:
    """Retrieve client IP respecting reverse proxies (X-Forwarded-For)."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"

def sanitize_text(text: str) -> str:
    """Sanitize text buffer to remove null bytes and unprintable control chars."""
    if not text:
        return ""
    # Strip null bytes and non-printable control chars except \n, \r, \t
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

    # Security audit logging
    log.info("[%s] [%s] %s %s -> %s (%.1fms)",
             req_id, client_ip, request.method, request.path, resp.status_code, dur)

    # Security response headers
    resp.headers["X-Request-ID"] = req_id
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return resp

# ═══════════════════════════════════════════════════════════════════════════
# FILE & OCR PREPROCESSING ENGINE
# ═══════════════════════════════════════════════════════════════════════════

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def sniff_real_type(path: str) -> str | None:
    """Detect actual file type from magic bytes, ignoring user-supplied extension."""
    try:
        with open(path, "rb") as f:
            head = f.read(32)
    except OSError:
        return None

    if head.startswith(b"%PDF-"):              return "pdf"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):  return "png"
    if head.startswith(b"\xff\xd8\xff"):       return "jpg"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP": return "webp"
    if head[:4] == b"\x00\x00\x01\x00":        return None  # ICO — reject
    if head[:2] == b"PK":                      return None  # ZIP/docx — reject
    if head[:2] == b"MZ":                      return None  # EXE — reject

    try:
        head.decode("utf-8")
        return "txt"
    except UnicodeDecodeError:
        pass

    return None

def extract_text_from_pdf(filepath: str) -> str:
    """Extract embedded text streams from PDF, handling encryption gracefully."""
    if not PYPDF_AVAILABLE:
        return ""
    try:
        reader = PdfReader(filepath)
        if reader.is_encrypted:
            try:
                reader.decrypt("")
            except Exception:
                log.info("Encrypted PDF rejected (no empty password).")
                return ""
        pages_text = []
        for page in reader.pages:
            t = page.extract_text()
            if t:
                pages_text.append(t)
        return "\n".join(pages_text).strip()
    except Exception as e:
        log.warning("PDF parse failed: %s", e)
        return ""

def preprocess_image_pipeline(raw_img: "Image.Image") -> list[tuple[str, "Image.Image"]]:
    """
    Produce optimized image passes to maximize OCR text yield from low-quality
    screenshots, WhatsApp compression artifacts, and phone photos.
    """
    variants = []
    try:
        # 1. Correct EXIF rotation if present
        img = ImageOps.exif_transpose(raw_img)
    except Exception:
        img = raw_img

    # 2. Scale up if resolution is low (crucial for WhatsApp/SMS screenshot OCR)
    w, h = img.size
    resample_filter = getattr(Image, "Resampling", Image).LANCZOS
    if max(w, h) < 1400:
        scale = min(3.0, 1800.0 / max(w, h))
        new_size = (int(w * scale), int(h * scale))
        img = img.resize(new_size, resample=resample_filter)

    # Pass A: Grayscale with high contrast and sharpness (handles stamps, colored paper)
    gray = img.convert("L")
    gray_auto = ImageOps.autocontrast(gray, cutoff=1)
    contrast_enhanced = ImageEnhance.Contrast(gray_auto).enhance(1.9)
    sharp_enhanced = ImageEnhance.Sharpness(contrast_enhanced).enhance(1.5)
    variants.append(("contrast_grayscale", sharp_enhanced))

    # Pass B: Binarized thresholding (cuts through dark/colored noisy backgrounds)
    try:
        thresholded = sharp_enhanced.point(lambda p: 255 if p > 135 else 0)
        variants.append(("binarized", thresholded))
    except Exception:
        pass

    # Pass C: Direct RGB (fallback for subtle colored text)
    if img.mode != "RGB":
        variants.append(("rgb", img.convert("RGB")))
    else:
        variants.append(("rgb", img))

    return variants

def extract_text_from_image(filepath: str) -> str:
    """
    Execute multi-pass OCR on preprocessed image variants to capture the highest
    yield text from scam documents and screenshots.
    """
    if not (PILLOW_AVAILABLE and PYTESSERACT_AVAILABLE):
        return ""

    tess_path = os.getenv("TESSERACT_CMD")
    if tess_path:
        pytesseract.pytesseract.tesseract_cmd = tess_path

    best_text = ""
    try:
        with Image.open(filepath) as raw_img:
            variants = preprocess_image_pipeline(raw_img)

            # Try passes until satisfactory text is retrieved
            for variant_name, img_variant in variants:
                try:
                    # Config options: OEM 3 (Default LSTM), PSM 3 (Fully automatic page segmentation)
                    config = "--oem 3 --psm 3"
                    text = pytesseract.image_to_string(img_variant, lang="eng", config=config).strip()
                    if len(text) > len(best_text):
                        best_text = text

                    # If we found substantial text (>120 chars), we don't need further passes
                    if len(best_text) >= 120:
                        break
                except Exception as sub_e:
                    log.debug("OCR pass [%s] error: %s", variant_name, sub_e)

            # Fallback pass: Sparse text mode (PSM 11) for scattered text or badges
            if len(best_text) < 40:
                try:
                    sparse_text = pytesseract.image_to_string(
                        variants[0][1], lang="eng", config="--oem 3 --psm 11"
                    ).strip()
                    if len(sparse_text) > len(best_text):
                        best_text = sparse_text
                except Exception:
                    pass

    except Exception as e:
        log.warning("OCR pipeline failed for %s: %s", filepath, e)

    return best_text.strip()

# ═══════════════════════════════════════════════════════════════════════════
# FORENSIC & HEURISTIC ENGINE
# ═══════════════════════════════════════════════════════════════════════════

# Official government domain rules
OFFICIAL_SUFFIXES = (
    ".gov.in", ".nic.in", ".mil.in", ".ac.in", ".edu.in", ".res.in"
)
OFFICIAL_EXACT = {
    "gov.in", "nic.in", "digitalindia.gov.in", "india.gov.in",
    "cybercrime.gov.in", "incometax.gov.in", "uidai.gov.in",
    "parivahan.gov.in", "ceir.sancharsaathi.gov.in", "echallan.parivahan.gov.in"
}

# Known Indian Government Agency keywords vulnerable to typosquatting & spoofing
GOV_BRAND_TOKENS = [
    "incometax", "parivahan", "echallan", "challan", "uidai", "aadhaar",
    "aadhar", "cybercrime", "passportindia", "epfindia", "epfo", "rbi",
    "sebi", "trai", "cbi", "ncb", "delhipolice", "mumbaipolice", "digilocker",
    "sancharsaathi", "mha", "nic", "gov"
]

# URL Shorteners often used to hide phishing destinations
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy",
    "shorturl.at", "ow.ly", "buff.ly", "rebrand.ly", "soo.gd"
}

# Suspicious TLDs heavily correlated with fraud & phishing infrastructure
SUSPICIOUS_TLDS = (
    ".icu", ".top", ".xyz", ".club", ".buzz", ".work",
    ".tk", ".ml", ".ga", ".cf", ".gq"
)

IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$")

# Comprehensive forensic threat categories
THREAT_CATEGORIES = [
    (
        "digital_arrest",
        "Digital Arrest & Virtual Extortion",
        r"\b(digital\s*arrest|virtual\s*arrest|stay\s*on\s*(video|camera|call)|do\s*not\s*disconnect|skype\s*call|video\s*interrogation|video\s*statement\s*under\s*section\s*161|stay\s*isolated|room\s*lock)\b",
        4.5,
        "Law enforcement in India NEVER conducts 'Digital Arrests' or video-call interrogations."
    ),
    (
        "narcotics_courier_trap",
        "Parcel Interception & Narcotics Trap",
        r"\b(fedex|dhl|bluedart|customs\s*department|narcotics\s*control\s*bureau|ncb|contraband|mdma|drugs\s*found|parcel\s*(seized|held|confiscated)|illegal\s*passport)\b",
        4.0,
        "Courier companies and customs do not demand money over calls or WhatsApp for seized packages."
    ),
    (
        "fake_legal_coercion",
        "Coercive Legal Prosecution Threats",
        r"\b(non[- ]bailable\s*warrant|nbw\s*issued|arrest\s*warrant|supreme\s*court\s*order|high\s*court\s*notice|cbi\s*(raid|warrant|notice)|ed\s*summon|pmla\s*case|money\s*laundering\s*case|police\s*patrol\s*dispatched|local\s*police\s*arriving)\b",
        3.5,
        "Arrest warrants and summons are never served over instant messaging apps or phone calls."
    ),
    (
        "urgent_financial_coercion",
        "Urgent Financial Coercion & Fake Fine",
        r"\b(pay\s*now\s*to\s*avoid\s*arrest|penalty\s*of\s*rs|fine\s*of\s*rs|bail\s*amount|security\s*deposit|immediate\s*penalty|pay\s*fine\s*within|transfer\s*funds\s*to\s*(rbi|safe|clearing|supervision)|freeze\s*all\s*(bank\s*)?accounts)\b",
        3.8,
        "Government authorities never request payments to 'safe custody' or 'RBI verification' accounts."
    ),
    (
        "coercive_deadline",
        "High-Pressure Coercive Deadline",
        r"\b(within\s*(15|30)\s*minutes|within\s*(1|2|3)\s*hours?|immediately|immediate\s*action|before\s*5\s*pm\s*today|urgent\s*compliance|last\s*warning)\b",
        2.5,
        "High-pressure artificial deadlines are designed to induce panic and prevent independent verification."
    ),
    (
        "telecom_sim_threat",
        "Telecom & SIM Deactivation Threat",
        r"\b(trai\s*disconnection|mobile\s*number\s*(blocked|suspended|disconnected)|sim\s*(deactivated|blocked)\s*in\s*2\s*hours?|illegal\s*calls\s*from\s*your\s*sim)\b",
        3.0,
        "TRAI does not disconnect individual mobile connections or send cancellation warning SMS."
    ),
    (
        "utility_kyc_bait",
        "Utility Cutoff or KYC Suspension Bait",
        r"\b((electricity|power\s*supply)\s*will\s*be\s*(disconnected|cut)\s*tonight|bill\s*update\s*pending|pan\s*(inactive|blocked)|aadhaar\s*(suspended|deactivated)|update\s*your\s*kyc\s*now)\b",
        2.8,
        "Discoms and UIDAI do not send evening SMS threats requesting immediate third-party app installations."
    ),
    (
        "crypto_giftcard_trap",
        "Cryptocurrency or Gift Card Demand",
        r"\b(cryptocurrency|bitcoin|usdt|binance|gift\s*card|google\s*play\s*card|apple\s*gift\s*card|steam\s*wallet)\b",
        4.0,
        "Official institutions NEVER accept payments or fines via cryptocurrency or retail gift cards."
    ),
    (
        "malware_apk_payload",
        "Malicious APK Application Reference",
        r"\b([a-zA-Z0-9_\-]+\.apk|download\s*the\s*app|install\s*support\s*app|anydesk|teamviewer|rustdesk)\b",
        3.5,
        "Do not download .apk files or install remote-access tools; they allow attackers to steal OTPs."
    )
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
RAW_DOMAIN_PATTERN = re.compile(r"\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b", re.IGNORECASE)
# Indian UPI VPA pattern: e.g. police-fine@okhdfcbank, payment@paytm, etc.
UPI_HANDLE_PATTERN = re.compile(r"\b[a-zA-Z0-9.\-_]{2,50}@(okhdfcbank|okaxis|oksbi|okicici|ybl|paytm|upi|axl|ibl|barodampay|federal|idfcbank|freecharge|airtel)\b", re.IGNORECASE)
GENERAL_UPI_PATTERN = re.compile(r"\b[a-zA-Z0-9.\-_]{3,50}@[a-zA-Z]{2,24}\b", re.IGNORECASE)

def inspect_domains_and_urls(text: str) -> tuple[list[str], list[str], list[dict], float]:
    """
    Forensically dissect all URLs and lookalike domain patterns in the text.
    Returns: (official_urls, fake_urls, domain_findings, url_risk_points)
    """
    official_urls = []
    fake_urls = []
    findings = []
    url_risk_points = 0.0

    urls = URL_PATTERN.findall(text)
    # Check for bare domain or IP address strings in text (e.g., 'phishtank.icu/login' or '192.168.1.1')
    raw_candidates = re.findall(
        r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s<>\"')]*)?|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>\"')]*)?",
        text,
        re.IGNORECASE
    )
    for rc in raw_candidates:
        full = rc if rc.startswith(("http://", "https://")) else f"http://{rc}"
        if full not in urls:
            urls.append(full)

    checked_hosts = set()

    for url in urls:
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower().strip(".")
        except Exception:
            continue

        if not host or host in checked_hosts:
            continue
        checked_hosts.add(host)

        is_official = host in OFFICIAL_EXACT or host.endswith(OFFICIAL_SUFFIXES)

        if is_official:
            official_urls.append(url)
            continue

        fake_urls.append(url)

        # 1. Numeric IP address host validation
        if IPV4_REGEX.match(host):
            findings.append({
                "type": "issue",
                "severity": "critical",
                "text": f"High-risk phishing indicator: Raw numeric IP host identified '{host}'. Direct IP links bypass DNS security and indicate rogue phishing infrastructure."
            })
            url_risk_points = max(url_risk_points, 7.5)

        # 2. High-risk phishing TLDs (.icu, .top, .xyz, etc.)
        elif any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            findings.append({
                "type": "issue",
                "severity": "critical",
                "text": f"High-risk phishing indicator: Suspicious top-level domain flagged for '{host}'. This TLD ({host.split('.')[-1]}) is heavily abused for disposable phishing infrastructure."
            })
            url_risk_points = max(url_risk_points, 7.5)

        # 3. URL Shortener detection
        elif host in URL_SHORTENERS:
            findings.append({
                "type": "issue",
                "severity": "high",
                "text": f"URL shortener '{host}' detected ({url}). Official government agencies never distribute legal notices or summons via masking shorteners."
            })
            url_risk_points = max(url_risk_points, 7.5)

        # 4. Lookalike / Typosquatting Government Domain Check
        else:
            matched_brands = [b for b in GOV_BRAND_TOKENS if b in host]
            if matched_brands:
                findings.append({
                    "type": "issue",
                    "severity": "critical",
                    "text": f"Spoofed / Typosquatted government domain: '{host}' mimics official services ({', '.join(matched_brands[:3])}) but is NOT hosted under .gov.in or .nic.in."
                })
                url_risk_points = max(url_risk_points, 7.5)
            else:
                findings.append({
                    "type": "warn",
                    "severity": "medium",
                    "text": f"Non-government domain: '{host}'. Legitimate Indian government portals must terminate in .gov.in or .nic.in."
                })
                url_risk_points = max(url_risk_points, 4.5)

    return official_urls, fake_urls, findings, url_risk_points

def inspect_upi_handles(text: str) -> list[dict]:
    """Detect presence of personal UPI VPAs inside purported legal/gov communications."""
    findings = []
    handles = UPI_HANDLE_PATTERN.findall(text)
    all_vpas = GENERAL_UPI_PATTERN.findall(text)

    # Exclude normal email addresses from general VPAs
    filtered_vpas = [v for v in all_vpas if not any(v.lower().endswith(dom) for dom in [".com", ".org", ".net", ".edu", ".gov.in", ".nic.in"])]

    detected_handles = list(set(handles + filtered_vpas))
    if detected_handles:
        findings.append({
            "type": "issue",
            "severity": "critical",
            "text": f"Fraudulent UPI payment handle identified ({', '.join(detected_handles[:3])}). Official law enforcement and ministries NEVER collect fines, bails, or penalties via personal UPI VPAs."
        })
    return findings

def _run_ai_analysis(text: str, filename: str | None) -> dict:
    """
    Core Heuristic Analysis Engine:
    Evaluates text against digital arrest markers, lookalike phishing patterns,
    UPI handle mismatches, and structural notice forensics.
    """
    text_clean = sanitize_text(text or "")
    text_lower = text_clean.lower()
    findings: list[dict] = []
    risk_points = 0.0
    trust_points = 0.0
    detected_tags = []

    # 1. Threat category pattern scanning
    for tag, title, pattern, weight, explanation in THREAT_CATEGORIES:
        matches = re.findall(pattern, text_lower)
        if matches:
            detected_tags.append(tag)
            findings.append({
                "type": "issue",
                "severity": "high" if weight >= 3.5 else "medium",
                "text": f"{title}: {explanation}"
            })
            risk_points += weight

    # 2. URL & Domain Forensics
    official_urls, fake_urls, domain_findings, url_risk_points = inspect_domains_and_urls(text_clean)
    findings.extend(domain_findings)
    if fake_urls:
        detected_tags.append("suspicious_urls")
        risk_points += url_risk_points
    if official_urls:
        findings.append({
            "type": "good",
            "severity": "positive",
            "text": f"Authoritative government domain verified: '{official_urls[0]}'."
        })
        trust_points += 2.0

    # 3. UPI Handle Detection
    upi_findings = inspect_upi_handles(text_clean)
    if upi_findings:
        detected_tags.append("upi_payment_trap")
        findings.extend(upi_findings)
        risk_points += 4.0

    # 4. Phone number & helpline inspection
    has_indian_phone = bool(re.search(r"\b[6-9]\d{9}\b|\+91[-\s]?\d{10}", text_clean))
    has_helpline = bool(re.search(r"\b(1930|112|100|1939)\b", text_clean))
    if not has_indian_phone and not has_helpline and len(text_clean) > 150:
        findings.append({
            "type": "warn",
            "severity": "low",
            "text": "No verifiable public authority helpline or official contact number detected."
        })
        risk_points += 0.8
    elif has_helpline:
        findings.append({
            "type": "good",
            "severity": "positive",
            "text": "Reference to recognized national cyber safety helpline (1930 / 112) present."
        })
        trust_points += 1.0

    # 5. Document structural anomalies
    if filename and filename.lower().endswith(".pdf") and len(text_clean) < 80:
        findings.append({
            "type": "warn",
            "severity": "medium",
            "text": "Document contains minimal OCR-readable text. Potential rasterized/image-only payload designed to evade text filters."
        })
        risk_points += 1.5

    # 6. Recognized Administrative Entity references (trust checks)
    if re.search(r"\b(government of india|ministry of [a-z\s]+|department of [a-z\s]+|high court of [a-z\s]+)\b", text_lower):
        if not detected_tags:
            findings.append({
                "type": "good",
                "severity": "positive",
                "text": "Document references recognized public administrative or judicial phrasing without coercive triggers."
            })
            trust_points += 1.5

    # Formal reference number syntax check
    if re.search(r"\b(ref(?:erence)?\s*(?:no|number)[.:]?\s*[A-Z0-9/\-_]{5,30}|fir\s*no[.:]?\s*\d+/\d{4})\b", text_clean, re.IGNORECASE):
        findings.append({
            "type": "good",
            "severity": "positive",
            "text": "Formal administrative filing / reference numbering syntax detected."
        })
        trust_points += 1.0

    # Calculate calibrated risk score (0.0 to 10.0)
    base_risk = risk_points - (trust_points * 0.4)
    if url_risk_points >= 7.5:
        risk = max(7.5, min(10.0, base_risk))
    elif url_risk_points >= 4.5:
        risk = max(4.5, min(10.0, base_risk))
    else:
        risk = max(0.0, min(10.0, base_risk))

    # Categorize Verdict
    if risk >= 6.0:
        verdict = "HIGH RISK — LIKELY SCAM"
        verdict_code = "danger"
        summary = (
            "CRITICAL THREAT SIGNALS DETECTED. This communication exhibits high-confidence "
            "indicators of government impersonation, digital arrest extortion, or lookalike phishing. "
            "Do NOT transfer money, install applications, or click links. Report immediately to 1930."
        )
    elif risk >= 3.0:
        verdict = "SUSPICIOUS — USE CAUTION"
        verdict_code = "warning"
        summary = (
            "SECURITY ANOMALIES OBSERVED. One or more suspicious markers (coercive language, "
            "non-government links, or artificial urgency) were identified. Verify independently "
            "through official public portals before taking any action."
        )
    else:
        verdict = "LIKELY LEGITIMATE"
        verdict_code = "safe"
        summary = (
            "NO CRITICAL THREAT MARKERS DETECTED. The communication does not exhibit coercive extortion, "
            "fraudulent payment requests, or typosquatted links. Always cross-reference with official portals."
        )

    issues    = [f["text"] for f in findings if f["type"] == "issue"]
    warnings  = [f["text"] for f in findings if f["type"] == "warn"]
    positives = [f["text"] for f in findings if f["type"] == "good"]

    return {
        "verdict": verdict,
        "verdict_code": verdict_code,
        "score": round(risk, 1),
        "summary": summary,
        "findings": findings,
        "threat_tags": detected_tags,
        "extracted_text": text_clean[:1200] if text_clean else "",
        "trust_score": round(max(0, 100 - (risk * 10)), 1),
        "issues": issues,
        "warnings": warnings,
        "positives": positives,
        "scanned_text": text_clean[:600] if text_clean else None,
    }

# ═══════════════════════════════════════════════════════════════════════════
# CONVERSATIONAL INTELLIGENCE & DETERMINISTIC FALLBACK ENGINE
# ═══════════════════════════════════════════════════════════════════════════

def _generate_deterministic_reply(query: str, history: list[dict] | None = None) -> str:
    """
    Autonomous cybersecurity advisory generator invoked when the Groq LLM API
    is unreachable, rate-limited, or experiencing latency spikes.
    Context-aware across previous conversation turns.
    """
    q = (query or "").lower()

    # Context enrichment from recent history
    history_text = " ".join([turn.get("content", "").lower() for turn in (history or [])[-3:]])
    combined_context = f"{history_text} {q}"

    # 1. Digital Arrest / Skype / Police Video Interrogation
    if any(k in combined_context for k in ["digital arrest", "video call", "skype", "camera", "stay on line", "cbi video", "customs video"]):
        return (
            "### Critical Advisory: Digital Arrest Scam Alert\n\n"
            "**Verdict**: 100% FRAUDULENT COERCION.\n\n"
            "**Key Facts You Must Know**:\n"
            "* **No 'Digital Arrest' Exists in Indian Law**: Neither the Code of Criminal Procedure (CrPC), "
            "Bharatiya Nagarik Suraksha Sanhita (BNSS), nor the Indian Penal Code recognizes 'digital arrest'.\n"
            "* **No Video-Call Interrogations**: Legitimate police, CBI, Customs, ED, or NIA officers "
            "NEVER question suspects or take official statements via WhatsApp or Skype video calls.\n"
            "* **Never Send Funds**: Scammers will demand that you deposit funds into a 'safe custody' or "
            "'RBI verification' account. No such account exists in the Reserve Bank of India.\n\n"
            "**Immediate Action Protocol**:\n"
            "1. **Disconnect immediately**: Terminate the call without fear.\n"
            "2. **Call 1930**: Report the caller's phone numbers to the National Cyber Crime Helpline.\n"
            "3. **File a report**: Register an incident at [cybercrime.gov.in](https://cybercrime.gov.in).\n"
            "4. **Report to Chakshu**: Lodge the fraudulent number on the DoT Sanchar Saathi Chakshu portal."
        )

    # 2. FedEx / DHL / Narcotics / Parcel Contraband Trap
    if any(k in combined_context for k in ["fedex", "dhl", "courier", "parcel", "customs", "drugs", "passport in parcel", "taiwan", "narcotics"]):
        return (
            "### Advisory: Courier & Narcotics Impersonation Scam\n\n"
            "**Verdict**: HIGH-RISK IMPERSONATION SCHEME.\n\n"
            "**Modus Operandi**:\n"
            "Fraudsters pose as FedEx or DHL customer support stating that a package sent in your name "
            "containing passports, drugs, or illegal items has been intercepted at customs, then connect "
            "you to a fake 'police officer' demanding money to issue a clearance certificate.\n\n"
            "**Recommended Steps**:\n"
            "1. **Do not pay any fee or penalty**.\n"
            "2. Couriers and Customs never demand settlement via UPI, bank transfer, or crypto.\n"
            "3. Contact your local police station or dial **1930** immediately.\n"
            "4. File a complaint on [cybercrime.gov.in](https://cybercrime.gov.in)."
        )

    # 3. Traffic Challan / e-Challan / Parivahan Fake Notice
    if any(k in combined_context for k in ["challan", "echallan", "traffic", "parivahan", "speeding fine"]):
        return (
            "### Verification Advisory: Traffic e-Challan SMS\n\n"
            "**Key Signals**:\n"
            "* Real e-Challan SMS notices from Traffic Police ALWAYS direct you to **echallan.parivahan.gov.in**.\n"
            "* Scammers send links like `echallan-parivahan.vip`, `parivahan-gov.in.net`, or prompt you to download an `.apk` file.\n"
            "* Genuine notices contain your complete Vehicle Registration Number, Chassis Number, and Engine Number.\n\n"
            "**Action Steps**:\n"
            "1. Never click links in unverified challan SMS messages.\n"
            "2. Open your browser directly and visit [echallan.parivahan.gov.in](https://echallan.parivahan.gov.in).\n"
            "3. Enter your Vehicle Number to inspect authentic pending challans safely."
        )

    # 4. Immediate reporting & lost money
    if any(k in q for k in ["report", "complaint", "fraud", "scammed", "money lost", "cheated", "1930"]):
        return (
            "### Emergency Action Protocol: Incident Escalation\n\n"
            "If funds have been fraudulently transferred within the last few hours:\n\n"
            "1. **Golden Hour Helpline**: Dial **1930** immediately. The Citizen Financial Cyber Fraud Reporting "
            "System can instruct beneficiary banks to freeze the fraudster's account before withdrawal.\n"
            "2. **Official Cyber Portal**: File a detailed complaint at [cybercrime.gov.in](https://cybercrime.gov.in).\n"
            "3. **Bank Notification**: Contact your bank's dedicated 24x7 fraud desk to hotlist cards, "
            "block UPI IDs, and obtain an acknowledgment reference.\n"
            "4. **Preserve Forensic Evidence**: Screenshot transaction IDs, UTR references, chat transcripts, "
            "and caller numbers."
        )

    # 5. Court Summons & Arrest Warrants
    if any(k in q for k in ["court", "warrant", "summons", "cbi", "ed ", "enforcement directorate"]):
        return (
            "### Legal Verification: Judicial & Investigative Summons\n\n"
            "**Forensic Factsheet**:\n"
            "* Indian Courts (Supreme Court, High Courts, District Courts) NEVER serve arrest warrants "
            "or trial summons over WhatsApp or messaging applications.\n"
            "* Summons must be served by an authorized process server or sent via registered post.\n"
            "* Official case statuses can be verified in real time on the **eCourts Services** national portal "
            "([ecourts.gov.in](https://ecourts.gov.in))."
        )

    # 6. UPI Fraud & PIN Safety
    if any(k in q for k in ["upi", "paytm", "phonepe", "gpay", "collect request", "qr code", "pin"]):
        return (
            "### UPI Security Protocol\n\n"
            "**Fundamental Rule**: You **NEVER enter your UPI PIN to receive money** — a PIN is required ONLY to send funds.\n\n"
            "* QR codes are solely for paying, never for receiving.\n"
            "* Decline all unexpected UPI 'Collect Requests'.\n"
            "* Legitimate departments and vendors never ask you to scan a QR code to process refunds."
        )

    # 7. Greetings & Capabilities
    if any(k in q for k in ["hello", "hi", "hey", "who are you", "help"]):
        return (
            "### Greetings from CivicShield AI Intelligence\n\n"
            "I am your dedicated cybersecurity forensics assistant. I can help you:\n"
            "* Verify suspicious SMS, WhatsApp messages, court summons, and challan notices.\n"
            "* Identify lookalike government phishing URLs and typosquatted domains.\n"
            "* Guide emergency escalation for financial cyber fraud via **1930** and **cybercrime.gov.in**.\n\n"
            "You can upload a document above for instant heuristic scanning, or paste any suspicious text here."
        )

    # Default fallback
    return (
        "### CivicShield Intelligence Guidance\n\n"
        "I have processed your query regarding digital verification and cyber compliance.\n\n"
        "**Core Recommendations**:\n"
        "1. **Scan Suspicious Documents**: Upload any questionable notice or paste the message text in the CivicShield scanner.\n"
        "2. **Check URLs Carefully**: Authentic Indian government portals always end in `.gov.in` or `.nic.in`.\n"
        "3. **Emergency Support**: In case of financial extortion or fraudulent debit, call **1930** immediately."
    )

def _call_groq(messages: list[dict]) -> tuple[str, str]:
    """
    Call Groq chat completions API with timeout protection.
    Returns: (reply_text, engine_name)
    """
    if not groq_client:
        raise RuntimeError("Groq client not initialised")

    completion = groq_client.chat.completions.create(
        model=GROQ_MODEL,
        messages=messages,
        temperature=GROQ_TEMPERATURE,
        max_completion_tokens=GROQ_MAX_TOKENS,
        reasoning_effort=GROQ_REASONING_EFFORT,
        stream=False,
    )

    choice = completion.choices[0]
    reply = (choice.message.content or "").strip()

    if not reply:
        reasoning = getattr(choice.message, "reasoning", None)
        if reasoning:
            reply = f"{reasoning}\n\n*(Analysis synthesized by Groq reasoning engine)*"
        else:
            reply = ""

    return reply, f"groq/{GROQ_MODEL}"

# ═══════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/api/health", methods=["GET", "OPTIONS"])
def health():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify({
        "status": "healthy",
        "service": "CivicShield AI System",
        "llm_engine": f"groq/{GROQ_MODEL}" if groq_client else "autonomous-heuristic",
        "llm_configured": bool(groq_client),
        "reasoning_effort": GROQ_REASONING_EFFORT,
        "capabilities": {
            "ocr": bool(PYTESSERACT_AVAILABLE and PILLOW_AVAILABLE),
            "pdf": bool(PYPDF_AVAILABLE),
            "llm": bool(groq_client),
            "rate_limiting": bool(LIMITER_AVAILABLE),
            "heuristic_forensics": True,
        },
        "version": "4.1.0",
        "timestamp": int(time.time()),
    })

@app.route("/api/scan", methods=["POST", "OPTIONS"])
@limiter.limit("60 per hour")
def scan():
    if request.method == "OPTIONS":
        return "", 204
    extracted_text = ""
    filename = None

    if "file" in request.files:
        f = request.files["file"]
        if f.filename == "":
            return jsonify({"error": "No file selected."}), 400

        if not allowed_file(f.filename):
            return jsonify({"error": f"Invalid file extension. Permitted types: {', '.join(sorted(ALLOWED_EXTENSIONS))}"}), 400

        filename = secure_filename(f.filename)
        save_path = str(UPLOAD_DIR / f"{uuid.uuid4().hex}_{filename}")
        f.save(save_path)

        try:
            real_type = sniff_real_type(save_path)
            if real_type is None:
                return jsonify({"error": "File signature does not match permitted document or image types."}), 400

            if real_type == "pdf":
                extracted_text = extract_text_from_pdf(save_path)
            elif real_type == "txt":
                try:
                    extracted_text = Path(save_path).read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    extracted_text = ""
            else:
                extracted_text = extract_text_from_image(save_path)
        finally:
            try:
                os.remove(save_path)
            except OSError:
                pass

    elif request.is_json:
        body = request.get_json(silent=True) or {}
        extracted_text = sanitize_text(body.get("text") or "")
        if not extracted_text:
            return jsonify({"error": "Missing or empty 'text' parameter in JSON payload."}), 400

    elif request.form.get("text"):
        extracted_text = sanitize_text(request.form.get("text", ""))

    else:
        return jsonify({"error": "No file attachment or text buffer supplied in request."}), 400

    if not extracted_text and filename:
        return jsonify({
            "error": "Unable to extract legible text from this file. "
                     "If it is an image, ensure image contrast is sufficient and OCR engine is operational."
        }), 422

    result = _run_ai_analysis(extracted_text, filename)
    return jsonify(result), 200

@app.route("/api/chat", methods=["POST", "OPTIONS"])
@limiter.limit("120 per hour")
def chat():
    if request.method == "OPTIONS":
        return "", 204
    """
    Multi-turn conversational AI endpoint powered by Groq (openai/gpt-oss-120b)
    with dynamic heuristic fallback during rate limits or latency spikes.

    Payload format:
    {
      "message": "User query string",
      "history": [ {"role": "user"|"assistant", "content": "..."} ]
    }
    """
    body = request.get_json(silent=True) or {}
    user_message = sanitize_text(body.get("message") or "")

    if not user_message:
        return jsonify({"error": "Message body cannot be empty."}), 400

    history = body.get("history") or []
    source = "heuristic"
    fallback_reason = None
    reply = ""

    if groq_client:
        try:
            # Build conversation history payload (sliding window of last 10 turns)
            messages = [{"role": "system", "content": SYSTEM_PROMPT}]

            for turn in history[-10:]:
                role = turn.get("role")
                content = sanitize_text(turn.get("content") or "")
                if role == "model":
                    role = "assistant"
                if role in ("user", "assistant") and content:
                    messages.append({"role": role, "content": content})

            messages.append({"role": "user", "content": user_message})

            reply, source = _call_groq(messages)

            if not reply:
                reply = _generate_deterministic_reply(user_message, history)
                source = "autonomous-heuristic"
                fallback_reason = "empty_llm_response"

        except AuthenticationError as e:
            log.error("[%s] Groq authentication failed: %s", getattr(g, "request_id", "-"), e)
            reply = _generate_deterministic_reply(user_message, history)
            source = "autonomous-heuristic"
            fallback_reason = "authentication_error"

        except RateLimitError as e:
            log.warning("[%s] Groq rate limit hit: %s — activating autonomous fallback",
                        getattr(g, "request_id", "-"), e)
            reply = _generate_deterministic_reply(user_message, history)
            source = "autonomous-heuristic"
            fallback_reason = "rate_limit_exceeded"

        except APIConnectionError as e:
            log.warning("[%s] Groq connection failed: %s — activating autonomous fallback",
                        getattr(g, "request_id", "-"), e)
            reply = _generate_deterministic_reply(user_message, history)
            source = "autonomous-heuristic"
            fallback_reason = "connection_timeout"

        except GroqError as e:
            log.warning("[%s] Groq API error: %s — activating autonomous fallback",
                        getattr(g, "request_id", "-"), e)
            reply = _generate_deterministic_reply(user_message, history)
            source = "autonomous-heuristic"
            fallback_reason = "api_error"

        except Exception as e:
            log.exception("[%s] Unexpected LLM fault: %s", getattr(g, "request_id", "-"), e)
            reply = _generate_deterministic_reply(user_message, history)
            source = "autonomous-heuristic"
            fallback_reason = "unexpected_fault"

    else:
        reply = _generate_deterministic_reply(user_message, history)
        source = "autonomous-heuristic"

    return jsonify({
        "reply": reply,
        "engine": source,
        "status": "success",
        "fallback_reason": fallback_reason,
        "request_id": getattr(g, "request_id", "-"),
    }), 200

# ═══════════════════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════════════

@app.errorhandler(413)
def too_large(_):
    return jsonify({
        "error": f"Payload exceeds maximum permissible size ({MAX_MB} MB). Please compress or crop the file.",
        "status_code": 413
    }), 413

@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Resource not found.", "status_code": 404}), 404

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({
        "error": "Rate limit exceeded. Please wait a moment before submitting further requests.",
        "detail": str(e.description) if hasattr(e, "description") else "",
        "status_code": 429
    }), 429

@app.errorhandler(500)
def server_error(e):
    log.exception("Internal server fault")
    return jsonify({"error": "Internal computation fault. Please retry.", "status_code": 500}), 500

# ═══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"

    log.info("=" * 64)
    log.info("CivicShield Enterprise Core v4.1.0 operational on port %d", port)
    log.info("  LLM Engine ....... %s", f"groq/{GROQ_MODEL}" if groq_client else "autonomous-heuristic")
    log.info("  Reasoning ........ %s", GROQ_REASONING_EFFORT)
    log.info("  OCR Engine ....... %s", "ENABLED (Multi-pass PIL + Tesseract)" if (PYTESSERACT_AVAILABLE and PILLOW_AVAILABLE) else "disabled")
    log.info("  PDF Parser ....... %s", "ENABLED (PyPDF)" if PYPDF_AVAILABLE else "disabled")
    log.info("  Rate Limiting .... %s", "ENABLED" if LIMITER_AVAILABLE else "disabled")
    log.info("  Allowed Origins .. %s", CORS_ORIGINS)
    log.info("=" * 64)

    app.run(host="0.0.0.0", port=port, debug=debug)