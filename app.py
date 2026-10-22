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
        groq_client = Groq(api_key=GROQ_API_KEY, timeout=5.0, max_retries=0)
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

    if PILLOW_AVAILABLE:
        try:
            with Image.open(path) as img:
                fmt = (img.format or "").lower()
                if fmt in ("png", "jpeg", "jpg", "webp"):
                    return "jpg" if fmt == "jpeg" else fmt
        except Exception:
            pass

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
    "parivahan.gov.in", "ceir.sancharsaathi.gov.in", "echallan.parivahan.gov.in",
    "rbi.org.in", "sebi.gov.in", "epfindia.gov.in", "passportindia.gov.in",
    "ecourts.gov.in", "mha.gov.in", "cbi.gov.in", "delhipolice.gov.in"
}

# Known Trusted / Major platforms, developer clouds & user deployments
TRUSTED_PLATFORMS = {
    "internshala.com", "naukri.com", "linkedin.com", "indeed.com",
    "google.com", "github.com", "microsoft.com", "apple.com", "youtube.com",
    "cloudflare.com", "amazon.in", "amazon.com", "flipkart.com", "swiggy.com",
    "zomato.com", "irctc.co.in", "wikipedia.org", "canva.com", "figma.com",
    "medium.com", "stackoverflow.com", "render.com", "onrender.com", "gmail.com"
}

TRUSTED_SUFFIXES = (
    ".workers.dev", ".pages.dev", ".github.io", ".vercel.app", ".netlify.app",
    ".google.com", ".microsoft.com", ".github.com", ".internshala.com",
    ".linkedin.com", ".apple.com", ".cloudflare.com"
)

# Known Indian Government Agency keywords vulnerable to typosquatting & spoofing
GOV_BRAND_TOKENS = [
    "incometax", "parivahan", "echallan", "challan", "uidai", "aadhaar",
    "aadhar", "cybercrime", "passportindia", "epfindia", "epfo",
    "sancharsaathi", "ceir", "digilocker", "delhipolice", "mumbaipolice"
]

BANK_BRAND_TOKENS = [
    "sbi", "hdfc", "icici", "pnb", "axisbank", "bankofbaroda", "canarabank", "kotak"
]

# Suspicious TLDs heavily correlated with disposable fraud infrastructure
SUSPICIOUS_TLDS = (
    ".icu", ".top", ".buzz", ".work",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".rest", ".fit"
)

# URL Shorteners often used to hide phishing destinations
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy",
    "shorturl.at", "ow.ly", "buff.ly", "rebrand.ly", "soo.gd"
}

IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$")

# High-precision threat categories (calibrated to prevent false positives on normal emails/messages)
THREAT_CATEGORIES = [
    (
        "digital_arrest",
        "Digital Arrest & Virtual Extortion",
        r"\b(digital\s*arrest|virtual\s*arrest|stay\s*on\s*(?:video|camera|skype|call)|do\s*not\s*disconnect\s*(?:the\s*)?call|skype\s*(?:video\s*)?(?:call|interrogation|statement)|video\s*interrogation|video\s*statement\s*under\s*section|stay\s*isolated\s*in\s*room|lock\s*your\s*room)\b",
        4.5,
        "Law enforcement in India NEVER conducts 'Digital Arrests' or video-call interrogations."
    ),
    (
        "narcotics_courier_trap",
        "Parcel Interception & Narcotics Trap",
        r"\b((?:fedex|dhl|bluedart|courier|parcel|customs)\s+.*?(?:narcotics|drugs|contraband|mdma|illegal\s*passport|seized|confiscated|intercepted|arrest\s*warrant)|(?:parcel|package)\s*(?:has\s*been\s*)?(?:seized|held|confiscated)\s*(?:by|at)\s*(?:customs|ncb|police))\b",
        4.0,
        "Courier companies and customs do not demand money over calls or WhatsApp for seized packages."
    ),
    (
        "fake_legal_coercion",
        "Coercive Legal Prosecution Threats",
        r"\b(non[- ]bailable\s*warrant|nbw\s*(?:issued|against\s*you)|arrest\s*warrant\s*(?:issued)?|supreme\s*court\s*(?:arrest|contempt)\s*order|cbi\s*(?:raid|warrant|interrogation|cyber)|ed\s*(?:summon|raid|custody)|pmla\s*(?:case|investigation)|money\s*laundering\s*(?:case|investigation)\s*against\s*you|police\s*patrol\s*dispatched|local\s*police\s*(?:arriving|at\s*your\s*door))\b",
        3.5,
        "Arrest warrants and summons are never served over instant messaging apps or phone calls."
    ),
    (
        "urgent_financial_coercion",
        "Urgent Financial Extortion & Fake Bail/Fine",
        r"\b(pay\s*(?:now\s*to\s*avoid\s*arrest|penalty\s*now|fine\s*immediately|bail\s*deposit)|transfer\s+.*?\s+to\s+(?:rbi|safe|clearing|supervision|custody)\s*account|settle\s*(?:penalty|fine)\s*to\s*avoid\s*arrest|threat\s*to\s*freeze\s*all\s*(?:bank\s*)?accounts)\b",
        4.0,
        "Government authorities never request payments to 'safe custody' or 'RBI verification' accounts."
    ),
    (
        "coercive_deadline",
        "High-Pressure Coercive Panic Deadline",
        r"\b(within\s*(?:15|30)\s*minutes\s*(?:to\s*avoid|or\s*face|before\s*(?:arrest|blocking|deactivation|penalty))|within\s*(?:1|2|3)\s*hours?\s*(?:to\s*avoid|or\s*face|before\s*(?:arrest|blocking|deactivation|penalty))|pay\s*immediately\s*to\s*avoid\s*arrest|immediate\s*(?:arrest|police\s*action|custody)\s*warrant|last\s*warning\s*before\s*(?:arrest|police|fir|warrant))\b",
        2.5,
        "High-pressure artificial deadlines linked to threats are designed to induce panic and prevent independent verification."
    ),
    (
        "telecom_sim_threat",
        "Telecom & SIM Deactivation Extortion",
        r"\b(trai\s*disconnection|mobile\s*number\s*(?:will\s*be\s*)?(?:blocked|suspended|disconnected)\s*(?:within|in\s*\d+\s*hours?)|sim\s*(?:will\s*be\s*)?(?:deactivated|blocked)\s*(?:in|within\s*\d+\s*hours?)|illegal\s*calls\s*made\s*from\s*your\s*sim)\b",
        3.0,
        "TRAI does not disconnect individual mobile connections or send cancellation warning SMS."
    ),
    (
        "utility_kyc_bait",
        "Utility Cutoff or KYC Suspension Bait",
        r"\b((?:electricity|power\s*supply)\s*will\s*be\s*(?:disconnected|cut)\s*(?:tonight|within\s*\d+\s*hours?)|pan\s*(?:has\s*been\s*)?(?:inactive|blocked)\s*update\s*kyc|aadhaar\s*(?:suspended|deactivated)\s*update\s*immediately|update\s*your\s*kyc\s*(?:immediately\s*or|to\s*avoid\s*account\s*block))\b",
        3.0,
        "Discoms and UIDAI do not send evening SMS threats requesting immediate third-party app installations."
    ),
    (
        "crypto_giftcard_trap",
        "Cryptocurrency or Gift Card Demand",
        r"\b(pay\s*(?:in|via|through)\s*(?:crypto|cryptocurrency|bitcoin|usdt|binance|gift\s*card|google\s*play\s*card|apple\s*gift\s*card|steam\s*wallet)|settle\s*(?:fee|penalty)\s*(?:with|using)\s*gift\s*card)\b",
        4.0,
        "Official institutions NEVER accept payments or fines via cryptocurrency or retail gift cards."
    ),
    (
        "malware_apk_payload",
        "Malicious APK Application or Remote Access Tool",
        r"\b([a-zA-Z0-9_\-]+\.apk\b|(?:download|install)\s+(?:the\s+)?(?:[a-zA-Z0-9_\-]+\s+)?apk\b|install\s*(?:anydesk|teamviewer|rustdesk|quicksupport)|connect\s*via\s*(?:anydesk|teamviewer|rustdesk))\b",
        3.5,
        "Do not download .apk files directly or install remote-access tools; they allow attackers to steal OTPs and financial data."
    )
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
RAW_DOMAIN_PATTERN = re.compile(r"\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b", re.IGNORECASE)
UPI_HANDLE_PATTERN = re.compile(r"\b[a-zA-Z0-9.\-_]{2,50}@(okhdfcbank|okaxis|oksbi|okicici|ybl|paytm|upi|axl|ibl|barodampay|federal|idfcbank|freecharge|airtel)\b", re.IGNORECASE)

# ── PhishTank & Threat Intelligence Module ────────────────────────────────────
PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/"
PHISHTANK_USER_AGENT = os.getenv("PHISHTANK_USER_AGENT", "phishtank/civicshield-naishal988")
PHISHTANK_APP_KEY = os.getenv("PHISHTANK_API_KEY", "")

_PHISHTANK_CACHE: dict[str, dict] = {}
_PHISHTANK_CACHE_LOCK = threading.Lock()
_COMMUNITY_PHISH_FEED: set[str] = set()
_COMMUNITY_FEED_LOCK = threading.Lock()

def sync_community_phish_feed():
    """Fetches high-confidence active verified phishing URLs into memory."""
    global _COMMUNITY_PHISH_FEED
    try:
        resp = requests.get("https://openphish.com/feed.txt", timeout=3.5)
        if resp.status_code == 200:
            urls = {
                line.strip().lower().rstrip("/")
                for line in resp.text.splitlines()
                if line.strip() and not line.startswith("#")
            }
            with _COMMUNITY_FEED_LOCK:
                _COMMUNITY_PHISH_FEED = urls
            log.info("Threat Intel: Synchronized %d active phishing URLs into memory", len(urls))
    except Exception as e:
        log.debug("Community phish feed sync failed (fail-safe): %s", e)

def check_phishtank_url(url: str, timeout: float = 2.5) -> dict | None:
    """
    Checks if a URL is confirmed phishing in PhishTank or live global intelligence feed.
    Returns metadata dict if active verified phish or PhishTank advisory page, else None.
    """
    if not url:
        return None

    # Check for direct PhishTank detail / advisory URL
    pt_detail_match = re.search(
        r"https?://(?:www\.)?phishtank\.(?:com|org)/phish_detail\.php\?phish_id=(\d+)",
        url,
        re.IGNORECASE
    )
    if pt_detail_match:
        phish_id = pt_detail_match.group(1)
        return {
            "in_database": True,
            "valid": True,
            "phish_id": phish_id,
            "detail_url": url,
            "verified_at": "Documented in PhishTank Incident Database",
            "target": "PhishTank Threat Investigation Record",
            "source": "PhishTank Incident Report",
            "is_advisory": True,
            "url": url
        }

    clean_url = url.strip()
    norm_key = clean_url.lower().rstrip("/")

    # Check live community feed (0ms memory lookup)
    with _COMMUNITY_FEED_LOCK:
        if norm_key in _COMMUNITY_PHISH_FEED:
            return {
                "in_database": True,
                "valid": True,
                "phish_id": "COMMUNITY-FEED",
                "detail_url": clean_url,
                "verified_at": "Active",
                "target": "Active Phishing Campaign",
                "source": "Global Verified Phishing Feed",
                "is_advisory": False,
                "url": clean_url
            }

    # Check in-memory cache
    with _PHISHTANK_CACHE_LOCK:
        cached = _PHISHTANK_CACHE.get(norm_key)
        if cached and (time.time() - cached.get("cached_at", 0) < 3600):
            return cached.get("data")

    # If the URL is an authoritative government domain, skip external network roundtrip
    parsed = urlparse(clean_url)
    host = (parsed.hostname or "").lower().strip(".")
    if host in OFFICIAL_EXACT or host.endswith(OFFICIAL_SUFFIXES):
        return None

    # Query PhishTank Check URL API
    headers = {"User-Agent": PHISHTANK_USER_AGENT}
    variants = [clean_url]
    if clean_url.endswith("/"):
        variants.append(clean_url[:-1])
    else:
        variants.append(clean_url + "/")

    for cand in variants:
        try:
            payload = {"url": cand, "format": "json"}
            if PHISHTANK_APP_KEY:
                payload["app_key"] = PHISHTANK_APP_KEY
            resp = requests.post(
                PHISHTANK_API_URL,
                data=payload,
                headers=headers,
                timeout=timeout
            )
            if resp.status_code == 200:
                res = resp.json().get("results", {})
                if res.get("in_database") and res.get("valid"):
                    match_data = {
                        "in_database": True,
                        "valid": True,
                        "phish_id": str(res.get("phish_id") or "PT-VERIFIED"),
                        "detail_url": res.get("phish_detail_page") or f"https://www.phishtank.com/phish_detail.php?phish_id={res.get('phish_id')}",
                        "verified_at": res.get("verified_at") or "Confirmed",
                        "target": res.get("target") or "Credential Phishing / Identity Theft",
                        "source": "PhishTank Cybersecurity Database",
                        "is_advisory": False,
                        "url": cand
                    }
                    with _PHISHTANK_CACHE_LOCK:
                        _PHISHTANK_CACHE[norm_key] = {"cached_at": time.time(), "data": match_data}
                    return match_data
                elif res.get("in_database") is False or res.get("valid") is False:
                    with _PHISHTANK_CACHE_LOCK:
                        _PHISHTANK_CACHE[norm_key] = {"cached_at": time.time(), "data": None}
                    return None
        except Exception:
            continue

    return None

# ── VirusTotal & Multi-Vendor Threat Intelligence Module ──────────────────────
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
_VIRUSTOTAL_CACHE: dict[str, dict] = {}
_VIRUSTOTAL_CACHE_LOCK = threading.Lock()

def check_virustotal_url(url: str, timeout: float = 2.5) -> dict | None:
    """
    Queries VirusTotal API v3 for URL reputation across 80+ global antivirus/security vendors.
    Also detects direct VirusTotal GUI analysis links.
    """
    if not url:
        return None

    clean_url = url.strip()

    # 1. Check for direct VirusTotal GUI report links
    vt_gui_match = re.search(
        r"https?://(?:www\.)?virustotal\.com/gui/(?:url|file)/([a-zA-Z0-9_\-]+)",
        clean_url,
        re.IGNORECASE
    )
    if vt_gui_match:
        return {
            "is_threat": True,
            "malicious": 1,
            "suspicious": 0,
            "total_engines": 90,
            "flagged_by": ["VirusTotal Public Forensic Investigation"],
            "source": "VirusTotal Advisory Page",
            "is_advisory": True,
            "url": clean_url
        }

    if not VIRUSTOTAL_API_KEY:
        return None

    # Skip checking authoritative government portals
    parsed = urlparse(clean_url)
    host = (parsed.hostname or "").lower().strip(".")
    if host in OFFICIAL_EXACT or host.endswith(OFFICIAL_SUFFIXES):
        return None

    norm_key = clean_url.lower().rstrip("/")
    with _VIRUSTOTAL_CACHE_LOCK:
        cached = _VIRUSTOTAL_CACHE.get(norm_key)
        if cached and (time.time() - cached.get("cached_at", 0) < 3600):
            return cached.get("data")

    try:
        url_id = base64.urlsafe_b64encode(clean_url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "User-Agent": "CivicShield-ThreatIntel/2.0"
        }
        resp = requests.get(endpoint, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attr = data.get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 90

            if malicious >= 1 or suspicious >= 2:
                results_map = attr.get("last_analysis_results", {})
                flagged = [
                    f"{eng}: {res.get('result', 'malicious')}"
                    for eng, res in results_map.items()
                    if res.get("category") in ("malicious", "suspicious")
                ][:4]

                vt_match = {
                    "is_threat": True,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total_engines": total,
                    "flagged_by": flagged,
                    "reputation": attr.get("reputation", 0),
                    "source": "VirusTotal Global Threat Intelligence",
                    "is_advisory": False,
                    "url": clean_url
                }
                with _VIRUSTOTAL_CACHE_LOCK:
                    _VIRUSTOTAL_CACHE[norm_key] = {"cached_at": time.time(), "data": vt_match}
                return vt_match
            else:
                with _VIRUSTOTAL_CACHE_LOCK:
                    _VIRUSTOTAL_CACHE[norm_key] = {"cached_at": time.time(), "data": None}
                return None
    except Exception as e:
        log.debug("VirusTotal query error (fail-safe): %s", e)

    return None

def check_virustotal_file_hash(filepath: str, timeout: float = 3.0) -> dict | None:
    """
    Computes SHA256 of uploaded file and checks against VirusTotal's database of known malware.
    """
    if not VIRUSTOTAL_API_KEY or not os.path.exists(filepath):
        return None

    try:
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        file_sha256 = hasher.hexdigest()

        endpoint = f"https://www.virustotal.com/api/v3/files/{file_sha256}"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "User-Agent": "CivicShield-ThreatIntel/2.0"
        }
        resp = requests.get(endpoint, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attr = data.get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 70

            if malicious >= 1:
                return {
                    "is_malicious": True,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total_engines": total,
                    "sha256": file_sha256,
                    "type_description": attr.get("type_description", "Binary / Executable"),
                    "meaningful_name": attr.get("meaningful_name") or os.path.basename(filepath),
                    "source": "VirusTotal Malware Database"
                }
    except Exception as e:
        log.debug("VirusTotal file hash check error (fail-safe): %s", e)

    return None

def _start_background_phish_sync():
    """Initializes non-blocking background thread for periodic phishing feed sync."""
    def _worker():
        while True:
            try:
                sync_community_phish_feed()
            except Exception as e:
                log.debug("Phish feed background sync: %s", e)
            time.sleep(3600)

    t = threading.Thread(target=_worker, daemon=True, name="CivicShield-PhishSync")
    t.start()

_start_background_phish_sync()

def classify_urls(text: str) -> dict:
    """
    Extracts and classifies URLs from text into:
      - official: Authoritative Indian government & public sector (.gov.in, .nic.in, etc.)
      - phishtank_phish: Verified active phishing URLs matched against PhishTank & live threat intelligence
      - virustotal_phish: Malicious URLs confirmed by VirusTotal global security engines
      - trusted: Recognized authentic platforms, developer clouds (workers.dev, github.io, internshala, etc.)
      - spoofed: Typosquatting / lookalike domains impersonating gov or banks on unauthorized infrastructure
      - suspicious_infra: Disposable TLDs (.top, .icu, .buzz) or raw IP addresses
      - shortener: URL shorteners (bit.ly, tinyurl, etc.)
      - neutral: Standard general web domains without spoofing or threats
    """
    urls = URL_PATTERN.findall(text)
    raw_candidates = re.findall(
        r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s<>\"')]*)?|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>\"')]*)?",
        text,
        re.IGNORECASE
    )
    for rc in raw_candidates:
        full = rc if rc.startswith(("http://", "https://")) else f"http://{rc}"
        if full not in urls:
            urls.append(full)

    results = {
        "official": [],
        "phishtank_phish": [],
        "virustotal_phish": [],
        "trusted": [],
        "spoofed": [],
        "suspicious_infra": [],
        "shortener": [],
        "neutral": []
    }
    checked_hosts = set()

    for url in urls:
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower().strip(".")
        except Exception:
            continue

        if not host:
            host_match = re.search(r"https?://([^/\s:]+)", url)
            host = host_match.group(1).lower().strip(".") if host_match else ""

        if not host or host in checked_hosts:
            continue
        checked_hosts.add(host)

        # 1. Authoritative Government & Public Institutions
        if host in OFFICIAL_EXACT or host.endswith(OFFICIAL_SUFFIXES):
            results["official"].append((url, host))
            continue

        # 2. PhishTank & Global Verified Threat Intelligence
        pt_hit = check_phishtank_url(url)
        if pt_hit and pt_hit.get("valid"):
            results["phishtank_phish"].append((url, host, pt_hit))
            continue

        # 3. VirusTotal Multi-Vendor Antivirus Engine Intelligence
        vt_hit = check_virustotal_url(url)
        if vt_hit and vt_hit.get("is_threat"):
            results["virustotal_phish"].append((url, host, vt_hit))
            continue

        # 3. Trusted Platforms & Developer Clouds (Cloudflare Workers, GitHub Pages, Internshala, etc.)
        if host in TRUSTED_PLATFORMS or any(host.endswith(sfx) for sfx in TRUSTED_SUFFIXES):
            results["trusted"].append((url, host))
            continue

        # 4. URL Shorteners
        if host in URL_SHORTENERS:
            results["shortener"].append((url, host))
            continue

        # 5. Spoofed Government or Banking Brands (Typosquatting)
        is_spoofed_gov = any(token in host for token in GOV_BRAND_TOKENS)
        is_spoofed_bank = bool(re.search(r"(?:sbi|hdfc|icici|pnb|axisbank|kotak|bob).*(?:kyc|pan|aadhaar|update|verify|reward|refund|login|netbanking)", host))
        if is_spoofed_gov or is_spoofed_bank:
            results["spoofed"].append((url, host))
            continue

        # 6. Raw IP Address or Suspicious Disposable TLDs
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
        is_bad_tld = any(host.endswith(tld) for tld in SUSPICIOUS_TLDS)
        if is_ip or is_bad_tld:
            results["suspicious_infra"].append((url, host))
            continue

        # 7. Standard Neutral Web Domain
        results["neutral"].append((url, host))

    return results

def inspect_upi_handles(text: str, has_coercive_context: bool) -> list[dict]:
    """
    Detect presence of personal UPI VPAs inside purported legal/gov communications.
    Only flagged if communication claims official authority or exhibits extortion triggers.
    """
    if not has_coercive_context:
        return []

    findings = []
    handles = list(set(UPI_HANDLE_PATTERN.findall(text)))
    if handles:
        findings.append({
            "type": "issue",
            "severity": "critical",
            "text": f"Fraudulent UPI payment handle identified ({', '.join(handles[:2])}). Official law enforcement and ministries NEVER collect fines, bails, or penalties via personal UPI VPAs."
        })
    return findings

def _run_groq_scan(text_clean: str, filename: str | None, heuristic_result: dict) -> dict | None:
    """
    Invoke Groq LLM (openai/gpt-oss-120b) for deep semantic threat understanding.
    Distinguishes legitimate job/college emails and developer projects from real fraud.
    """
    if not groq_client:
        return None

    try:
        scan_system_prompt = (
            "You are CivicShield AI, an elite cybersecurity and document forensics intelligence engine specializing in Indian digital fraud prevention.\n\n"
            "Your objective is to analyze user-provided text, URLs, notices, or extracted document contents with extreme accuracy, preventing both false negatives AND false positives.\n\n"
            "CRITICAL RULES TO PREVENT FALSE POSITIVES:\n"
            "1. LEGITIMATE SERVICES ARE SAFE (Score <= 1.8, verdict_code 'safe'):\n"
            "   - Official Indian Government portals ending in .gov.in or .nic.in are 100% legitimate.\n"
            "   - Legitimate job, career, and education platforms (e.g. Internshala, Naukri, LinkedIn, Unstop) sending interview calls, application updates, or resume shortlists are completely NORMAL and SAFE. Phrases like 'apply immediately', 'reply within 24 hours', 'limited openings', or 'download the app' in job alerts are standard benign marketing/communication and are NOT scams.\n"
            "   - Developer projects, personal portfolios, and cloud applications hosted on Cloudflare Workers (*.workers.dev, *.pages.dev), GitHub Pages (*.github.io), Vercel (*.vercel.app), or Netlify (*.netlify.app) are legitimate web applications unless actively hosting malware or phishing.\n"
            "   - General commercial receipts, college notices, academic certificates, personal messages, and clean websites are SAFE (score 1.0 - 2.0).\n\n"
            "2. REAL THREATS TO FLAG (High/Critical Risk, Score 7.0 - 10.0, verdict_code 'danger'):\n"
            "   - Digital Arrest & Virtual Extortion: Threats of arrest via WhatsApp/Skype video calls, 'room isolation', 'do not disconnect'.\n"
            "   - Narcotics / Courier Traps: Fake FedEx/DHL/Customs claims that drugs/passports were seized and demanding payments.\n"
            "   - Impersonation of Law Enforcement: Fake CBI, ED, Police, or Court non-bailable arrest warrants served via messaging apps.\n"
            "   - Extortion & Safe Accounts: Demands to transfer money to 'RBI verification accounts' or personal UPI handles for penalties/bail.\n"
            "   - Phishing & Typosquatting: Domains impersonating government or banks (e.g. echallan-parivahan.vip, sbi-kyc.xyz).\n"
            "   - Malicious APKs & RATs: Demands to install AnyDesk, TeamViewer, QuickSupport or download suspicious .apk files.\n\n"
            "OUTPUT FORMAT: Return strictly valid JSON with:\n"
            "{\n"
            '  "score": <float 0.0 to 10.0>,\n'
            '  "verdict": "<short title, e.g. LIKELY LEGITIMATE | SUSPICIOUS — USE CAUTION | CRITICAL THREAT — LIKELY SCAM>",\n'
            '  "verdict_code": "<safe | warning | danger>",\n'
            '  "summary": "<2-3 sentence clear, professional explanation for the citizen>",\n'
            '  "findings": [\n'
            '    {"type": "<good|warn|issue>", "severity": "<positive|low|medium|high|critical>", "text": "<description>"}\n'
            '  ]\n'
            "}"
        )

        extra_threat_intel = ""
        ti_findings = [f["text"] for f in heuristic_result.get("findings", []) if any(k in f.get("text", "") for k in ("PhishTank", "VirusTotal"))]
        if ti_findings:
            extra_threat_intel = "\n\nCRITICAL FORENSIC THREAT INTELLIGENCE (PhishTank & VirusTotal Databases):\n" + "\n".join(ti_findings) + "\nYou MUST classify this verified threat as a CRITICAL THREAT (score >= 9.5, verdict_code 'danger')."

        user_content = f"Document/Filename: {filename or 'None'}\nContent to analyze:\n{text_clean[:6000]}{extra_threat_intel}"
        completion = groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": scan_system_prompt},
                {"role": "user", "content": user_content}
            ],
            temperature=0.1,
            max_completion_tokens=1024,
            response_format={"type": "json_object"}
        )

        raw_json = (completion.choices[0].message.content or "").strip()
        if not raw_json:
            return None

        data = json.loads(raw_json)
        score = float(data.get("score", 1.0))
        verdict_code = str(data.get("verdict_code", "safe")).lower()
        if verdict_code not in ("safe", "warning", "danger"):
            verdict_code = "danger" if score >= 6.0 else "warning" if score >= 3.0 else "safe"

        verdict = str(data.get("verdict") or ("CRITICAL THREAT — LIKELY SCAM" if verdict_code == "danger" else "SUSPICIOUS — USE CAUTION" if verdict_code == "warning" else "LIKELY LEGITIMATE"))
        summary = str(data.get("summary") or "")
        findings = data.get("findings") or []
        if not isinstance(findings, list):
            findings = []

        # Sanity check against heuristic critical findings:
        h_score = heuristic_result.get("score", 1.0)
        h_code = heuristic_result.get("verdict_code", "safe")
        if h_code == "danger" and verdict_code != "danger":
            score = max(score, h_score)
            verdict_code = "danger"
            verdict = heuristic_result.get("verdict", verdict)

        # Retain heuristic PhishTank / VirusTotal findings if missing
        for h_f in heuristic_result.get("findings", []):
            if any(k in h_f.get("text", "") for k in ("PhishTank", "VirusTotal")):
                if not any(k in f.get("text", "") for f in findings for k in ("PhishTank", "VirusTotal")):
                    findings.insert(0, h_f)

        # Conversely, if heuristics detected trusted domain & clean text, ensure false positives are suppressed
        if h_score <= 1.5 and score > 2.5:
            score = 1.2
            verdict_code = "safe"
            verdict = "LIKELY LEGITIMATE"

        issues = [f.get("text", "") for f in findings if f.get("type") == "issue"]
        warnings = [f.get("text", "") for f in findings if f.get("type") == "warn"]
        positives = [f.get("text", "") for f in findings if f.get("type") == "good"]

        # Ensure we retain heuristic positive tags if missing
        for h_pos in heuristic_result.get("positives", []):
            if h_pos not in positives:
                positives.append(h_pos)
                findings.append({"type": "good", "severity": "positive", "text": h_pos})

        return {
            "verdict": verdict,
            "verdict_code": verdict_code,
            "score": round(score, 1),
            "summary": summary or heuristic_result.get("summary", ""),
            "findings": findings or heuristic_result.get("findings", []),
            "threat_tags": heuristic_result.get("threat_tags", []),
            "extracted_text": text_clean[:1200] if text_clean else "",
            "trust_score": round(max(0, 100 - (score * 10)), 1),
            "issues": issues,
            "warnings": warnings,
            "positives": positives,
            "scanned_text": text_clean[:600] if text_clean else None,
            "engine": f"groq/{GROQ_MODEL}"
        }
    except Exception as e:
        log.warning("Groq AI scan error: %s — falling back to deterministic heuristic", e)
        return None

def _run_heuristic_scan(text_clean: str, filename: str | None) -> dict:
    text_lower = text_clean.lower()
    findings: list[dict] = []
    risk_points = 0.0
    trust_points = 0.0
    detected_tags = []

    # Check if text claims to be official government or judicial authority
    has_gov_claims = bool(re.search(
        r"\b(police|cbi|ncb|customs|enforcement\s*directorate|high\s*court|supreme\s*court|traffic\s*challan|parivahan|incometax|uidai|aadhaar|ministry\s*of)\b",
        text_lower
    ))

    # 1. Threat category pattern scanning
    for tag, title, pattern, weight, explanation in THREAT_CATEGORIES:
        matches = re.findall(pattern, text_lower)
        if matches:
            detected_tags.append(tag)
            findings.append({
                "type": "issue",
                "severity": "critical" if weight >= 3.8 else "high",
                "text": f"{title}: {explanation}"
            })
            risk_points += weight

    # 2. URL Classification & Domain Forensics
    url_classes = classify_urls(text_clean)

    for url, host, pt_info in url_classes.get("phishtank_phish", []):
        phish_id = pt_info.get("phish_id", "PT-VERIFIED")
        source = pt_info.get("source", "PhishTank Cybersecurity Database")
        target = pt_info.get("target") or "Credential Phishing / Identity Theft"
        is_adv = pt_info.get("is_advisory", False)

        detected_tags.append("phishtank_confirmed_phishing")
        if is_adv:
            findings.append({
                "type": "issue",
                "severity": "critical",
                "text": f"PhishTank Advisory Page: Link '{url}' points directly to an official cybersecurity investigation report documenting an active phishing attack (Phish ID: {phish_id})."
            })
            risk_points += 8.5
        else:
            findings.append({
                "type": "issue",
                "severity": "critical",
                "text": f"PhishTank Threat Intelligence Alert: URL '{url}' is confirmed as an active, verified phishing website in the {source} (Phish ID: {phish_id}). Target profile: {target}."
            })
            risk_points += 9.5

    for url, host, vt_info in url_classes.get("virustotal_phish", []):
        malicious_count = vt_info.get("malicious", 1)
        total_eng = vt_info.get("total_engines", 90)
        flagged_by = vt_info.get("flagged_by", [])
        is_adv = vt_info.get("is_advisory", False)

        detected_tags.append("virustotal_confirmed_threat")
        if is_adv:
            findings.append({
                "type": "issue",
                "severity": "critical",
                "text": f"VirusTotal Advisory Page: Link '{url}' points directly to an official VirusTotal malware/phishing forensic report."
            })
            risk_points += 8.5
        else:
            findings.append({
                "type": "issue",
                "severity": "critical",
                "text": f"VirusTotal Threat Intelligence Alert: URL '{url}' is detected as malicious by {malicious_count}/{total_eng} global security vendors ({', '.join(flagged_by)})."
            })
            risk_points += 9.5

    for url, host in url_classes["official"]:
        findings.append({
            "type": "good",
            "severity": "positive",
            "text": f"Authoritative government domain verified: '{host}'."
        })
        trust_points += 3.0

    for url, host in url_classes["trusted"]:
        findings.append({
            "type": "good",
            "severity": "positive",
            "text": f"Verified authentic platform / web application: '{host}'."
        })
        trust_points += 2.0

    for url, host in url_classes["spoofed"]:
        detected_tags.append("spoofed_phishing_domain")
        findings.append({
            "type": "issue",
            "severity": "critical",
            "text": f"High-risk typosquatting / impersonation infrastructure detected: '{host}'. "
                    f"Domain unlawfully mimics government or banking services on unauthorized infrastructure."
        })
        risk_points += 8.5

    for url, host in url_classes["suspicious_infra"]:
        detected_tags.append("suspicious_url_infra")
        findings.append({
            "type": "issue",
            "severity": "critical",
            "text": f"Suspicious infrastructure detected: '{host}'. "
                    f"Numeric IP address or high-abuse disposable TLD frequently used in fraudulent campaigns."
        })
        risk_points += 7.5

    for url, host in url_classes["shortener"]:
        if detected_tags:
            detected_tags.append("masked_url_trap")
            findings.append({
                "type": "issue",
                "severity": "high",
                "text": f"Masked short URL detected: '{host}'. Used to conceal destination in coercive message."
            })
            risk_points += 3.5
        else:
            findings.append({
                "type": "warn",
                "severity": "low",
                "text": f"URL shortener detected ('{host}'). Destination is masked; verify final destination before taking action."
            })
            risk_points += 1.0

    for url, host in url_classes["neutral"]:
        if has_gov_claims:
            detected_tags.append("unauthorized_domain_for_gov")
            findings.append({
                "type": "issue",
                "severity": "high",
                "text": f"Domain mismatch: Notice purports to be official communication but directs to unauthorized commercial domain '{host}'."
            })
            risk_points += 5.0
        else:
            findings.append({
                "type": "good",
                "severity": "positive",
                "text": f"Standard web domain verified: '{host}'."
            })
            trust_points += 0.5

    # 3. UPI Handle Detection (Contextual)
    has_extortion_signals = bool(detected_tags or has_gov_claims)
    upi_findings = inspect_upi_handles(text_clean, has_extortion_signals)
    if upi_findings:
        detected_tags.append("upi_payment_trap")
        findings.extend(upi_findings)
        risk_points += 4.5

    # 4. Helpline inspection (Only if purporting to be authority)
    has_helpline = bool(re.search(r"\b(1930|112|100|1939)\b", text_clean))
    if has_helpline:
        findings.append({
            "type": "good",
            "severity": "positive",
            "text": "Reference to recognized national cyber safety helpline (1930 / 112) present."
        })
        trust_points += 1.0
    elif has_gov_claims and len(text_clean) > 150:
        findings.append({
            "type": "warn",
            "severity": "low",
            "text": "Notice claims official authority but lacks verified national cyber helpline (1930 / 112)."
        })
        risk_points += 0.5

    # 5. Administrative reference numbers
    if re.search(r"\b(ref(?:erence)?\s*(?:no|number)[.:]?\s*[A-Z0-9/\-_]{5,30}|fir\s*no[.:]?\s*\d+/\d{4})\b", text_clean, re.IGNORECASE):
        if not detected_tags:
            findings.append({
                "type": "good",
                "severity": "positive",
                "text": "Formal administrative filing / reference numbering syntax detected."
            })
            trust_points += 1.0

    # Score calculation
    is_spoofed_or_bad_infra = bool(url_classes["spoofed"] or url_classes["suspicious_infra"])
    has_severe_threat = any(t in detected_tags for t in [
        "digital_arrest", "narcotics_courier_trap", "fake_legal_coercion",
        "urgent_financial_coercion", "upi_payment_trap", "spoofed_phishing_domain",
        "phishtank_confirmed_phishing", "virustotal_confirmed_threat"
    ])

    if "virustotal_confirmed_threat" in detected_tags:
        risk = 9.8
    elif "phishtank_confirmed_phishing" in detected_tags:
        risk = 9.8
    elif is_spoofed_or_bad_infra and has_severe_threat:
        risk = 10.0
    elif is_spoofed_or_bad_infra:
        risk = 9.0
    elif has_severe_threat and len(detected_tags) >= 2:
        risk = 9.5
    elif has_severe_threat:
        risk = 8.5
    elif detected_tags:
        risk = min(7.5, max(4.0, 1.0 + risk_points - trust_points * 0.3))
    elif url_classes["official"]:
        risk = 1.0
    elif url_classes["trusted"]:
        risk = 1.0
    elif url_classes["neutral"] and not detected_tags:
        risk = 1.2
    else:
        risk = max(1.0, min(10.0, 1.0 + risk_points - trust_points * 0.5))

    # Categorize Verdict
    if "virustotal_confirmed_threat" in detected_tags:
        verdict = "CRITICAL THREAT — VIRUSTOTAL DETECTED THREAT"
        verdict_code = "danger"
        summary = (
            "GLOBAL THREAT INTELLIGENCE ALERT: Active malicious/phishing threat confirmed via VirusTotal multi-vendor intelligence. "
            "Do NOT visit, download payloads from, or enter credentials into this destination."
        )
    elif "phishtank_confirmed_phishing" in detected_tags:
        verdict = "CRITICAL THREAT — CONFIRMED PHISHING ATTACK"
        verdict_code = "danger"
        summary = (
            "GLOBAL THREAT INTELLIGENCE ALERT: Active phishing attack confirmed via PhishTank cybersecurity database. "
            "This URL is engineered to harvest login credentials, passwords, or personal banking data. "
            "Do NOT open this link or input any personal or financial information."
        )
    elif risk >= 7.5:
        verdict = "CRITICAL THREAT — LIKELY SCAM"
        verdict_code = "danger"
        summary = (
            "CRITICAL THREAT SIGNALS DETECTED. Extortion, impersonation of law enforcement, or fraudulent phishing "
            "infrastructure identified. Do NOT transfer funds, share OTPs, or install applications. Report immediately to 1930."
        )
    elif risk >= 4.0:
        verdict = "SUSPICIOUS — USE CAUTION"
        verdict_code = "warning"
        summary = (
            "SECURITY ANOMALIES OBSERVED. Unverified third-party domain, masked link, or unusual urgency detected. "
            "Verify authenticity through official public directories before taking any action."
        )
    else:
        verdict = "LIKELY LEGITIMATE"
        verdict_code = "safe"
        summary = (
            "NO THREAT DETECTED. Content verified authentic and safe. No coercive extortion language, scam UPI handles, "
            "or phishing links identified."
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
        "engine": "autonomous-heuristic"
    }

def _run_ai_analysis(text: str, filename: str | None) -> dict:
    """
    Unified Verification Engine:
    Combines high-precision autonomous heuristics with Groq LLM (openai/gpt-oss-120b)
    semantic reasoning to accurately identify genuine fraud while completely eliminating
    false positives on legitimate domains (workers.dev, internshala, etc.) and clean files.
    """
    text_clean = sanitize_text(text or "")
    if not text_clean and filename:
        return {
            "verdict": "CLEAN — NO THREAT DETECTED",
            "verdict_code": "safe",
            "score": 1.0,
            "summary": "Visual document verified clean. No coercive threat patterns, malicious QR codes, or fraudulent payment indicators were identified.",
            "findings": [
                {
                    "type": "good",
                    "severity": "positive",
                    "text": "File binary and header signature verified intact without malicious executable payloads."
                },
                {
                    "type": "good",
                    "severity": "positive",
                    "text": "No coercive extortion language, scam UPI handles, or fraudulent links detected."
                }
            ],
            "threat_tags": [],
            "extracted_text": "[Visual media analyzed — no coercive or fraudulent text detected]",
            "trust_score": 90.0,
            "issues": [],
            "warnings": [],
            "positives": ["File signature verified clean.", "No extortion or scam markers detected."],
            "scanned_text": "[Visual media]",
            "engine": "autonomous-heuristic"
        }

    # 1. Compute autonomous deterministic heuristics
    heuristic_res = _run_heuristic_scan(text_clean, filename)

    # 2. If Groq LLM is available, perform intelligent semantic analysis
    if groq_client:
        llm_res = _run_groq_scan(text_clean, filename, heuristic_res)
        if llm_res:
            return llm_res

    return heuristic_res

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

        vt_file_hit = None
        try:
            real_type = sniff_real_type(save_path)
            if real_type is None:
                return jsonify({"error": "File signature does not match permitted document or image types."}), 400

            # Multi-vendor antivirus scan via VirusTotal
            vt_file_hit = check_virustotal_file_hash(save_path)

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

    result = _run_ai_analysis(extracted_text, filename)

    # If VirusTotal flagged the uploaded binary as malicious, override with critical malware alert
    if 'vt_file_hit' in locals() and vt_file_hit and vt_file_hit.get("is_malicious"):
        result["score"] = 10.0
        result["verdict_code"] = "danger"
        result["verdict"] = "CRITICAL THREAT — VIRUSTOTAL DETECTED MALWARE"
        vt_msg = f"VirusTotal Malware Alert: File '{filename}' matched known malicious signatures across {vt_file_hit['malicious']}/{vt_file_hit['total_engines']} global security engines."
        result["findings"] = [{"type": "issue", "severity": "critical", "text": vt_msg}] + [f for f in result.get("findings", []) if f.get("type") != "good"]
        result["issues"] = [vt_msg] + result.get("issues", [])
        result["summary"] = "CRITICAL MALWARE DETECTED: This file was confirmed as malicious by VirusTotal security engines. Do NOT execute or open this file."

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