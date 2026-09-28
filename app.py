"""
CivicShield Backend - app.py
============================
Enterprise Flask API powering the CivicShield verification platform
and the CivicShield AI Cyber Intelligence Assistant.

LLM Engine: Groq — openai/gpt-oss-120b
  • 131K context window
  • Reasoning effort: low / medium / high
  • OpenAI-compatible chat completions API
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
    from PIL import Image
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

try:
    import pytesseract
    PYTESSERACT_AVAILABLE = True
except ImportError:
    PYTESSERACT_AVAILABLE = False

# ── Groq LLM client (replaces Gemini) ────────────────────────────────────────
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
CORS(app, resources={r"/api/*": {"origins": "*"}})

app.config.update(
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,  # 5 MB — matches frontend limit
    SECRET_KEY=os.getenv("SECRET_KEY", uuid.uuid4().hex),
)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "pdf", "txt"}

# Optional rate limiter
if LIMITER_AVAILABLE:
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["240 per hour"],
        storage_uri=os.getenv("RATE_LIMIT_STORAGE", "memory://"),
        headers_enabled=True,
    )
else:
    limiter = None
    log.warning("Flask-Limiter not installed — running without rate limits.")

# ═══════════════════════════════════════════════════════════════════════════
# GROQ LLM CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL   = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
GROQ_REASONING_EFFORT = os.getenv("GROQ_REASONING_EFFORT", "medium")  # low | medium | high
GROQ_MAX_TOKENS = int(os.getenv("GROQ_MAX_TOKENS", "2048"))
GROQ_TEMPERATURE = float(os.getenv("GROQ_TEMPERATURE", "0.4"))

# System instruction — CivicShield persona for the OSS-120B model
SYSTEM_PROMPT = (
    "You are CivicShield AI Assistant, an elite, professional cybersecurity and "
    "document forensics expert. You assist citizens in detecting government impersonation scams, "
    "evaluating fraudulent digital summons, understanding official Indian administrative channels "
    "(e.g., cybercrime.gov.in, National Cyber Crime Helpline 1930), and validating electronic records.\n\n"
    "Be precise, calm, authoritative, and structured. Never use emojis or casual slang. "
    "When the user asks about a suspicious message, structure your response with clear headings: "
    "verdict, key signals, and recommended next steps."
)

groq_client = None
if GROQ_AVAILABLE and GROQ_API_KEY:
    try:
        groq_client = Groq(api_key=GROQ_API_KEY)
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
# REQUEST TRACING
# ═══════════════════════════════════════════════════════════════════════════

@app.before_request
def _start_timer():
    g._t0 = time.perf_counter()
    g.request_id = uuid.uuid4().hex[:8]

@app.after_request
def _log_request(resp):
    dur = (time.perf_counter() - getattr(g, "_t0", time.perf_counter())) * 1000
    log.info("[%s] %s %s -> %s (%.1fms)",
             getattr(g, "request_id", "-"),
             request.method, request.path, resp.status_code, dur)
    resp.headers["X-Request-ID"] = getattr(g, "request_id", "-")
    return resp

# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def sniff_real_type(path: str) -> str | None:
    """Detect actual file type from magic bytes, ignoring extension."""
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
        return "\n".join((page.extract_text() or "") for page in reader.pages).strip()
    except Exception as e:
        log.warning("PDF parse failed: %s", e)
        return ""

def extract_text_from_image(filepath: str) -> str:
    if not (PILLOW_AVAILABLE and PYTESSERACT_AVAILABLE):
        return ""
    try:
        img = Image.open(filepath)
        if img.mode != "RGB":
            img = img.convert("RGB")
        tess_path = os.getenv("TESSERACT_CMD")
        if tess_path:
            pytesseract.pytesseract.tesseract_cmd = tess_path
        return pytesseract.image_to_string(img, lang="eng").strip()
    except Exception as e:
        log.warning("OCR failed for %s: %s", filepath, e)
        return ""

# ═══════════════════════════════════════════════════════════════════════════
# VERIFICATION CORE (unchanged — heuristic engine, no LLM needed)
# ═══════════════════════════════════════════════════════════════════════════

SCAM_KEYWORDS = [
    ("urgent demand",             r"\burgent\b"),
    ("immediate action required", r"\bimmediately\b"),
    ("penalty/fine",              r"\b(penalty|fine)\b"),
    ("threat of arrest",          r"\barrest\b"),
    ("legal action threat",       r"\blegal action\b"),
    ("KYC verification bait",     r"\bverify your details\b"),
    ("click-here lure",           r"\bclick here\b"),
    ("account suspension threat", r"\b(account|aadhaar|aadhar|pan)\b.{0,20}\b(suspended|blocked)\b"),
    ("payment pressure",          r"\b(pay now|wire transfer|upi transfer)\b"),
    ("crypto bait",               r"\bcryptocurrency\b"),
    ("gift card bait",            r"\bgift card\b"),
    ("impersonation hook",        r"\b(gov of india|government of india)\b"),
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
OFFICIAL_SUFFIXES = (".gov.in", ".nic.in", ".gov", ".mil")
OFFICIAL_EXACT = {"gov.in", "nic.in"}

def classify_urls(text: str) -> tuple[list[str], list[str]]:
    official, fake = [], []
    for url in URL_PATTERN.findall(text):
        try:
            host = (urlparse(url).hostname or "").lower().strip(".")
        except Exception:
            continue
        if not host:
            continue
        is_official = host in OFFICIAL_EXACT or host.endswith(OFFICIAL_SUFFIXES)
        (official if is_official else fake).append(url)
    return official, fake

def _run_ai_analysis(text: str, filename: str | None) -> dict:
    """Heuristic engine — returns score 0-10 (higher = worse) + findings."""
    text_lower = (text or "").lower()
    findings: list[dict] = []
    risk_points = 0
    trust_points = 0

    matched_labels = [label for label, pat in SCAM_KEYWORDS if re.search(pat, text_lower)]
    if matched_labels:
        findings.append({
            "type": "issue",
            "text": f"High-pressure language detected ({', '.join(matched_labels[:4])}). "
                    "Genuine government notices avoid coercive or threatening language."
        })
        risk_points += 3 * min(len(matched_labels), 3)

    official_urls, fake_urls = classify_urls(text)
    if fake_urls:
        findings.append({
            "type": "issue",
            "text": f"Suspicious or non-government URL identified: '{fake_urls[0]}'. "
                    "Valid Indian government domains must end in .gov.in or .nic.in."
        })
        risk_points += 3
    if official_urls:
        findings.append({
            "type": "good",
            "text": f"Official government domain verified: '{official_urls[0]}'."
        })
        trust_points += 1

    has_phone = bool(re.search(r"\b[6-9]\d{9}\b|\+91[-\s]?\d{10}", text))
    if not has_phone and len(text) > 120:
        findings.append({
            "type": "warn",
            "text": "No verifiable public helpline or telephone number found."
        })
        risk_points += 1

    if filename and filename.lower().endswith(".pdf") and len(text) < 80:
        findings.append({
            "type": "warn",
            "text": "Document contains minimal OCR-readable text. Potential hidden raster payload."
        })
        risk_points += 1.5

    if re.search(r"government of india|ministry of|department of|collector office", text_lower):
        findings.append({
            "type": "good",
            "text": "Document references a recognized public administrative entity."
        })
        trust_points += 1

    if re.search(r"reference no[.:]?\s*[A-Z0-9/-]+", text, re.IGNORECASE):
        findings.append({
            "type": "good",
            "text": "Formal reference filing syntax detected."
        })
        trust_points += 1

    risk = max(0.0, min(10.0, risk_points - (trust_points * 0.5)))

    if risk >= 6.0:
        verdict = "HIGH RISK — LIKELY SCAM"
        verdict_code = "danger"
        summary = ("Critical threat markers observed. This communication exhibits known "
                   "tactics of impersonation fraud. File an incident report at cybercrime.gov.in.")
    elif risk >= 3.0:
        verdict = "SUSPICIOUS — USE CAUTION"
        verdict_code = "warning"
        summary = ("One or more security anomalies were flagged. Do not transfer funds, share "
                   "identity credentials, or execute external links until independently verified.")
    else:
        verdict = "LIKELY LEGITIMATE"
        verdict_code = "safe"
        summary = ("No high-severity structural indicators were detected. Cross-reference this "
                   "communication against official agency portals before proceeding.")

    issues    = [f["text"] for f in findings if f["type"] == "issue"]
    warnings  = [f["text"] for f in findings if f["type"] == "warn"]
    positives = [f["text"] for f in findings if f["type"] == "good"]

    return {
        "verdict": verdict,
        "verdict_code": verdict_code,
        "score": round(risk, 1),
        "summary": summary,
        "findings": findings,
        "extracted_text": text[:800] if text else "",
        "trust_score": round(max(0, 100 - (risk * 10)), 1),
        "issues": issues,
        "warnings": warnings,
        "positives": positives,
        "scanned_text": text[:600] if text else None,
    }

# ═══════════════════════════════════════════════════════════════════════════
# DETERMINISTIC FALLBACK (used when Groq is unreachable)
# ═══════════════════════════════════════════════════════════════════════════

def _generate_deterministic_reply(query: str) -> str:
    q = (query or "").lower()

    if any(k in q for k in ["hello", "hi ", "hey", "who are you", "what can you do"]):
        return ("Greetings. I am the CivicShield AI Intelligence Assistant. "
                "I provide real-time forensic analysis on digital communications, verify government "
                "notice legitimacy, explain impersonation tactics, and guide cyber incident escalations. "
                "How may I assist your verification protocol today?")

    if any(k in q for k in ["report", "complaint", "fraud", "scammed", "money lost", "cheated", "1930"]):
        return ("Immediate Action Protocol for Financial & Cyber Fraud:\n\n"
                "1. National Helpline: Call 1930 immediately to freeze fraudulent bank transfers.\n"
                "2. Formal Portal: Register an incident at cybercrime.gov.in.\n"
                "3. Banking: Contact your branch to place a hotlist stop on debit cards.\n"
                "4. Evidence: Preserve all transaction references, SMS headers, screenshots, and call logs.")

    if any(k in q for k in ["police", "cbi", "court", "arrest", "summons", "warrant", "customs", "ed "]):
        return ("Legal Advisory Notice:\n\n"
                "No legitimate law enforcement or investigative authority (CBI, ED, Police, or High Courts) "
                "issues arrest warrants or demands security clearances over WhatsApp, Skype, or phone calls.\n\n"
                "Official procedural summons must arrive through designated departmental channels or registered post. "
                "Demands for fund transfers to 'clearing accounts' are fraudulent extortion attempts.")

    if any(k in q for k in ["pan", "aadhar", "aadhaar", "kyc", "electricity", "bill update", "discom"]):
        return ("Service Verification Guidelines:\n\n"
                "Public utilities and UIDAI/Income Tax authorities do not send SMS messages threatening "
                "immediate service termination within hours. Genuine updates must be initiated solely via "
                "m-Aadhaar, incometax.gov.in, or respective official discom portals. Never install APK files "
                "sent over messaging apps.")

    if any(k in q for k in ["upi", "paytm", "phonepe", "gpay", "collect request", "qr"]):
        return ("UPI Fraud Prevention Protocol:\n\n"
                "You NEVER enter a UPI PIN to receive money — only to send it. "
                "Never approve a collect request you didn't create. QR codes are for paying, not receiving.\n\n"
                "If money was already debited: call 1930 within the golden hour and inform your bank "
                "to freeze the beneficiary account.")

    if any(k in q for k in ["verify", "check", "scan", "analyze", "gov.in", "domain"]):
        return ("To analyze a suspicious document, upload it via the CivicShield Main Scan dashboard. "
                "The forensic scanner parses cryptographic markers, evaluates URL domain suffixes against "
                "national registries, and calculates a risk probability score.\n\n"
                "For URL verification: only .gov.in and .nic.in are authoritative. Anything else — "
                "including lookalikes like 'gov-in.co' or 'incometax-verify-india.com' — is suspect.")

    return ("I have registered your inquiry regarding verification and compliance. "
            "For suspect document forensics, submit your file through the primary scanner interface. "
            "For immediate emergency reporting within India, utilize the National Helpline 1930 "
            "or portal cybercrime.gov.in.")

# ═══════════════════════════════════════════════════════════════════════════
# GROQ CHAT HELPER
# ═══════════════════════════════════════════════════════════════════════════

def _call_groq(messages: list[dict]) -> tuple[str, str]:
    """
    Call Groq's chat completions API.
    Returns (reply_text, engine_name).
    Raises on failure so the caller can fall back.
    """
    if not groq_client:
        raise RuntimeError("Groq client not initialised")

    # Reasoning effort only supported by gpt-oss models — safe to always send
    completion = groq_client.chat.completions.create(
        model=GROQ_MODEL,
        messages=messages,
        temperature=GROQ_TEMPERATURE,
        max_completion_tokens=GROQ_MAX_TOKENS,
        reasoning_effort=GROQ_REASONING_EFFORT,   # low | medium | high
        stream=False,
    )

    choice = completion.choices[0]
    reply = (choice.message.content or "").strip()

    # Defensive: some reasoning models return empty content when thinking
    if not reply:
        # Try the reasoning field if present
        reasoning = getattr(choice.message, "reasoning", None)
        if reasoning:
            reply = f"Reasoning: {reasoning}\n\n(No direct answer returned — try rephrasing.)"
        else:
            reply = ""

    return reply, f"groq/{GROQ_MODEL}"

# ═══════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "CivicShield AI System",
        "llm_engine": f"groq/{GROQ_MODEL}" if groq_client else "autonomous-heuristic",
        "llm_configured": bool(groq_client),
        "reasoning_effort": GROQ_REASONING_EFFORT,
        "capabilities": {
            "ocr": PYTESSERACT_AVAILABLE and PILLOW_AVAILABLE,
            "pdf": PYPDF_AVAILABLE,
            "llm": bool(groq_client),
            "rate_limiting": LIMITER_AVAILABLE,
        },
        "version": "4.0.0",
    })

@app.route("/api/scan", methods=["POST"])
def scan():
    extracted_text = ""
    filename = None

    if "file" in request.files:
        f = request.files["file"]
        if f.filename == "":
            return jsonify({"error": "No file selected."}), 400

        if not allowed_file(f.filename):
            return jsonify({"error": f"Invalid extension. Permitted: {', '.join(sorted(ALLOWED_EXTENSIONS))}"}), 400

        filename = secure_filename(f.filename)
        save_path = str(UPLOAD_DIR / f"{uuid.uuid4().hex}_{filename}")
        f.save(save_path)

        try:
            real_type = sniff_real_type(save_path)
            if real_type is None:
                return jsonify({"error": "File content does not match a permitted format."}), 400

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
        extracted_text = (body.get("text") or "").strip()
        if not extracted_text:
            return jsonify({"error": "Missing payload text parameter."}), 400

    elif request.form.get("text"):
        extracted_text = request.form.get("text", "").strip()

    else:
        return jsonify({"error": "No file payload or text buffer supplied."}), 400

    if not extracted_text and filename:
        return jsonify({
            "error": "Unable to extract text from this file. "
                     "If it is an image, ensure OCR dependencies (pytesseract + Pillow) are installed."
        }), 422

    result = _run_ai_analysis(extracted_text, filename)
    return jsonify(result), 200

if limiter:
    scan = limiter.limit("30 per hour")(scan)

@app.route("/api/chat", methods=["POST"])
def chat():
    """
    Conversational AI endpoint powered by Groq (openai/gpt-oss-120b).

    Accepts: { "message": "...", "history": [{role, content}, ...] }
    Returns: { "reply": "...", "engine": "groq/openai/gpt-oss-120b" | "heuristic" }
    """
    body = request.get_json(silent=True) or {}
    user_message = (body.get("message") or "").strip()

    if not user_message:
        return jsonify({"error": "Message body cannot be empty."}), 400

    source = "heuristic"
    reply = ""

    if groq_client:
        try:
            # Build Groq message array — system first, then conversation history,
            # then the new user message. This is the OpenAI-compatible format.
            history = body.get("history") or []
            messages = [{"role": "system", "content": SYSTEM_PROMPT}]

            for turn in history[-6:]:
                role = turn.get("role")
                content = (turn.get("content") or "").strip()
                # Groq expects 'user' or 'assistant' (not 'model')
                if role == "model":
                    role = "assistant"
                if role in ("user", "assistant") and content:
                    messages.append({"role": role, "content": content})

            messages.append({"role": "user", "content": user_message})

            reply, source = _call_groq(messages)

            if not reply:
                reply = _generate_deterministic_reply(user_message)
                source = "heuristic"

        except AuthenticationError as e:
            log.error("[%s] Groq auth failed — check GROQ_API_KEY: %s",
                      getattr(g, "request_id", "-"), e)
            reply = _generate_deterministic_reply(user_message)
            source = "heuristic (auth-error)"

        except RateLimitError as e:
            log.warning("[%s] Groq rate limit hit: %s", getattr(g, "request_id", "-"), e)
            reply = _generate_deterministic_reply(user_message)
            source = "heuristic (rate-limit)"

        except APIConnectionError as e:
            log.warning("[%s] Groq connection failed: %s", getattr(g, "request_id", "-"), e)
            reply = _generate_deterministic_reply(user_message)
            source = "heuristic (connection)"

        except GroqError as e:
            log.warning("[%s] Groq API error: %s", getattr(g, "request_id", "-"), e)
            reply = _generate_deterministic_reply(user_message)
            source = "heuristic (api-error)"

        except Exception as e:
            log.exception("[%s] Unexpected LLM failure: %s", getattr(g, "request_id", "-"), e)
            reply = _generate_deterministic_reply(user_message)
            source = "heuristic (unexpected)"

    else:
        reply = _generate_deterministic_reply(user_message)

    return jsonify({
        "reply": reply,
        "engine": source,
        "status": "success",
    }), 200

if limiter:
    chat = limiter.limit("60 per hour")(chat)

# ═══════════════════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════════════

@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "Payload exceeds 16 MB limit."}), 413

@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Resource not found."}), 404

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Rate limit exceeded. Please slow down.",
                    "detail": str(e.description) if hasattr(e, "description") else ""}), 429

@app.errorhandler(500)
def server_error(e):
    log.exception("Internal server fault")
    return jsonify({"error": "Internal computation fault. Retry query."}), 500

# ═══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"

    log.info("=" * 60)
    log.info("CivicShield core v4.0.0 operational on port %d (debug=%s)", port, debug)
    log.info("  LLM engine ... %s", f"groq/{GROQ_MODEL}" if groq_client else "heuristic-only")
    log.info("  Reasoning .... %s", GROQ_REASONING_EFFORT)
    log.info("  OCR .......... %s", "ENABLED" if (PYTESSERACT_AVAILABLE and PILLOW_AVAILABLE) else "disabled")
    log.info("  PDF parsing .. %s", "ENABLED" if PYPDF_AVAILABLE else "disabled")
    log.info("  Rate limit ... %s", "ENABLED" if LIMITER_AVAILABLE else "disabled")
    log.info("=" * 60)

    app.run(host="0.0.0.0", port=port, debug=debug)
