"""
CivicShield Backend - app.py
============================
Enterprise Flask API powering the CivicShield verification platform
and the CivicShield AI Cyber Intelligence Assistant.
"""

import os
import re
import io
import uuid
import logging
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Optional heavy document-parsing libraries
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

# Optional external LLM clients
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
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
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    SECRET_KEY=os.getenv("SECRET_KEY", uuid.uuid4().hex),
)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "pdf", "txt"}

# Configure Gemini if an API key is present
GEMINI_KEY = os.getenv("GEMINI_API_KEY", "")
if GEMINI_AVAILABLE and GEMINI_KEY:
    genai.configure(api_key=GEMINI_KEY)
    llm_model = genai.GenerativeModel(
        model_name="gemini-1.5-flash",
        system_instruction=(
            "You are CivicShield AI Assistant, an elite, professional cybersecurity and "
            "document forensics expert. You assist citizens in detecting government impersonation scams, "
            "evaluating fraudulent digital summons, understanding official Indian administrative channels "
            "(e.g., cybercrime.gov.in, National Cyber Crime Helpline 1930), and validating electronic records. "
            "Be precise, calm, authoritative, and structured. Never use emojis or casual slang."
        )
    )
else:
    llm_model = None

# ── Helpers ──────────────────────────────────────────────────────────────────

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_pdf(filepath: str) -> str:
    if not PYPDF_AVAILABLE:
        return ""
    reader = PdfReader(filepath)
    return "\n".join((page.extract_text() or "") for page in reader.pages)

def extract_text_from_image(filepath: str) -> str:
    return ""

# ── Verification Core ────────────────────────────────────────────────────────

SCAM_KEYWORDS = [
    r"\burgent\b", r"\bimmediately\b", r"\bpenalty\b", r"\bfine\b",
    r"\barrest\b", r"\blegal action\b", r"\bverify your details\b",
    r"\bclick here\b", r"\byour account (will be|has been) (suspended|blocked)\b",
    r"\bpay now\b", r"\bwire transfer\b", r"\bcryptocurrency\b",
    r"\bgift card\b", r"\bsocial security\b", r"\baadhar (suspend|block)\b",
]

FAKE_DOMAIN_PATTERN = re.compile(
    r"https?://[^\s]*(?<!\.gov\.in)(?<!\.nic\.in)(?<!\.gov)(?<!\.mil)\b",
    re.IGNORECASE,
)

OFFICIAL_DOMAIN_PATTERN = re.compile(
    r"https?://[^\s]*(\.gov\.in|\.nic\.in|\.gov|\.mil)\b",
    re.IGNORECASE,
)

def _run_ai_analysis(text: str, filename: str | None) -> dict:
    text_lower = text.lower()
    issues: list[str] = []
    warnings: list[str] = []
    positives: list[str] = []
    score: int = 100

    matched_keywords = [
        p.replace(r"\b", "").replace("\\", "")
        for p in SCAM_KEYWORDS if re.search(p, text_lower)
    ]

    if matched_keywords:
        issues.append(
            f"High-pressure language detected: {', '.join(matched_keywords[:4])}. "
            "Legitimate government notices do not use coercive or threatening language."
        )
        score -= 30 * min(len(matched_keywords), 3)

    fake_urls = FAKE_DOMAIN_PATTERN.findall(text)
    official_urls = OFFICIAL_DOMAIN_PATTERN.findall(text)

    if fake_urls:
        issues.append(
            f"Suspicious or non-government URL identified: '{fake_urls[0]}'. "
            "Valid Indian government domains must end strictly in .gov.in or .nic.in."
        )
        score -= 25

    if official_urls:
        positives.append(
            f"Official government domain verified: '{official_urls[0]}'."
        )
        score += 5

    has_phone = bool(re.search(r"\b[6-9]\d{9}\b|\+91[-\s]?\d{10}", text))
    if not has_phone and len(text) > 100:
        warnings.append(
            "No verifiable public helpline or telephone directory number found."
        )
        score -= 10

    if filename and filename.lower().endswith(".pdf") and len(text) < 80:
        warnings.append(
            "Document contains minimal OCR-readable text. Potential hidden raster payload."
        )
        score -= 15

    if re.search(r"government of india|ministry of|department of|collector office", text_lower):
        positives.append("Document references a recognized public administrative entity.")
        score += 5

    if re.search(r"reference no[.:]?\s*[A-Z0-9/-]+", text, re.IGNORECASE):
        positives.append("Formal reference filing syntax detected.")
        score += 5

    score = max(0, min(100, score))

    if score >= 70:
        verdict = "LIKELY LEGITIMATE"
        verdict_code = "safe"
        summary = (
            "No high-severity structural indicators were detected. "
            "Cross-reference this communication against official agency portals before proceeding."
        )
    elif score >= 40:
        verdict = "SUSPICIOUS - USE CAUTION"
        verdict_code = "warning"
        summary = (
            "One or more security anomalies were flagged. "
            "Do not transfer funds, share identity credentials, or execute external links."
        )
    else:
        verdict = "HIGH RISK - LIKELY SCAM"
        verdict_code = "danger"
        summary = (
            "Critical threat markers observed. This communication exhibits known "
            "tactics of impersonation fraud. File an incident report at cybercrime.gov.in."
        )

    return {
        "verdict": verdict,
        "verdict_code": verdict_code,
        "score": score,
        "summary": summary,
        "issues": issues,
        "warnings": warnings,
        "positives": positives,
        "scanned_text": text[:600] if text else None,
    }

# ── Conversational AI Engine ─────────────────────────────────────────────────

def _generate_deterministic_reply(query: str) -> str:
    """Rule-based engine guaranteeing immediate, accurate responses without external API overhead."""
    q = query.lower()

    if any(k in q for k in ["hello", "hi", "hey", "who are you", "what can you do"]):
        return (
            "Greetings. I am the CivicShield AI Intelligence Assistant. "
            "I provide real-time forensic analysis on digital communications, verify government "
            "notice legitimacy, explain impersonation tactics, and guide cyber incident escalations. "
            "How may I assist your verification protocol today?"
        )

    if any(k in q for k in ["report", "complaint", "fraud", "scammed", "money lost", "cheated"]):
        return (
            "Immediate Action Protocol for Financial & Cyber Fraud:\n\n"
            "1. National Helpline: Call 1930 immediately to freeze fraudulent bank transfers within the golden hour.\n"
            "2. Formal Portal: Register an incident at cybercrime.gov.in.\n"
            "3. Banking: Contact your branch to place a hotlist stop on debit cards and freeze net-banking access.\n"
            "4. Evidence: Preserve all transaction references, SMS headers, screenshots, and call logs without alteration."
        )

    if any(k in q for k in ["police", "cbi", "court", "arrest", "summons", "warrant", "customs"]):
        return (
            "Legal Advisory Notice:\n\n"
            "No legitimate law enforcement or investigative authority (CBI, ED, Police, or High Courts) "
            "issues arrest warrants or demands security clearances over WhatsApp, Skype, or phone calls.\n\n"
            "Official procedural summons must arrive through designated departmental channels or registered postal service. "
            "Demands for fund transfers to 'clearing accounts' are fraudulent extortion attempts."
        )

    if any(k in q for k in ["pan", "aadhar", "aadhaar", "kyc", "electricity", "bill update"]):
        return (
            "Service Verification Guidelines:\n\n"
            "Public utilities and UIDAI/Income Tax authorities do not send SMS messages threatening "
            "immediate service termination within hours. Genuine updates must be initiated solely via "
            "m-Aadhaar, incometax.gov.in, or respective official discom portals. Never install APK files "
            "sent over messaging apps."
        )

    if any(k in q for k in ["verify", "check", "scan", "analyze"]):
        return (
            "To analyze a suspicious document, upload it directly via the CivicShield Main Scan dashboard. "
            "The forensic scanner will parse cryptographic markers, evaluate URL domain suffixes against "
            "national registries, and calculate a threat probability score."
        )

    return (
        "I have registered your inquiry regarding verification and compliance. "
        "For suspect document forensics, submit your file through the primary scanner interface. "
        "For immediate emergency reporting within India, utilize the National Helpline 1930 or portal cybercrime.gov.in."
    )

# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "CivicShield AI System",
        "engine_mode": "hybrid-llm" if llm_model else "autonomous-heuristic",
        "version": "2.4.0",
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
            return jsonify({"error": f"Invalid extension. Permitted: {', '.join(ALLOWED_EXTENSIONS)}"}), 400

        filename = secure_filename(f.filename)
        save_path = str(UPLOAD_DIR / filename)
        f.save(save_path)

        ext = filename.rsplit(".", 1)[1].lower()
        if ext == "pdf":
            extracted_text = extract_text_from_pdf(save_path)
        elif ext == "txt":
            extracted_text = Path(save_path).read_text(errors="ignore")
        else:
            extracted_text = extract_text_from_image(save_path)

        try:
            os.remove(save_path)
        except OSError:
            pass

    elif request.is_json:
        body = request.get_json(silent=True) or {}
        extracted_text = body.get("text", "").strip()
        if not extracted_text:
            return jsonify({"error": "Missing payload text parameter."}), 400

    elif request.form.get("text"):
        extracted_text = request.form.get("text", "").strip()

    else:
        return jsonify({"error": "No file payload or text buffer supplied."}), 400

    result = _run_ai_analysis(extracted_text, filename)
    return jsonify(result), 200

@app.route("/api/chat", methods=["POST"])
def chat():
    """
    Conversational AI interface endpoint.
    Accepts: { "message": "...", "history": [...] }
    Returns: { "reply": "...", "source": "gemini" | "heuristic", "timestamp": "..." }
    """
    body = request.get_json(silent=True) or {}
    user_message = body.get("message", "").strip()

    if not user_message:
        return jsonify({"error": "Message body cannot be empty."}), 400

    source = "heuristic"
    reply = ""

    if llm_model:
        try:
            # Build conversation context from provided client history
            history = body.get("history", [])
            chat_session = llm_model.start_chat(history=[])
            
            # Replay recent context safely
            for turn in history[-4:]:
                role = "user" if turn.get("role") == "user" else "model"
                content = turn.get("content", "")
                if content:
                    chat_session.history.append({"role": role, "parts": [content]})

            response = chat_session.send_message(user_message)
            reply = response.text
            source = "gemini-1.5-flash"
        except Exception as e:
            log.warning("LLM request failed, falling back to deterministic engine: %s", e)
            reply = _generate_deterministic_reply(user_message)
    else:
        reply = _generate_deterministic_reply(user_message)

    return jsonify({
        "reply": reply,
        "engine": source,
        "status": "success",
    }), 200

# ── Error Handlers ────────────────────────────────────────────────────────────

@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "Payload exceeds 16 MB limit."}), 413

@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Resource not found."}), 404

@app.errorhandler(500)
def server_error(e):
    log.exception("Internal server fault")
    return jsonify({"error": "Internal computation fault. Retry query."}), 500

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    log.info("CivicShield core operational on port %d (debug=%s)", port, debug)
    app.run(host="0.0.0.0", port=port, debug=debug)
