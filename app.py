"""
CivicShield Backend - app.py
============================
A Flask API that powers the CivicShield AI document-verification platform.
Currently runs mock AI analysis; replace the `_run_ai_analysis` function with
your real Groq / OpenAI / Gemini call when ready.
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

# ── Optional heavy libs (graceful fallback if not installed) ─────────────────
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

# ── Bootstrap ────────────────────────────────────────────────────────────────
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── App setup ────────────────────────────────────────────────────────────────
BASE_DIR  = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__, static_folder=str(STATIC_DIR))
CORS(app, resources={r"/api/*": {"origins": "*"}})

app.config.update(
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024,   # 16 MB upload limit
    SECRET_KEY          = os.getenv("SECRET_KEY", uuid.uuid4().hex),
)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "pdf", "txt"}

# ── Helpers ──────────────────────────────────────────────────────────────────

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def extract_text_from_pdf(filepath: str) -> str:
    """Pull raw text from all pages of a PDF using pypdf."""
    if not PYPDF_AVAILABLE:
        return ""
    reader = PdfReader(filepath)
    return "\n".join(
        (page.extract_text() or "") for page in reader.pages
    )


def extract_text_from_image(filepath: str) -> str:
    """
    Placeholder for OCR.  Replace with pytesseract / Google Vision / etc.
    Currently returns an empty string – the mock analyser will still work.
    """
    return ""


# ── Mock AI Analysis Engine ───────────────────────────────────────────────────
# Replace `_run_ai_analysis` with your real LLM/CV call (Groq, Gemini, OpenAI).

SCAM_KEYWORDS = [
    r"\bargent\b", r"\bimmediately\b", r"\bpenalty\b", r"\bfine\b",
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
    """
    Mock AI analysis.  Returns a structured verdict dict.
    -------------------------------------------------------
    TODO: Replace this function body with your actual AI call, e.g.:
        response = groq_client.chat.completions.create(
            model="llama3-70b-8192",
            messages=[{"role": "user", "content": PROMPT.format(text=text)}],
        )
        return parse_llm_response(response)
    """
    text_lower = text.lower()
    issues   : list[str] = []
    warnings : list[str] = []
    positives: list[str] = []
    score    : int        = 100          # start at 100, deduct per finding

    # ── 1. Scam keyword detection ────────────────────────────────────────────
    matched_keywords: list[str] = []
    for pattern in SCAM_KEYWORDS:
        if re.search(pattern, text_lower):
            matched_keywords.append(pattern.replace(r"\b", "").replace("\\", ""))

    if matched_keywords:
        issues.append(
            f"High-pressure language detected: "
            f"{', '.join(matched_keywords[:4])}{'…' if len(matched_keywords) > 4 else ''}. "
            "Legitimate government notices do not use urgent scare tactics."
        )
        score -= 30 * min(len(matched_keywords), 3)

    # ── 2. Domain legitimacy check ───────────────────────────────────────────
    fake_urls     = FAKE_DOMAIN_PATTERN.findall(text)
    official_urls = OFFICIAL_DOMAIN_PATTERN.findall(text)

    if fake_urls:
        issues.append(
            f"Suspicious or non-government URL found: '{fake_urls[0]}'. "
            "Real government domains must end in .gov.in or .nic.in."
        )
        score -= 25

    if official_urls:
        positives.append(
            f"Official government domain detected: '{official_urls[0]}'. "
            "This matches expected government URL patterns."
        )
        score += 5

    # ── 3. No contact info ───────────────────────────────────────────────────
    has_phone = bool(re.search(r"\b[6-9]\d{9}\b|\+91[-\s]?\d{10}", text))
    if not has_phone and len(text) > 100:
        warnings.append(
            "No verifiable official phone number found. "
            "Authentic government letters typically include a toll-free helpline."
        )
        score -= 10

    # ── 4. Sender/letterhead check ───────────────────────────────────────────
    if filename and filename.lower().endswith(".pdf") and len(text) < 80:
        warnings.append(
            "The uploaded PDF contains very little readable text. "
            "It may use embedded images to hide fake content from scanners."
        )
        score -= 15

    # ── 5. Positive signals ──────────────────────────────────────────────────
    if re.search(r"government of india|ministry of|department of|collector office", text_lower):
        positives.append("Document references a recognisable government body.")
        score += 5

    if re.search(r"reference no[.:]?\s*[A-Z0-9/-]+", text, re.IGNORECASE):
        positives.append("A formal reference number was found — this is expected in genuine notices.")
        score += 5

    # ── 6. Clamp score & derive verdict ─────────────────────────────────────
    score = max(0, min(100, score))

    if score >= 70:
        verdict      = "LIKELY LEGITIMATE"
        verdict_code = "safe"
        summary      = (
            "Based on our AI scan, this document appears to be legitimate. "
            "We found no major red flags. However, always verify directly "
            "with the issuing department using their official website."
        )
    elif score >= 40:
        verdict      = "SUSPICIOUS — USE CAUTION"
        verdict_code = "warning"
        summary      = (
            "Our AI scan found one or more suspicious signals in this document. "
            "Do not make any payments or share personal data until you have "
            "confirmed authenticity by calling the department's official helpline."
        )
    else:
        verdict      = "HIGH RISK — LIKELY SCAM"
        verdict_code = "danger"
        summary      = (
            "⚠️  Our AI scan flagged this document as high-risk. "
            "Multiple scam indicators were found. Do NOT pay, click links, "
            "or share personal information. Report this to cybercrime.gov.in."
        )

    return {
        "verdict"     : verdict,
        "verdict_code": verdict_code,   # "safe" | "warning" | "danger"
        "score"       : score,
        "summary"     : summary,
        "issues"      : issues,
        "warnings"    : warnings,
        "positives"   : positives,
        "scanned_text": text[:600] if text else None,   # first 600 chars for UI preview
        "note"         : "This is a mock AI analysis. Integrate your LLM/CV API in app.py → _run_ai_analysis().",
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the frontend single-page application."""
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/api/health", methods=["GET"])
def health():
    """Simple health-check endpoint for Render / uptime monitors."""
    return jsonify({"status": "ok", "service": "CivicShield API", "version": "1.0.0"})


@app.route("/api/scan", methods=["POST"])
def scan():
    """
    Main analysis endpoint.
    Accepts either:
      - multipart/form-data  with a `file` field  (image or PDF)
      - application/json     with a `text` field  (raw suspicious text)
    Returns a JSON verdict object.
    """
    extracted_text = ""
    filename       = None

    # ── A. File upload path ──────────────────────────────────────────────────
    if "file" in request.files:
        f = request.files["file"]
        if f.filename == "":
            return jsonify({"error": "No file selected."}), 400

        if not allowed_file(f.filename):
            return jsonify({"error": f"File type not allowed. Accepted: {', '.join(ALLOWED_EXTENSIONS)}"}), 400

        filename  = secure_filename(f.filename)
        save_path = str(UPLOAD_DIR / filename)
        f.save(save_path)
        log.info("File saved → %s", save_path)

        ext = filename.rsplit(".", 1)[1].lower()
        if ext == "pdf":
            extracted_text = extract_text_from_pdf(save_path)
        elif ext == "txt":
            extracted_text = Path(save_path).read_text(errors="ignore")
        else:
            extracted_text = extract_text_from_image(save_path)

        # Clean up upload after extraction
        try:
            os.remove(save_path)
        except OSError:
            pass

    # ── B. Raw-text path ─────────────────────────────────────────────────────
    elif request.is_json:
        body = request.get_json(silent=True) or {}
        extracted_text = body.get("text", "").strip()
        if not extracted_text:
            return jsonify({"error": "Provide either a file or a non-empty 'text' field."}), 400

    # ── C. Form text field ───────────────────────────────────────────────────
    elif request.form.get("text"):
        extracted_text = request.form.get("text", "").strip()

    else:
        return jsonify({"error": "No file or text provided. Please upload a document or paste suspicious content."}), 400

    # ── Run analysis ─────────────────────────────────────────────────────────
    log.info("Running AI analysis on %d characters of text …", len(extracted_text))
    result = _run_ai_analysis(extracted_text, filename)
    log.info("Verdict: %s  (score=%d)", result["verdict"], result["score"])

    return jsonify(result), 200


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "File too large. Maximum upload size is 16 MB."}), 413


@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Endpoint not found."}), 404


@app.errorhandler(500)
def server_error(e):
    log.exception("Internal server error")
    return jsonify({"error": "Internal server error. Please try again."}), 500


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port  = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    log.info("🛡️  CivicShield server starting on http://0.0.0.0:%d  (debug=%s)", port, debug)
    app.run(host="0.0.0.0", port=port, debug=debug)
