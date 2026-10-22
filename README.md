# CivicShield: AI-Powered Digital Forensics & Scam Neutralization System

<div align="center">

![CivicShield Banner](https://img.shields.io/badge/Security-Government%20Impersonation%20Detection-blue?style=for-the-badge&logo=shield)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![Flask 3.x](https://img.shields.io/badge/Flask-3.x-black?style=for-the-badge&logo=flask)
![Groq OSS-120B](https://img.shields.io/badge/LLM-Groq%20GPT--OSS--120B-orange?style=for-the-badge&logo=openai)
![Tesseract OCR](https://img.shields.io/badge/OCR-Tesseract%205.x-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)

**An Interdisciplinary Team (IDT) Academic Cybersecurity Initiative**  
*Defending citizens against Digital Arrests, Government Impersonation, and Social Engineering Extortion.*

</div>

---

## Table of Contents

1. [Executive Summary & Problem Statement](#1-executive-summary--problem-statement)
2. [Key Capabilities & Forensic Innovations](#2-key-capabilities--forensic-innovations)
3. [System Architecture & Data Flow](#3-system-architecture--data-flow)
4. [Technology Stack](#4-technology-stack)
5. [Heuristic Forensics & Threat Taxonomy](#5-heuristic-forensics--threat-taxonomy)
6. [API Specification & Endpoints](#6-api-specification--endpoints)
7. [Installation & Local Setup](#7-installation--local-setup)
8. [Docker & Container Deployment](#8-docker--container-deployment)
9. [Cloud Deployment Guide (Render / Vercel / Railway)](#9-cloud-deployment-guide-render--vercel--railway)
10. [Project Leadership & Contribution Matrix](#10-project-leadership--contribution-matrix)
11. [Risk Score Benchmark & Demo Test Cases (1 to 10 Calibration)](#risk-score-benchmark--demo-test-cases-1-to-10-calibration)

---

## 1. Executive Summary & Problem Statement

### The Epidemic of "Digital Arrest" & Official Impersonation Scams
In recent years, cybercrime syndicates targeting Indian citizens have shifted from rudimentary phishing to sophisticated, high-pressure psychological extortion schemes known collectively as **"Digital Arrests"** and **Government Agency Impersonation**.

According to the **Indian Cyber Crime Coordination Centre (I4C)** under the Ministry of Home Affairs (MHA), citizens have lost hundreds of crores to organized transnational fraud rings. The modus operandi involves:

1. **Intimidation via Fake Authorities**: Attackers pose as officers of the **Central Bureau of Investigation (CBI)**, **Narcotics Control Bureau (NCB)**, **Enforcement Directorate (ED)**, **Customs Department**, or state police crime branches (e.g., Mumbai Police, Delhi Police).
2. **Fabricated Digital Summons**: Victims receive forged arrest warrants, court notices bearing simulated National Emblems, or fake traffic challans.
3. **Coercive Video Confinement**: Victims are forced onto Skype, WhatsApp, or Webex video calls under the false pretense of a "Digital Arrest" and prohibited from hanging up.
4. **Financial Exfiltration**: Victims are coerced into transferring their life savings into "RBI verification accounts," "safe custody accounts," or unverified personal UPI handles under the guise of "asset verification."

### The Solution: CivicShield
**CivicShield** is an automated, real-time cyber forensic analysis platform and AI assistant built to neutralize these attacks before financial harm occurs. It provides:
- **Zero-Trust Document Verification**: Multi-pass image pre-processing and OCR extraction to detect forged seals, non-statutory threats, and hidden payloads.
- **Lookalike Phishing & Typosquatting Detection**: Real-time algorithmic checking against legitimate Indian National Top-Level Domains (`.gov.in`, `.nic.in`) and flagging of malicious URL shorteners or rogue TLDs (`.xyz`, `.vip`).
- **UPI Handle & Fraudulent VPA Interception**: Immediate flagging of personal UPI IDs inside purported official communications.
- **Resilient AI Intelligence Assistant**: Powered by the Groq LPU inference engine running `openai/gpt-oss-120b` with autonomous heuristic fallback when external networks fail.

---

## 2. Key Capabilities & Forensic Innovations

| Feature | Technical Implementation | Security Impact |
| :--- | :--- | :--- |
| **Multi-Pass OCR Pipeline** | Grayscale auto-contrast, adaptive thresholding, resolution upscaling via Pillow & Tesseract | Captures high-clarity text from blurry, low-resolution WhatsApp screenshots and noisy photographs. |
| **Typosquatting Engine** | Substring brand-token analysis, TLD whitelisting, punycode resolution, URL shortener detection | Prevents victims from navigating to clone portals mimicking Parivahan, UIDAI, Income Tax, or Delhi Police. |
| **VPA / UPI Mismatch Filter** | Regular expression parser identifying personal banking VPAs (`@okhdfcbank`, `@paytm`, `@ybl`) | Unmasks fraudulent extortion: official government bodies never collect fines via personal UPI IDs. |
| **Digital Arrest Classifier** | Weighted semantic keyword heuristic matching coercive legal language, section numbers, and urgency cues | Provides an instant 0–10 calibrated risk score and transparent evidence breakdown. |
| **Multi-Turn Conversational AI** | Groq OpenAI-compatible Chat Completions with 131K context window & sliding memory | Empathetic, authoritative cybersecurity advisory guiding victims through Golden Hour escalation (1930 / cybercrime.gov.in). |
| **Autonomous Heuristic Fallback** | Instantaneous offline rule engine activated during API rate limits or latency spikes | Guarantees 100% platform availability even during upstream cloud outages. |

---

## 3. System Architecture & Data Flow

### Architectural Block Diagram (ASCII)

```
┌────────────────────────────────────────────────────────────────────────┐
│                       CIVICSHIELD CLIENT (SPA)                         │
│  - Vanilla JavaScript & Dark Mode CSS Design System                    │
│  - Environment-Aware Origin Resolver (Window.location.origin)          │
│  - Interactive Step-by-Step Scan Loader & Error Recovery Card          │
│  - Real-Time Markdown Chat Interface with Inline Retry Action          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP POST (Multipart / JSON)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   ENTERPRISE FLASK BACKEND (app.py)                    │
│  - Structured CORS Engine (Configurable Origins)                       │
│  - Security Audit Logging & Request ID Tracing (UUIDv4)                │
│  - Payload Sanitization & Buffer Size Enforcement (Max 10 MB)          │
│  - Rate Limiting Middleware (Flask-Limiter / Memory / Redis)           │
└───────┬───────────────────────────┬────────────────────────────┬───────┘
        │                           │                            │
        ▼ (File Ingestion)          ▼ (Text / Chat)              ▼ (Heuristics)
┌───────────────────────┐   ┌───────────────────────┐   ┌───────────────────────┐
│ MULTI-PASS OCR PIPELINE│   │  GROQ LLM INFERENCE   │   │ FORENSIC RULE ENGINE  │
│ - Magic byte sniffing │   │ - openai/gpt-oss-120b │   │ - Digital arrest cues │
│ - EXIF orientation fix│   │ - 131K context window │   │ - Typosquatting checks│
│ - Grayscale & Contrast│   │ - Sliding turn window │   │ - Personal UPI hunter │
│ - Adaptive binarize   │   │ - Latency resilience  │   │ - Risk score (0 - 10) │
│ - Tesseract OCR (Eng) │   │ - Autonomous fallback │   │ - Evidence signals    │
└───────────────────────┘   └───────────────────────┘   └───────────────────────┘
```

### End-to-End Data Flow (Mermaid)

```mermaid
sequenceDiagram
    autonumber
    actor Citizen as Citizen / User
    participant Frontend as CivicShield SPA (index.html)
    participant Flask as Flask Core (app.py)
    participant OCR as Pillow + Tesseract Pipeline
    participant Heuristic as Forensic Heuristic Engine
    participant Groq as Groq LLM (gpt-oss-120b)

    Citizen->>Frontend: Uploads suspicious summons (PDF/Image) or pastes SMS
    Frontend->>Frontend: Displays progressive step loader (25% -> 50% -> 75%)
    Frontend->>Flask: POST /api/scan (Multipart FormData or JSON)
    Flask->>Flask: Validates magic bytes, checks payload limits & rate limits
    
    alt File Payload (PDF / Image)
        Flask->>OCR: Ingests file & applies preprocessing (Grayscale + Contrast + Binarize)
        OCR-->>Flask: Returns normalized textual transcription
    end

    Flask->>Heuristic: Evaluates text against forensic threat taxonomy
    Heuristic->>Heuristic: Inspects domains (e.g., .gov.in vs typosquats)
    Heuristic->>Heuristic: Detects unauthorized UPI handles (@okhdfcbank, @paytm)
    Heuristic->>Heuristic: Flags digital arrest coercive phrases & artificial deadlines
    Heuristic-->>Flask: Returns risk score (0-10), verdict, and findings array

    Flask-->>Frontend: HTTP 200 JSON Response (verdict, score, evidence, text)
    Frontend->>Citizen: Renders animated circular risk meter, evidence cards, and advice

    opt Citizen Opens Assistant
        Citizen->>Frontend: "They said Mumbai Police will arrest me in 1 hour on Skype. What should I do?"
        Frontend->>Flask: POST /api/chat (message + history)
        alt Groq API Reachable
            Flask->>Groq: Chat completion with system instructions & multi-turn memory
            Groq-->>Flask: Authoritative Markdown advisory response
        else Rate Limit / Latency Spike / Offline
            Flask->>Flask: Triggers autonomous context-aware deterministic fallback
        end
        Flask-->>Frontend: HTTP 200 JSON Response (reply, engine tag)
        Frontend->>Citizen: Formats Markdown response (bold headers, bullet points, helpline 1930)
    end
```

---

## 4. Technology Stack

### Backend Core
- **Framework**: Python 3.10+ / Flask 3.x
- **Inference Engine**: Groq Cloud SDK (`groq`) using `openai/gpt-oss-120b`
- **OCR Engine**: Tesseract OCR 5.x via `pytesseract`
- **Image Processing**: Pillow (PIL) 10.x (`ImageOps`, `ImageEnhance`, `ImageFilter`)
- **PDF Extraction**: `pypdf` 4.x (with encrypted stream bypass handling)
- **Security & Hygiene**: `Flask-CORS`, `Flask-Limiter`, `werkzeug.utils`
- **WSGI Production Server**: Gunicorn 21.x

### Frontend Architecture
- **Structure**: Semantic HTML5 Single Page Application (SPA)
- **Styling**: Vanilla CSS3 Custom Properties (Dark glassmorphism, responsive grid, micro-animations)
- **Typography**: Google Fonts (`DM Sans`, `Instrument Sans`, `JetBrains Mono`)
- **Icons**: Inline scalable vector graphics (SVG) with zero external icon-font bloat
- **Markdown Engine**: Custom built-in regex parser (XSS-sanitized with zero third-party script vulnerabilities)

---

## 5. Heuristic Forensics & Threat Taxonomy

CivicShield's heuristic engine classifies indicators across weighted threat categories:

```
Threat Points (T) = ∑ CategoryWeights + URLRisk + UPIRisk
Trust Points (P)  = ∑ VerifiedGovDomains + OfficialRefSyntax + NationalHelplineCues
Calibrated Risk   = MAX(0.0, MIN(10.0, T - (P * 0.4)))
```

### Risk Calibration Table

| Risk Score | Verdict Category | Badge Style | System Action & Guidance |
| :---: | :---: | :---: | :--- |
| **7.0 – 10.0** | `HIGH RISK — LIKELY SCAM` | `Danger (Red)` | Critical social engineering detected. Immediate escalation instructions for National Helpline 1930 and cybercrime.gov.in. |
| **3.0 – 6.9** | `SUSPICIOUS — USE CAUTION` | `Warning (Amber)` | Anomalous patterns detected (non-official domain or urgent phrasing). Advise independent verification via official portals. |
| **0.0 – 2.9** | `LIKELY LEGITIMATE` | `Safe (Green)` | No coercive threat markers found. Valid `.gov.in` domain or formal procedural reference verified. |

---

## 6. API Specification & Endpoints

### 1. Health & Telemetry
- **Endpoint**: `GET /api/health`
- **Description**: Returns operational status, engine capabilities, and version metadata.
- **Response**: `200 OK`
```json
{
  "status": "healthy",
  "service": "CivicShield AI System",
  "llm_engine": "groq/openai/gpt-oss-120b",
  "llm_configured": true,
  "reasoning_effort": "medium",
  "capabilities": {
    "ocr": true,
    "pdf": true,
    "llm": true,
    "rate_limiting": true,
    "heuristic_forensics": true
  },
  "version": "4.1.0",
  "timestamp": 1792576400
}
```

---

### 2. Forensic Scan & Document Analysis
- **Endpoint**: `POST /api/scan`
- **Headers**: `Content-Type: multipart/form-data` OR `Content-Type: application/json`
- **Rate Limit**: 60 requests / hour

#### Request Formats:
**A. Multipart Form Data (File Upload):**
```
file: [binary attachment: .pdf, .png, .jpg, .jpeg, .webp, .txt]
```

**B. JSON Payload (Pasted Message):**
```json
{
  "text": "URGENT: Your Aadhaar has been blocked in connection with a money laundering case. Connect on Skype immediately or transfer Rs 50,000 security bail to cyber-verify@okhdfcbank."
}
```

#### Response (`200 OK`):
```json
{
  "verdict": "HIGH RISK — LIKELY SCAM",
  "verdict_code": "danger",
  "score": 10.0,
  "trust_score": 0.0,
  "summary": "CRITICAL THREAT SIGNALS DETECTED. This communication exhibits high-confidence indicators of government impersonation, digital arrest extortion, or lookalike phishing.",
  "findings": [
    {
      "type": "issue",
      "severity": "high",
      "text": "Digital Arrest & Virtual Extortion: Law enforcement in India NEVER conducts 'Digital Arrests' or video-call interrogations."
    },
    {
      "type": "issue",
      "severity": "high",
      "text": "Coercive Legal Prosecution Threats: Arrest warrants and summons are never served over instant messaging apps or phone calls."
    },
    {
      "type": "issue",
      "severity": "critical",
      "text": "Fraudulent UPI payment handle identified (cyber-verify@okhdfcbank). Official law enforcement and ministries NEVER collect fines, bails, or penalties via personal UPI VPAs."
    }
  ],
  "threat_tags": [
    "digital_arrest",
    "fake_legal_coercion",
    "urgent_financial_coercion",
    "upi_payment_trap"
  ],
  "extracted_text": "URGENT: Your Aadhaar has been blocked..."
}
```

---

### 3. Cyber Intelligence Assistant Chat
- **Endpoint**: `POST /api/chat`
- **Headers**: `Content-Type: application/json`
- **Rate Limit**: 120 requests / hour

#### Request Format:
```json
{
  "message": "Someone claiming to be from Mumbai Cyber Cell called me about illegal narcotics in a FedEx package. What should I do?",
  "history": [
    { "role": "user", "content": "Hello, I got a call from an unknown officer." },
    { "role": "assistant", "content": "I can help verify official communications. What details did they provide?" }
  ]
}
```

#### Response (`200 OK`):
```json
{
  "reply": "### Advisory: Courier & Narcotics Impersonation Scam\n\n**Verdict**: HIGH-RISK IMPERSONATION SCHEME.\n\n**Modus Operandi**:\nFraudsters pose as FedEx or DHL customer support stating that a package containing contraband has been intercepted, then connect you to a fake police officer demanding money.\n\n**Recommended Steps**:\n1. **Do not pay any fee or penalty**.\n2. Contact your local police station or dial **1930** immediately.\n3. File an official complaint on **cybercrime.gov.in**.",
  "engine": "groq/openai/gpt-oss-120b",
  "status": "success",
  "fallback_reason": null,
  "request_id": "8a4f91b2"
}
```

---

### 4. HTTP Error Catalog

| Status Code | Error Message | Solution / Cause |
| :---: | :--- | :--- |
| `400 Bad Request` | `Missing or empty 'text' parameter in JSON payload.` | Ensure either a valid file or non-empty text string is provided. |
| `413 Payload Too Large` | `Payload exceeds maximum permissible size (10 MB).` | Compress PDF or downsample image resolution below 10 MB. |
| `422 Unprocessable` | `Unable to extract legible text from this file.` | The uploaded image is too blurry, unreadable, or missing OCR data. |
| `429 Rate Limited` | `Rate limit exceeded. Please wait a moment.` | Exceeded quota (60 scans/hr, 120 chats/hr). Retry after cooldown. |
| `500 Server Error` | `Internal computation fault. Please retry.` | Handled internal exception logged with unique `X-Request-ID`. |

---

## 7. Installation & Local Setup

### Prerequisites
- **Python 3.10** or higher
- **Git**
- **Tesseract OCR**:
  - **Windows**: Download the official installer from [UB-Mannheim Tesseract](https://github.com/UB-Mannheim/tesseract/wiki). Ensure it is installed to `C:\Program Files\Tesseract-OCR\tesseract.exe`.
  - **Ubuntu / Debian**:
    ```bash
    sudo apt-get update && sudo apt-get install -y tesseract-ocr tesseract-ocr-eng
    ```
  - **macOS (Homebrew)**:
    ```bash
    brew install tesseract
    ```

### Step 1: Clone the Repository
```bash
git clone https://github.com/cyber-pranav/CivicShield.git
cd CivicShield
```

### Step 2: Create and Activate Virtual Environment
```bash
# Linux / macOS:
python3 -m venv venv
source venv/bin/activate

# Windows (Command Prompt):
python -m venv venv
venv\Scripts\activate.bat

# Windows (PowerShell):
python -m venv venv
venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Copy the template configuration file:
```bash
cp .env.example .env
```
Open `.env` and configure your credentials:
```ini
SECRET_KEY=generate_a_random_secret_string
GROQ_API_KEY=gsk_your_groq_api_key_here
GROQ_MODEL=openai/gpt-oss-120b
PORT=5000
FLASK_DEBUG=false

# Windows only (if tesseract is not in system PATH):
# TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe
```

### Step 5: Start the Server
```bash
python app.py
```
Open your browser and navigate to:
```
http://localhost:5000
```

---

## 8. Docker & Container Deployment

CivicShield comes complete with a hardened multi-stage Docker setup and `docker-compose.yml`.

### Single-Command Run with Docker Compose
```bash
# Build and spin up container in detached mode
docker compose up -d --build
```
Inspect logs:
```bash
docker compose logs -f
```
Access the application at `http://localhost:5000`.

### Manual Docker Build
```bash
# Build production image
docker build -t civicshield:latest .

# Run with environment variables
docker run -d --name civicshield-app \
  -p 5000:5000 \
  --env-file .env \
  civicshield:latest
```

---

## 9. Cloud Deployment Guide (Render / Vercel / Railway)

### Deploying on Render (Recommended)
1. Fork or push this repository to GitHub.
2. Sign in to [Render](https://render.com) and click **New + > Web Service**.
3. Select your `CivicShield` repository.
4. Configure service settings:
   - **Environment**: `Docker`
   - **Branch**: `main`
   - **Region**: Singapore / Frankfurt / Oregon
   - **Plan**: Free or Starter
5. Add the Environment Variables:
   - `GROQ_API_KEY` = your Groq API key
   - `GROQ_MODEL` = `openai/gpt-oss-120b`
   - `GROQ_REASONING_EFFORT` = `medium`
   - `SECRET_KEY` = long random cryptographic string
   - `FLASK_DEBUG` = `false`
6. Click **Create Web Service**. Render will automatically build the `Dockerfile` with Tesseract OCR pre-installed and start Gunicorn.

---

## 10. Project Leadership & Contribution Matrix

> **Important Academic & Governance Notice:**
> **CivicShield was conceptualized, architected, and fully implemented by Naishal Nadiya (Technical & Product Lead). The repository includes co-authors representing the academic IDT group members for coursework and viva evaluation.**

This project was developed as an **Interdisciplinary Team (IDT)** academic capstone project combining Cybersecurity Forensics, Applied Artificial Intelligence, and Modern Full-Stack Software Engineering.

### Leadership & Role Distinction

1. **Product Architect & Technical Lead: Naishal Nadiya**
   - **Sole Creator & Lead Developer** of CivicShield.
   - Designed and engineered the entire core architecture, Flask backend, heuristic forensic scoring engine, Groq LLM integration (`openai/gpt-oss-120b`), OCR/PDF parsing pipeline, and modern dark-mode frontend interface.
   - Conceptualized and calibrated the deterministic 1-to-10 risk calibration matrix and unified single-page architecture.

2. **IDT Group Administrative Lead: Krishsinh Raj**
   - Handled academic coordination, institutional compliance, faculty liaison, and coursework submissions.

3. **Supporting Collaborators / Co-authors:**
   - **Diya Patel**: Documentation support & test dataset aggregation.
   - **Pranav** ([@cyber-pranav](https://github.com/cyber-pranav)): Edge-case testing & presentation assets.
   - **Ansh Dohare** ([@urxansh](https://github.com/urxansh)): Survey feedback & user testing.

---

### Contribution Weightage Matrix

| Member | Core Contributions | 
| :--- | :--- | :---: |
| **Naishal Nadiya** | End-to-end full-stack development, 1-10 risk calibration engine, Groq AI pipeline, OCR/PDF parsing, security logic | 
| **Krishsinh Raj** | Academic coordination, coursework deliverables, report compilation | 
| **Diya Patel** | Test dataset collection, sample scam text verification |
| **Pranav** | Browser edge-case testing, feedback collation | 
| **Ansh Dohare** | User testing, UI usability review |

---

## Risk Score Benchmark & Demo Test Cases (1 to 10 Calibration)

For academic viva demonstrations, defense juries, and faculty evaluations, CivicShield features a **deterministic 1-to-10 Risk Calibration Matrix**. The forensic engine computes transparent, reproducible threat scores by correlating domain registries, TLD abuse metrics, behavioral urgency patterns, and financial extortion markers.

### Viva Demonstration Matrix (1/10 to 10/10)

| Score | Category | Verdict Badge | Example Demonstration Input | Forensic Signals & Underlying Rationale |
| :---: | :--- | :--- | :--- | :--- |
| **1.0** | Authoritative Filing | `Safe` (Green) | `https://incometax.gov.in Reference No: IT/2026/8941` | Valid `.gov.in` domain + formal administrative reference number syntax. Maximum trust points awarded, 0 threat signals. |
| **2.0** | Verified Official Portal | `Safe` (Green) | `https://parivahan.gov.in` | Verified legitimate Indian government portal (`.gov.in` / `.nic.in`) without formal case filing syntax. |
| **3.0** | Benign Communication | `Safe` (Green) | `Meeting scheduled with municipal road repair team next Monday at city center.` | Non-official general text without any urgency, coercion, threat keywords, or external links. Clean baseline score. |
| **4.5** | Generic Third-Party Domain | `Suspicious` (Amber) | `https://news-bulletin.org/daily-update` | Generic non-government domain (`.org`, `.com`, `.net`). Unverified source without explicit scam triggers. |
| **5.5** | Unverified Domain + Urgency | `Suspicious` (Amber) | `https://portal-services.com/check KYC update pending immediately` | Generic domain (`4.5`) combined with soft coercive urgency cue (`immediately`, `pending KYC update`). |
| **7.0** | Urgent Coercion + Fake Fine | `High Risk` (Red) | `Electricity power supply disconnected tonight pay penalty within 2 hours at https://bill-pay-online.net` | Non-gov link + utility disconnection threat (`utility_kyc_bait`) + fake penalty demand + 2-hour deadline pressure. |
| **8.0** | Phishing Infrastructure | `High Risk` (Red) | `https://phishtank.icu/login` or `http://192.168.1.1/verify` | Disposable high-risk TLD (`.icu`, `.top`, `.xyz`) or raw numeric IPv4 hostname. Immediate minimum 8.0 score trigger. |
| **9.0** | Phishing + Arrest Threat | `High Risk` (Red) | `CBI arrest warrant issued against your Aadhaar. Connect immediately on video call: https://cbi-investigation.top/case` | Malicious TLD (`.top`) combined with simulated CBI arrest warrant, Aadhaar misuse threat, and video call confinement. |
| **10.0** | Phishing + Arrest + Extortion | `High Risk` (Red) | `Digital arrest order: CBI NBW issued. Transfer Rs 98,000 bail deposit to rbi-clearing@okhdfcbank or https://court-bail.icu/pay now` | Maximum severity composite: Malicious TLD (`.icu`) + Digital Arrest non-bailable warrant + personal UPI VPA extortion (`@okhdfcbank`). |

---

### Quick Copy-Paste Test Inputs for Faculty Review

Use the following snippets during live project evaluation to demonstrate the full dynamic range of the risk meter:

#### Test 1: Verified Safe Notice (Score: 1.0 / 10)
```text
https://incometax.gov.in Reference No: IT/2026/8941
```
*Expected Result:* Score **1.0**, Badge **Verified low risk** (Green ring), Findings report official government domain verification and formal filing syntax.

#### Test 2: Standard Official Portal (Score: 2.0 / 10)
```text
https://parivahan.gov.in
```
*Expected Result:* Score **2.0**, Badge **Verified low risk** (Green ring), Confirms official `.gov.in` whitelist status.

#### Test 3: Clean Benign Message (Score: 3.0 / 10)
```text
Meeting scheduled with municipal road repair team next Monday at city center.
```
*Expected Result:* Score **3.0**, Badge **Verified low risk** (Green ring), Zero threat tags detected.

#### Test 4: Generic Unverified Link (Score: 4.5 / 10)
```text
https://news-bulletin.org/daily-update
```
*Expected Result:* Score **4.5**, Badge **Suspicious** (Amber ring), Signals non-government third-party domain.

#### Test 5: Unverified Domain with Urgency Marker (Score: 5.5 / 10)
```text
https://portal-services.com/check KYC update pending immediately
```
*Expected Result:* Score **5.5**, Badge **Suspicious** (Amber ring), Flags artificial deadline pressure alongside non-gov destination.

#### Test 6: Fake Challan / Utility Disconnection Threat (Score: 7.0 / 10)
```text
Electricity power supply disconnected tonight pay penalty within 2 hours at https://bill-pay-online.net
```
*Expected Result:* Score **7.0**, Badge **High risk** (Red ring), Flags high-pressure power cutoff cue, artificial deadline, and penalty demand.

#### Test 7: PhishTank Malicious TLD URL (Score: 8.0 / 10)
```text
https://phishtank.icu/login
```
*Expected Result:* Score **8.0**, Badge **High risk** (Red ring), Flags critical indicator for disposable `.icu` phishing infrastructure.

#### Test 8: Raw IP Address Hostname (Score: 8.0 / 10)
```text
http://192.168.1.1/verify
```
*Expected Result:* Score **8.0**, Badge **High risk** (Red ring), Flags critical indicator for direct numeric IP address bypassing DNS reputation.

#### Test 9: Law Enforcement Impersonation & Arrest Threat (Score: 9.0 / 10)
```text
CBI arrest warrant issued against your Aadhaar. Connect immediately on video call: https://cbi-investigation.top/case
```
*Expected Result:* Score **9.0**, Badge **High risk** (Red ring), Detects fake CBI warrant, coercive video call demand, and malicious `.top` TLD.

#### Test 10: Digital Arrest & UPI Extortion Trap (Score: 10.0 / 10)
```text
Digital arrest order: CBI NBW issued. Transfer Rs 98,000 bail deposit to rbi-clearing@okhdfcbank or https://court-bail.icu/pay now
```
*Expected Result:* Score **10.0**, Badge **High risk** (Red ring), Flags digital arrest extortion, fraudulent personal UPI VPA (`@okhdfcbank`), and disposable `.icu` link.

---

<div align="center">

**CivicShield — Empowering Citizens with Autonomous Cybersecurity Intelligence.**  
*National Cyber Crime Reporting Helpline: 1930 | Portal: cybercrime.gov.in*

</div>

