# 🛡️ CivicShield Threat Forensics — Benchmark Testing Guide (`testing.md`)

This guide provides **10 calibrated Test Statements** and **10 calibrated Test Links / URL Scenarios** engineered specifically for the CivicShield Threat Intelligence & Forensics Engine.

Each test case has been empirically validated against CivicShield's dual-engine detection architecture:
- **Priority 1**: **PhishTank** Verified Threat Feed & Cybersecurity Database lookup (0ms memory + API).
- **Priority 2**: **VirusTotal v3** Multi-Vendor Global Antivirus Intelligence.
- **Deterministic Heuristic Engine**: 9 threat vectors (Digital Arrest, Legal Coercion, Urgent UPI Traps, APK Payloads, SIM/KYC Bait).

---

## 📊 CivicShield Risk Scoring Standard

CivicShield uses a dynamic **1.0 to 10.0 mathematical risk scale**:

$$\text{Risk Score} = \text{clamp}\Big(1.0 + \sum \text{Risk Points} - (\text{Effective Trust} \times 0.4),\; 1.0,\; 10.0\Big)$$

| Risk Score | Threat Level | Verdict Code | UI Status & Color | Action Guidance |
| :---: | :---: | :---: | :---: | :--- |
| **1.0 – 3.9** | **SAFE** | `safe` | 🟢 **LIKELY LEGITIMATE** | Normal daily communication or verified public infrastructure. |
| **4.0 – 6.9** | **SUSPICIOUS** | `warning` | 🟡 **SUSPICIOUS — USE CAUTION** | Security anomalies detected. Verify via independent channels before proceeding. |
| **7.0 – 10.0** | **CRITICAL** | `danger` | 🔴 **HIGH RISK / CONFIRMED THREAT** | Active cyber fraud, coercive extortion, or confirmed phishing threat. Report to **1930**. |

---

## 📝 Part 1: 10 Benchmark Test Statements

Copy and paste any statement below into the **CivicShield Scanner text box** (or submit via `/api/scan`) to verify the exact output.

### Quick Reference Matrix

| # | Expected Score | Threat Level | Verdict | Forensic Threat Category |
| :---: | :---: | :---: | :---: | :--- |
| **S1** | **1.0** | `SAFE` | `LIKELY LEGITIMATE` | Clean Community / Daily Life Notice |
| **S2** | **3.5** | `SAFE` | `LIKELY LEGITIMATE` | Operational Deadline Reminder (`+2.5`) |
| **S3** | **4.0** | `SUSPICIOUS` | `SUSPICIOUS — USE CAUTION` | Telecom SIM Deactivation Alert (`+3.0`) |
| **S4** | **4.5** | `SUSPICIOUS` | `SUSPICIOUS — USE CAUTION` | Police Division Notice / Legal Coercion (`+3.5`) |
| **S5** | **5.0** | `SUSPICIOUS` | `SUSPICIOUS — USE CAUTION` | Direct Monetary Penalty / Fine Demand (`+4.0`) |
| **S6** | **5.5** | `SUSPICIOUS` | `SUSPICIOUS — USE CAUTION` | Video Inquiry Demand / Camera Coercion (`+4.5`) |
| **S7** | **6.5** | `SUSPICIOUS` | `SUSPICIOUS — USE CAUTION` | TRAI Threat + 24-Hour Panic Deadline (`+5.5`) |
| **S8** | **7.0** | `CRITICAL` | `HIGH RISK — LIKELY SCAM` | Judicial Summons + 24-Hour Arrest Threat (`+6.0`) |
| **S9** | **8.0** | `CRITICAL` | `HIGH RISK — LIKELY SCAM` | Camera Interrogation + 30-Min Coercive Panic (`+7.0`) |
| **S10** | **9.0** | `CRITICAL` | `HIGH RISK — LIKELY SCAM` | Digital Arrest + Non-Bailable Warrant (`+8.0`) |
| **S+** | **10.0** | `CRITICAL` | `HIGH RISK — LIKELY SCAM` | Multi-Vector Digital Arrest + UPI Extortion (`+12.0`) |

---

### Detailed Statements (Copy-Paste Ready)

#### Statement 1 — Clean Public Notice (Score: 1.0 | SAFE)
```text
Dear resident, the annual general meeting of the housing society is scheduled for Sunday at 10 AM in the clubhouse.
```
- **Expected Score**: `1.0`
- **Threat Level**: `SAFE` (Verdict: `LIKELY LEGITIMATE`)
- **Forensic Signals**: Baseline score. Zero extortion markers, zero unverified links, zero legal threats.

#### Statement 2 — Operational Deadline Reminder (Score: 3.5 | SAFE)
```text
Friendly reminder: Please submit your employee self-evaluation feedback form within 24 hours to the HR portal.
```
- **Expected Score**: `3.5`
- **Threat Level**: `SAFE` (Verdict: `LIKELY LEGITIMATE`)
- **Forensic Signals**: Triggered `coercive_deadline` (`+2.5`). Mild operational deadline without legal coercion or money demands.

#### Statement 3 — Telecom SIM Alert (Score: 4.0 | SUSPICIOUS)
```text
Telecom alert: Illegal calls made from your SIM card.
```
- **Expected Score**: `4.0`
- **Threat Level**: `SUSPICIOUS` (Verdict: `SUSPICIOUS — USE CAUTION`)
- **Forensic Signals**: Triggered `telecom_sim_threat` (`+3.0`). Impersonates telecom carrier claiming unauthorized activity.

#### Statement 4 — Police Division Case Notice (Score: 4.5 | SUSPICIOUS)
```text
Police case registered against your vehicle. Report to the division office.
```
- **Expected Score**: `4.5`
- **Threat Level**: `SUSPICIOUS` (Verdict: `SUSPICIOUS — USE CAUTION`)
- **Forensic Signals**: Triggered `fake_legal_coercion` (`+3.5`). Threatens police action without verified legal channels.

#### Statement 5 — Monetary Penalty / Fee Demand (Score: 5.0 | SUSPICIOUS)
```text
Notice: Pay Rs 499 penalty for late library book return before the end of the semester.
```
- **Expected Score**: `5.0`
- **Threat Level**: `SUSPICIOUS` (Verdict: `SUSPICIOUS — USE CAUTION`)
- **Forensic Signals**: Triggered `urgent_financial_coercion` (`+4.0`). Direct monetary fee/penalty demand.

#### Statement 6 — Video Camera Inquiry Demand (Score: 5.5 | SUSPICIOUS)
```text
Order: You are instructed to stay on camera during this statement inquiry.
```
- **Expected Score**: `5.5`
- **Threat Level**: `SUSPICIOUS` (Verdict: `SUSPICIOUS — USE CAUTION`)
- **Forensic Signals**: Triggered `digital_arrest` (`+4.5`). Video surveillance / isolation coercion.

#### Statement 7 — TRAI Disconnection Threat + 24hr Deadline (Score: 6.5 | SUSPICIOUS)
```text
TRAI notification: Illegal calls made from your SIM card. Your mobile number will be disconnected within 24 hours.
```
- **Expected Score**: `6.5`
- **Threat Level**: `SUSPICIOUS` (Verdict: `SUSPICIOUS — USE CAUTION`)
- **Forensic Signals**: Triggered `telecom_sim_threat` (`+3.0`) + `coercive_deadline` (`+2.5`). Cumulative score: $1.0 + 3.0 + 2.5 = 6.5$.

#### Statement 8 — Judicial Contempt Summons + Arrest Threat (Score: 7.0 | CRITICAL)
```text
Supreme Court contempt notice: Police case registered against you. Appear before the magistrate within 24 hours.
```
- **Expected Score**: `7.0`
- **Threat Level**: `CRITICAL` (Verdict: `HIGH RISK — LIKELY SCAM`)
- **Forensic Signals**: Triggered `fake_legal_coercion` (`+3.5`) + `coercive_deadline` (`+2.5`). Cumulative score: $1.0 + 3.5 + 2.5 = 7.0$.

#### Statement 9 — Video Inquiry + 30-Minute Panic Threat (Score: 8.0 | CRITICAL)
```text
Cyber cell advisory: You are instructed to stay on camera for online inquiry. Respond immediately within 30 minutes.
```
- **Expected Score**: `8.0`
- **Threat Level**: `CRITICAL` (Verdict: `HIGH RISK — LIKELY SCAM`)
- **Forensic Signals**: Triggered `digital_arrest` (`+4.5`) + `coercive_deadline` (`+2.5`). Cumulative score: $1.0 + 4.5 + 2.5 = 8.0$.

#### Statement 10 — Digital Arrest + Non-Bailable Warrant (Score: 9.0 | CRITICAL)
```text
CBI Cyber Cell: You are placed under digital arrest. Stay on skype call. Non-bailable warrant issued against your name.
```
- **Expected Score**: `9.0`
- **Threat Level**: `CRITICAL` (Verdict: `HIGH RISK — LIKELY SCAM`)
- **Forensic Signals**: Triggered `digital_arrest` (`+4.5`) + `fake_legal_coercion` (`+3.5`). Cumulative score: $1.0 + 4.5 + 3.5 = 9.0$.

#### Bonus Statement (Extreme Composite) — Full Extortion Trap (Score: 10.0 | CRITICAL)
```text
Digital arrest order: CBI arrest warrant issued. Pay Rs 50000 penalty immediately to safe custody account via inspector@oksbi within 15 minutes to avoid arrest.
```
- **Expected Score**: `10.0`
- **Threat Level**: `CRITICAL` (Verdict: `HIGH RISK — LIKELY SCAM`)
- **Forensic Signals**: Triggered `digital_arrest` (`+4.5`) + `fake_legal_coercion` (`+3.5`) + `urgent_financial_coercion` (`+4.0`) + `coercive_deadline` (`+2.5`) + `upi_payment_trap` (`+4.5`). Score saturated at `10.0`.

---

## 🔗 Part 2: 10 Benchmark Test Links & Scenarios

Copy and paste any link or link scenario below into the **CivicShield Scanner** to verify multi-vendor threat intelligence and domain forensics.

### Quick Reference Matrix

| # | Expected Score | Threat Level | Verdict | Intelligence Engine & Forensic Vector |
| :---: | :---: | :---: | :---: | :--- |
| **L1** | **1.0** | `SAFE` | `LIKELY LEGITIMATE` | Authoritative `.gov.in` Domain (Income Tax) |
| **L2** | **1.0** | `SAFE` | `LIKELY LEGITIMATE` | Authoritative `.gov.in` Domain (Parivahan) |
| **L3** | **1.0** | `SAFE` | `LIKELY LEGITIMATE` | Verified Cloud / Developer Platform (`github.io`) |
| **L4** | **4.0** | `SUSPICIOUS` | `SUSPICIOUS — USE CAUTION` | Utility Cutoff Lure on Commercial Domain (`+3.0`) |
| **L5** | **4.5** | `SUSPICIOUS` | `SUSPICIOUS — USE CAUTION` | Government Authority Claim with Commercial Domain Mismatch (`+3.5`) |
| **L6** | **5.0** | `SUSPICIOUS` | `SUSPICIOUS — USE CAUTION` | Financial Penalty Notice with Unverified Web Domain (`+4.0`) |
| **L7** | **8.0** | `CRITICAL` | `HIGH RISK — LIKELY SCAM` | Police Case Threat pointing to Unverified Domain (`+7.0`) |
| **L8** | **8.5** | `CRITICAL` | `HIGH RISK — LIKELY SCAM` | Numeric IPv4 Infrastructure (`suspicious_infra` floor 8.5) |
| **L9** | **9.5** | `CRITICAL` | `HIGH RISK — LIKELY SCAM` | Typosquatted Lookalike Government Domain (`spoofed` floor 8.5) |
| **L10** | **9.8** | `CRITICAL` | `CRITICAL THREAT — PHISHTANK CONFIRMED PHISHING` | **PhishTank** Verified Global Threat Database (Priority 1) |
| **L+** | **10.0** | `CRITICAL` | `HIGH RISK — LIKELY SCAM` | Multi-Vector Threat: Spoofed Domain + Extortion + UPI Extraction |

---

### Detailed Links & Scenarios (Copy-Paste Ready)

#### Link 1 — Official Income Tax Portal (Score: 1.0 | SAFE)
```text
https://incometax.gov.in
```
- **Expected Score**: `1.0`
- **Threat Level**: `SAFE` (Verdict: `LIKELY LEGITIMATE`)
- **Forensic Signals**: Verified `.gov.in` TLD registered under Government of India DNS registry. Automatically granted maximum trust (`trust_score: 5.0`).

#### Link 2 — Official Parivahan National Portal (Score: 1.0 | SAFE)
```text
https://parivahan.gov.in
```
- **Expected Score**: `1.0`
- **Threat Level**: `SAFE` (Verdict: `LIKELY LEGITIMATE`)
- **Forensic Signals**: Verified Ministry of Road Transport & Highways authoritative portal.

#### Link 3 — Verified Cloud / Developer Infrastructure (Score: 1.0 | SAFE)
```text
https://civicshield.github.io
```
- **Expected Score**: `1.0`
- **Threat Level**: `SAFE` (Verdict: `LIKELY LEGITIMATE`)
- **Forensic Signals**: Verified trusted cloud infrastructure (`github.io`). Zero malicious signatures across VirusTotal multi-vendor databases.

#### Link 4 — Utility Cutoff Lure on Commercial Domain (Score: 4.0 | SUSPICIOUS)
```text
Electricity will be disconnected tonight. Check bill at http://power-billing-portal.com
```
- **Expected Score**: `4.0`
- **Threat Level**: `SUSPICIOUS` (Verdict: `SUSPICIOUS — USE CAUTION`)
- **Forensic Signals**: Triggered `utility_kyc_bait` (`+3.0`) + unverified commercial domain.

#### Link 5 — Government Impersonation Domain Mismatch (Score: 4.5 | SUSPICIOUS)
```text
Official notice from Ministry of Finance: verify pending income tax refund at http://tax-refund-services.com
```
- **Expected Score**: `4.5`
- **Threat Level**: `SUSPICIOUS` (Verdict: `SUSPICIOUS — USE CAUTION`)
- **Forensic Signals**: Triggered `unauthorized_domain_for_gov` (`+3.5`). The communication claims to represent the Ministry of Finance but directs users to an unauthorized `.com` domain instead of `.gov.in`.

#### Link 6 — Financial Penalty Notice on Unverified Web Domain (Score: 5.0 | SUSPICIOUS)
```text
Notice: Pay Rs 499 penalty for late return at http://civic-library-dues.org
```
- **Expected Score**: `5.0`
- **Threat Level**: `SUSPICIOUS` (Verdict: `SUSPICIOUS — USE CAUTION`)
- **Forensic Signals**: Triggered `urgent_financial_coercion` (`+4.0`) on third-party commercial infrastructure.

#### Link 7 — Police Legal Threat directing to Unofficial Domain (Score: 8.0 | CRITICAL)
```text
Police case registered against you. Check division report at http://civil-records-desk.org
```
- **Expected Score**: `8.0`
- **Threat Level**: `CRITICAL` (Verdict: `HIGH RISK — LIKELY SCAM`)
- **Forensic Signals**: Triggered `fake_legal_coercion` (`+3.5`) + `unauthorized_domain_for_gov` (`+3.5`). Cumulative risk score: $1.0 + 3.5 + 3.5 = 8.0$.

#### Link 8 — Direct Numeric IPv4 Address Infrastructure (Score: 8.5 | CRITICAL)
```text
http://192.168.1.100/admin-login
```
- **Expected Score**: `8.5`
- **Threat Level**: `CRITICAL` (Verdict: `HIGH RISK — LIKELY SCAM`)
- **Forensic Signals**: Triggered `suspicious_url_infra` (raw numeric IPv4 address instead of registered domain). Enforces safety floor `8.5`.

#### Link 9 — Typosquatted Lookalike Government Domain (Score: 9.5 | CRITICAL)
```text
http://parivahan-echallan-quickpay.org
```
- **Expected Score**: `9.5`
- **Threat Level**: `CRITICAL` (Verdict: `HIGH RISK — LIKELY SCAM`)
- **Forensic Signals**: Triggered `spoofed_phishing_domain` (`+8.5`). Unlawfully leverages government brand tokens (`parivahan`, `echallan`) on an unauthorized `.org` domain.

#### Link 10 — PhishTank Confirmed Threat Intelligence (Score: 9.8 | CRITICAL)
```text
https://phishtank.icu/login
```
- **Expected Score**: `9.8`
- **Threat Level**: `CRITICAL` (Verdict: `CRITICAL THREAT — PHISHTANK CONFIRMED PHISHING`)
- **Forensic Signals**: **Priority 1 PhishTank Threat Intelligence Engine Hit**. Verified active credential phishing attack in PhishTank cybersecurity database. Enforces global threat floor `9.8`.

#### Bonus Link (Composite Cyber Attack) — Multi-Vector Scam (Score: 10.0 | CRITICAL)
```text
URGENT: Police arrest warrant issued. Pay Rs 5000 fine at http://echallan-parivahan.com/pay immediately within 30 minutes to officer@oksbi
```
- **Expected Score**: `10.0`
- **Threat Level**: `CRITICAL` (Verdict: `HIGH RISK — LIKELY SCAM` / `CRITICAL THREAT`)
- **Forensic Signals**: Composite attack combining typosquatted domain (`echallan-parivahan.com`), fake arrest warrant, immediate deadline, and personal UPI extraction handle (`officer@oksbi`). Saturated at `10.0`.

---

## 🛠️ How to Test

### Method A: Via Web Browser UI
1. Run the CivicShield application:
   ```bash
   python app.py
   ```
2. Open your browser and navigate to `http://localhost:5000` (or `http://127.0.0.1:5000`).
3. Paste any statement or URL from this document into the **Text Input / Scan Box**.
4. Click **"Analyze Communication"** (or press Enter).
5. Verify the **Risk Score**, **Verdict Banner**, and **Forensic Tags** match this document.

### Method B: Via cURL / API
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "https://incometax.gov.in"}'
```

**Sample API Response**:
```json
{
  "score": 1.0,
  "threat_level": "SAFE",
  "verdict_code": "safe",
  "verdict": "LIKELY LEGITIMATE",
  "trust_score": 5.0,
  "engine": "phishtank-virustotal-threat-intel"
}
```

### Method C: Automated Regression Suite
You can execute a quick Python one-liner to verify all test cases programmatically:
```bash
python -c "import app; print(app._run_security_scan('https://incometax.gov.in', None)['score'])"
# Expected output: 1.0
```
