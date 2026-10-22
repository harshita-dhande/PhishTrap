# PhishTrap — Autonomous Phishing Detection & Response Platform

> **A fully automated, multi-vector SOAR (Security Orchestration, Automation & Response) system that intercepts phishing emails, detonates payloads in an isolated sandbox, and applies AI-powered threat verdicts — before a human ever touches the email.**

---

## 🔍 Problem Statement

Phishing remains the #1 vector for cyberattacks — responsible for over 91% of all data breaches. Despite decades of security research, three critical gaps persist:

1. **Signature-based tools are reactive.** Antivirus and spam filters look for *known* patterns. Novel phishing emails — crafted to evade keyword filters — slip through undetected.
2. **Manual triage doesn't scale.** Security Operations Center (SOC) analysts are overwhelmed. A single analyst cannot review hundreds of emails per day without missing something.
3. **Static analysis is blind to runtime behavior.** An encrypted ZIP attachment, a shortened URL, or a malicious PDF cannot be fully judged just by looking at it — you have to *run* it.

**PhishTrap solves all three gaps simultaneously.**

---

## 🧠 What is PhishTrap?

PhishTrap is a full-stack, autonomous phishing threat intelligence platform built from scratch. It operates as a four-tier pipeline:

```
📧 Suspicious Email Arrives
         │
   ┌─────▼──────┐
   │  TIER 1    │  Gmail API — Real-time Ingestion (OAuth2)
   │  Ingestion │  Monitors Inbox + Spam every 60 seconds
   └─────┬──────┘
         │
   ┌─────▼──────────────────────────────────────────┐
   │  TIER 2 — Multi-Vector Analysis Engine (Mac)   │
   │                                                 │
   │  ① Link Analysis     — Raw IPs, URL shorteners │
   │  ② Text Analysis     — Urgency & social eng.   │
   │  ③ OCR Extraction    — Text hidden in images   │
   │  ④ AI/LLM Brain      — Contextual reasoning    │
   │  ⑤ Reputation Check  — Domain/IP threat intel  │
   │  ⑥ PDF Analysis      — Embedded scripts/macros │
   └─────┬──────────────────────────────────────────┘
         │
   ┌─────▼──────┐
   │  TIER 3    │  Sandbox Detonation Agent (UTM Windows VM)
   │  Sandbox   │  Executes payload, records behavior telemetry
   └─────┬──────┘
         │
   ┌─────▼─────────────────────────────────────────┐
   │  TIER 4 — SOC Dashboard + Gmail Action Engine │
   │                                                │
   │  • Color-coded Gmail labels applied            │
   │  • HTML report note injected into thread       │
   │  • Live feed dashboard at http://127.0.0.1:8080│
   │  • Full JSON reports persisted to disk         │
   └───────────────────────────────────────────────┘
```

---

## ⚙️ The Pipeline — Step by Step

### Step 1 — Email Ingestion (Gmail API + OAuth2)
[`gmail_watcher.py`](file:///Users/harshita/Desktop/PhishTrap/gmail_watcher.py) runs as a background daemon, polling Gmail every 60 seconds using the official Gmail REST API authenticated via OAuth 2.0. It queries **both the Inbox and Spam folder** (`in:inbox OR in:spam`), fetches raw `.eml` bytes for any new message, and deduplicates using a persistent `gmail_seen.json` registry. Bot-sent report notes are excluded to prevent the watcher from re-analyzing its own outputs.

### Step 2 — Email Parsing
[`parse_eml.py`](file:///Users/harshita/Desktop/PhishTrap/parse_eml.py) decodes the raw email bytes into structured components: sender address, subject, plain-text body, HTML body, and raw attachment bytes. MIME boundaries are walked recursively to handle nested structures.

### Step 3 — OCR Extraction
[`ocr_extract.py`](file:///Users/harshita/Desktop/PhishTrap/ocr_extract.py) runs **Tesseract OCR** over any image attachments embedded in the email. This is critical because attackers routinely hide passwords, access codes, and phishing text *inside images* specifically to bypass text-based keyword scanners. PhishTrap sees through this technique.

### Step 4 — AI / LLM Brain (Local Ollama)
[`ai_brain.py`](file:///Users/harshita/Desktop/PhishTrap/ai_brain.py) sends the combined email body + OCR text to a **locally running Ollama LLM**. The model is prompted as a security analyst to detect hidden passwords, access codes, and decryption keys embedded in the content, returning a structured JSON result with a confidence score and reasoning. A **JSON salvage fallback** using regex handles cases where the LLM produces malformed output. Crucially, **all inference happens on-device** — no email data is ever sent to an external API.

### Step 5 — Link Analysis
[`link_extract.py`](file:///Users/harshita/Desktop/PhishTrap/link_extract.py) extracts all URLs from the email body using regex, then scores each one for:
- **Raw IP addresses** in the URL (e.g. `http://192.0.2.10/...`) — high risk score of 0.70
- **URL shorteners** (bit.ly, tinyurl, t.co, etc.) — obfuscation indicator
- **Lookalike domains** that mimic trusted brands (paypa1, amaz0n, etc.)
- **Suspicious TLDs** and abnormal port numbers

### Step 6 — Text / Language Analysis
[`text_analysis.py`](file:///Users/harshita/Desktop/PhishTrap/text_analysis.py) scans the email body for:
- **Urgency phrases**: "act immediately", "within 24 hours", "before Thursday", "payroll cutoff", "account suspended"
- **Credential harvesting cues**: "verify your identity", "access code", "password-protected", "compensation review"
- **Social engineering patterns**: impersonation of IT, HR, legal, or finance departments

### Step 7 — Reputation Check
[`reputation.py`](file:///Users/harshita/Desktop/PhishTrap/reputation.py) looks up the sender's domain against a local threat intelligence registry (`sender_reputation.json`). First-time-seen domains, known-bad domains, and free email providers masquerading as corporate senders add a `risk_bump` to the composite score.

### Step 8 — PDF Analysis
[`pdf_analysis.py`](file:///Users/harshita/Desktop/PhishTrap/pdf_analysis.py) inspects PDF attachments for suspicious embedded features: JavaScript actions, auto-open triggers, embedded executables, and form submission actions that silently exfiltrate data.

### Step 9 — Zip Extraction
[`unzip_payload.py`](file:///Users/harshita/Desktop/PhishTrap/unzip_payload.py) attempts to unzip any archive attachments using the password extracted by the AI/OCR stage. This mirrors the exact attack chain used in real malware campaigns: attacker sends a password-protected ZIP, hides the password in an image to evade AV scanners, victim extracts manually. PhishTrap replicates this extraction *safely* before sending to the sandbox.

### Step 10 — Sandbox Detonation (UTM Windows VM)
[`detonate.py`](file:///Users/harshita/Desktop/PhishTrap/detonate.py) forwards the extracted `.exe` payload to a **Flask-based detonation agent** running inside an isolated UTM Windows virtual machine at a fixed internal IP. The agent executes the file, records all observable behavior — processes spawned, file system changes, network connections initiated — and returns a structured telemetry JSON. The VM is completely air-gapped from the real network; malware that runs inside it **cannot escape**.

### Step 11 — Scoring & Verdict
[`score_and_report.py`](file:///Users/harshita/Desktop/PhishTrap/score_and_report.py) aggregates all six vector results into a **weighted composite risk score**:

| Vector | Weight |
|--------|--------|
| AI/LLM confidence | 30% |
| Detonation behavior | 25% |
| Link analysis | 20% |
| PDF analysis | 15% |
| Text language | 10% |
| Reputation bump | additive |

**Critical Threat Override**: If any single vector detects a high-confidence threat (malware execution, raw IP link, password-trick), the combined score is forcibly escalated to prevent dilution by clean vectors.

**Final Verdicts:**
| Score | Label | Color |
|-------|-------|-------|
| ≥ 0.70 | 🔴 Malicious | Red |
| 0.30 – 0.69 | 🟠 Suspicious | Orange |
| < 0.30 | ✅ Clean | Green |

### Step 12 — Automated Gmail Response
[`gmail_labels.py`](file:///Users/harshita/Desktop/PhishTrap/gmail_labels.py) applies color-coded Gmail labels (`PhishTrap/🔴 Malicious`, `PhishTrap/🟠 Suspicious`, `PhishTrap/✅ Clean`) to the processed email. If the email was caught in Spam, it is **automatically moved to Inbox under the PhishTrap label** — ensuring flagged emails are always visible in the triaged sidebar, not buried in Spam.

A **private HTML security report note** is injected directly into the email thread, so when an analyst opens the email, they immediately see the verdict, vector breakdown, and a 1-click link to the full dashboard report.

---

## 🖥️ The Dashboard — [`app.py`](file:///Users/harshita/Desktop/PhishTrap/app.py) + [`static/index.html`](file:///Users/harshita/Desktop/PhishTrap/static/index.html)

A **FastAPI** web application served at `http://127.0.0.1:8080` with five tabs:

| Tab | Purpose |
|-----|---------|
| **01 / Upload EML** | Manually upload a `.eml` file for pipeline analysis |
| **02 / Presets** | One-click demo with pre-generated phishing or benign emails |
| **03 / Live Feed** | Real-time WebSocket stream of sandbox detonation telemetry |
| **04 / History** | Persistent log of every email scanned with full report access |
| **05 / Gmail Live Feed** | Real-time view of all emails processed from Gmail monitoring |

Every completed scan writes a full JSON report to the `reports/` directory and an indexed entry to `history.json`, providing a permanent audit trail.

---

## 🛠️ Tech Stack

| Technology | Role |
|-----------|------|
| **Python 3.14** | Core pipeline, all analysis modules |
| **FastAPI + Uvicorn** | Async REST API + WebSocket server for dashboard |
| **Gmail REST API v1** | Email ingestion, label management, thread reply |
| **Google OAuth 2.0** | Secure authentication without storing passwords |
| **Ollama (local LLM)** | On-device AI inference for contextual phishing reasoning |
| **Tesseract OCR** | Image-to-text extraction to catch image-hidden content |
| **UTM Hypervisor** | Type-2 virtualization for isolated Windows sandbox |
| **Flask (Windows VM)** | Lightweight detonation agent API inside the VM |
| **HTML + Vanilla JS** | Zero-dependency SOC dashboard frontend |
| **WebSockets** | Real-time telemetry streaming from sandbox to dashboard |
| **Pillow (PIL)** | Lure image generation for demo email generation |
| **Requests + httplib2** | HTTP communication between pipeline stages and Gmail API |

---

## 🔐 Security Design Principles

1. **Privacy-first AI**: The LLM runs entirely on-device via Ollama. Email content never leaves the machine.
2. **Sandboxed execution**: Payloads are detonated only inside a fully isolated VM. The host machine is never at risk.
3. **OAuth, not passwords**: Gmail access is managed via OAuth 2.0 tokens — revocable, scoped, and never stored in plaintext.
4. **Deduplication**: `gmail_seen.json` ensures no email is processed more than once, preventing feedback loops.
5. **Bot-loop prevention**: The watcher filters its own report note messages to prevent analyzing its own outputs.
6. **Graceful degradation**: Every pipeline stage returns a safe default on failure — one crashed vector does not crash the whole pipeline.

---

## 📂 Key Files

| File | Purpose |
|------|---------|
| [`gmail_watcher.py`](file:///Users/harshita/Desktop/PhishTrap/gmail_watcher.py) | Background daemon — email monitor + full pipeline orchestrator |
| [`app.py`](file:///Users/harshita/Desktop/PhishTrap/app.py) | FastAPI server — dashboard backend, upload API, report storage |
| [`score_and_report.py`](file:///Users/harshita/Desktop/PhishTrap/score_and_report.py) | Multi-vector scoring engine + final verdict logic |
| [`ai_brain.py`](file:///Users/harshita/Desktop/PhishTrap/ai_brain.py) | Ollama LLM interface — password extraction + confidence scoring |
| [`detonate.py`](file:///Users/harshita/Desktop/PhishTrap/detonate.py) | Sandbox detonation client — sends payload to UTM Windows agent |
| [`gmail_labels.py`](file:///Users/harshita/Desktop/PhishTrap/gmail_labels.py) | Gmail action engine — apply labels, unspam, send HTML notes |
| [`link_extract.py`](file:///Users/harshita/Desktop/PhishTrap/link_extract.py) | URL extractor + IP / shortener / lookalike domain scorer |
| [`text_analysis.py`](file:///Users/harshita/Desktop/PhishTrap/text_analysis.py) | NLP-based urgency + credential-request pattern detector |
| [`ocr_extract.py`](file:///Users/harshita/Desktop/PhishTrap/ocr_extract.py) | Tesseract OCR runner for image-embedded text |
| [`pdf_analysis.py`](file:///Users/harshita/Desktop/PhishTrap/pdf_analysis.py) | PDF feature scanner for embedded scripts and auto-triggers |
| [`reputation.py`](file:///Users/harshita/Desktop/PhishTrap/reputation.py) | Sender domain threat intelligence lookup |
| [`parse_eml.py`](file:///Users/harshita/Desktop/PhishTrap/parse_eml.py) | Raw `.eml` byte parser — headers, body, attachments |
| [`generators.py`](file:///Users/harshita/Desktop/PhishTrap/generators.py) | Lure & benign email generator for testing and demos |
| [`generate_lure.py`](file:///Users/harshita/Desktop/PhishTrap/generate_lure.py) | Sends generated phishing lure email via Gmail |
| [`generate_benign.py`](file:///Users/harshita/Desktop/PhishTrap/generate_benign.py) | Sends generated clean email for false-positive testing |
| [`mock_payload_HARMLESS.exe`](file:///Users/harshita/Desktop/PhishTrap/mock_payload_HARMLESS.exe) | Demo payload — drops a `.TXT` file, zero malicious code |
| [`start_watcher.sh`](file:///Users/harshita/Desktop/PhishTrap/start_watcher.sh) | Startup script — kills stale processes, launches dashboard + watcher |
| [`static/index.html`](file:///Users/harshita/Desktop/PhishTrap/static/index.html) | Full SOC dashboard UI — single-page app with 5 tabs |

---

## 💡 What Makes PhishTrap Unique

### 1. Multi-Vector, Not Single-Signal
Every phishing email leaves multiple traces. PhishTrap checks **all of them simultaneously** — links, images, text, PDF structure, attachments, and live runtime behavior. Missing any one vector means missing threats that evade the others.

### 2. Behavioral Truth via Detonation
Static analysis of a file can be spoofed. Signature databases can be evaded. But **you cannot fake behavior** — if a file drops a payload, establishes a network connection, or modifies the registry when it runs, PhishTrap will see it. This is the same technique used by enterprise sandboxing products like Cuckoo Sandbox, ANY.RUN, and Palo Alto Wildfire.

### 3. The OCR + AI Password Chain
Real phishing campaigns today encrypt their malicious ZIP attachments and hide the password in an image attached to the email — specifically to defeat antivirus scanners (which can't open an encrypted file they don't have the password for). PhishTrap replicates this exact attack chain: OCR reads the password from the image, the AI confirms and extracts it, the pipeline unzips the attachment, and the payload goes to the sandbox.

### 4. Closed-Loop Automated Response
Detection alone is not enough. PhishTrap completes the loop: detected emails are **automatically labeled, organized, and annotated** in Gmail with a full analysis report — no human action required until a final review is needed.

### 5. Privacy-First AI on Local Hardware
Using Ollama, the LLM runs entirely on the analyst's own machine. No email content is ever transmitted to OpenAI, Anthropic, or any third-party service. This makes PhishTrap viable in regulated industries (healthcare, finance, legal) where cloud AI processing of sensitive emails is prohibited.

---

## 🎯 Impact Statement

> PhishTrap demonstrates a complete, end-to-end automated threat response cycle — from raw email ingestion, through multi-vector AI-powered analysis and isolated behavioral detonation, to automated classification and in-inbox analyst notification — built entirely from open-source tools on commodity hardware. It compresses what would take a trained SOC analyst 15–30 minutes per email into a fully automated pipeline that completes in under 60 seconds.

---

## 📊 Comparison to Industry Tools

| Capability | PhishTrap | Basic Spam Filter | Cuckoo Sandbox | Commercial SOAR |
|-----------|-----------|------------------|----------------|-----------------|
| Real-time Gmail monitoring | ✅ | ✅ | ❌ | ✅ |
| Behavioral sandbox detonation | ✅ | ❌ | ✅ | ✅ |
| Local on-device AI (no cloud) | ✅ | ❌ | ❌ | ❌ |
| OCR image text extraction | ✅ | ❌ | ❌ | Partial |
| Multi-vector scoring | ✅ | ❌ | Partial | ✅ |
| Automated Gmail labeling | ✅ | ❌ | ❌ | ✅ |
| In-thread analyst report note | ✅ | ❌ | ❌ | Partial |
| Open source / zero cost | ✅ | ❌ | ✅ | ❌ |

---

*Built with Python, FastAPI, Ollama, Tesseract OCR, Gmail API, and UTM Virtualization.*
