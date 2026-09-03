# MalwSentinel 🛡️
### Autonomous Tier-2 SOC Malware Triage & Threat Intelligence Agent

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Framework: Starlette](https://img.shields.io/badge/Framework-Starlette%20ASGI-green.svg)](https://www.starlette.io/)
[![Deployment: Vercel](https://img.shields.io/badge/Deployment-Vercel%20Serverless-black.svg)](https://malwsentinel.vercel.app)
[![Containment: Antigravity Guardrails](https://img.shields.io/badge/Guardrails-Active%20Containment-red.svg)](https://github.com/gangadharsai27/malwsentinel)

**Live Demo:** [https://malwsentinel.vercel.app](https://malwsentinel.vercel.app)  
**Localhost Console:** `http://localhost:8000`

---

## 📌 Executive Overview

**MalwSentinel** is a production-grade, containerized Tier-2 Security Operations Center (SOC) agent designed for automated, zero-trust static malware triage and threat intelligence synthesis.

Traditional Tier-1 SOC analysts face acute alert fatigue, often taking 30–60 minutes per sample to manually calculate entropy, parse PE headers, decode obfuscated strings, correlate IoCs, map MITRE ATT&CK techniques, and draft remediation advisories. Furthermore, handling live malware carries catastrophic risks of accidental execution.

**MalwSentinel automates the entire static triage lifecycle in seconds under active containment**, generating high-fidelity forensic reports, YARA detection rules, and STIX 2.1 JSON bundles powered by your choice of AI engine (**Google Gemini**, **LM Studio Local Offline**, or **OpenRouter Free Models**).

---

## 🚀 Key Features

### 1. 🔒 Active Containment & Policy Guardrails
- **Pre-execution Interception**: Enforces a strict security policy hook (`prevent_execution_hook`) that intercepts and denies all dynamic execution vectors (e.g., `cmd.exe`, `powershell.exe`, `os.system`, process spawning, memory manipulation).
- **Authorized Static Toolset**: Safely allows non-invasive analysis primitives (cryptographic hashing, PE structure parsing, Shannon entropy calculation, IoC pattern matching).
- **Audit Logging**: Every tool invocation is logged into an immutable policy audit trail showing tool status, evaluation timestamp, and containment rationale.
- **Violation Simulator**: Integrated visual simulator demonstrating real-time policy blocking of unauthorized command attempts.

### 2. 🔬 Deep Static Forensics Pipeline
- **Cryptographic Fingerprints**: Calculates MD5 and SHA-256 hashes for immediate threat database correlation.
- **Shannon Byte Entropy Analysis**: Measures randomness across 256-byte frequency distributions ($0.0000 - 8.0000$), detecting packed, encrypted, or obfuscated payloads (UPX, ASPack, Custom crypters).
- **PE Header & Section Decomposition**: Uses `pefile` to parse DOS headers, section names (`.text`, `.rdata`, `.data`), virtual sizes, raw data offsets, and section-level entropy.
- **Suspicious Win32 API Inspection**: Flags critical injection primitives (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`), execution APIs (`ShellExecuteW`, `WinExec`), and anti-debugging tricks (`GetTickCount`, `IsDebuggerPresent`).
- **Regex Byte-Stream IoC Extraction**: Extracts embedded IPv4 addresses, command-and-control (C2) URLs, and persistence registry keys (`HKLM\...\Run`).

### 3. 🧠 Multi-Provider AI Intelligence Engines
MalwSentinel features a pluggable, unified AI synthesis engine supporting 3 primary options:

| Engine | Deployment | Requirements | Description |
| :--- | :--- | :--- | :--- |
| **🟢 Google Gemini** | Cloud API | `GEMINI_API_KEY` | High-speed multimodal intelligence via Google Antigravity / Gemini SDK. |
| **💻 LM Studio** | Local Offline | **No API Key** | 100% private offline inference (`localhost:1234`) with automatic model auto-discovery (e.g., `prism-ml/bonsai-27b`, `qwen/qwen3-8b`, `google/gemma-4`). |
| **🚀 OpenRouter** | Cloud (Free) | Free API Key | Access to free-tier cloud models (`minimax/minimax-m3:free`, `nvidia/nemotron-3.5-lightning:free`) with built-in **403/404/429 auto-recovery**. |

### 4. 📑 Instant Threat Intelligence Deliverables
- **Executive SOC Report**: Professional markdown report with Executive Summary, Forensic Evidence, Risk Rating, and Recommended SOC Actions.
- **Auto-Generated YARA Detection Rules**: Ready-to-deploy rules with file metadata, identified hash indicators, and byte strings.
- **STIX 2.1 Threat Intel Bundle**: Standards-compliant JSON bundle containing Malware, Indicator, and Relationship objects for ingestion into MISP, OpenCTI, or enterprise SIEMs.
- **MITRE ATT&CK Matrix Mapping**: Automated mapping of static evidence to official ATT&CK techniques (e.g., T1055 Process Injection, T1106 Native API, T1082 System Info Discovery).

---

## 🏛️ System Architecture

```
                                +---------------------------------------------+
                                |             MalwSentinel Web UI             |
                                |     (Dark SOC Glassmorphic Dashboard)       |
                                +---------------------------------------------+
                                                       |
                                            POST /api/analyze (Sample)
                                                       v
+---------------------------------------------------------------------------------------------------------+
|                                    ACTIVE CONTAINMENT GUARDRAILS                                        |
|                          prevent_execution_hook(action) -> ALLOW / DENY                                 |
+---------------------------------------------------------------------------------------------------------+
                                                       |
                        +------------------------------+------------------------------+
                        |                                                             |
                        v                                                             v
        [ Authorized Static Forensics ]                               [ Blocked Dynamic Actions ]
        - SHA-256 / MD5 Hashers                                       - Shell execution (DENIED)
        - Shannon Entropy Scanner                                     - Memory injection (DENIED)
        - PE Header & Import Parser                                   - Process spawning (DENIED)
        - Byte-Stream IoC Extractor                                   - Logged to Policy Audit Trail
                        |
                        v
+---------------------------------------------------------------------------------------------------------+
|                                      UNIFIED AI REASONING ENGINE                                        |
|                                    (UnifiedTriageAgent Dispatcher)                                      |
+---------------------------------------------------------------------------------------------------------+
         |                                             |                                             |
         v                                             v                                             v
  [ Google Gemini ]                         [ LM Studio (Local) ]                         [ OpenRouter ]
  - Antigravity SDK                         - http://localhost:1234                       - https://openrouter.ai
  - Cloud reasoning                         - Zero data exfiltration                      - Free tier models
                                            - Auto-detects loaded model                   - 403 Auto-recovery
         |                                             |                                             |
         +---------------------------------------------+---------------------------------------------+
                                                       |
                                                       v
+---------------------------------------------------------------------------------------------------------+
|                                      ACTIONABLE SOC DELIVERABLES                                        |
|       - Executive Report (MD)          - Auto YARA Rules          - STIX 2.1 JSON Bundle                |
|       - MITRE ATT&CK Mapping           - Containment Audit Log    - Memory Heuristics Dial              |
+---------------------------------------------------------------------------------------------------------+
```

---

## 💻 Installation & Localhost Setup

### Prerequisites
- **Python 3.10** or higher
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/gangadharsai27/malwsentinel.git
cd malwsentinel
```

### 2. Create and Activate a Virtual Environment
**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Create or edit your [`.env`](.env) file in the root directory:
```env
# Google Gemini API Key (Optional)
GEMINI_API_KEY=your_gemini_api_key_here

# OpenRouter API Key (Optional - get free at https://openrouter.ai/keys)
OPENROUTER_API_KEY=sk-or-v1-your_key_here

# LM Studio requires NO API key! (Runs locally on port 1234)
```

### 5. Start the Local Server
```bash
python server.py
```
Open your browser and navigate to **`http://localhost:8000`**.

---

## 💻 Using with LM Studio (Local Offline Inference)

MalwSentinel natively integrates with **LM Studio** for 100% offline static malware analysis:

1. Download and install [LM Studio](https://lmstudio.ai/).
2. Load any model of your choice (e.g., `qwen/qwen3-8b`, `google/gemma-4`, or `prism-ml/bonsai-27b`).
3. Start the local server inside LM Studio on port `1234` (ensure Token Mode is disabled in settings).
4. In the MalwSentinel web console, click **"AI Engine"** in the top bar:
   - **Provider**: `💻 LM Studio (Local - localhost:1234)`
   - **Base URL**: `http://127.0.0.1:1234/v1`
   - **Model**: `local-model` *(Auto-detects loaded model)*
   - **API Key**: *(Leave blank)*
5. Click **"Run Static Triage"** — your local model generates the threat intelligence report with zero network transmission!

---

## 🚀 Using with OpenRouter (Free Tier)

MalwSentinel supports OpenRouter's free model collection:

1. Obtain a free key from **[openrouter.ai/keys](https://openrouter.ai/keys)**.
2. In the MalwSentinel console, click **"AI Engine"** and select **`🚀 OpenRouter (Free Models)`**.
3. Paste your key and choose your preferred model:
   - `minimax/minimax-m3:free` *(Default — verified fast & reliable)*
   - `nvidia/nemotron-3.5-lightning:free`
   - `liquid/lfm-2.5-2.6b:free`
   - `nvidia/nemotron-3-ultra-550b-a55b:free`
4. **Built-in Auto-Recovery**: If any selected model encounters rate limits (`429`), restrictions (`403`), or downtime (`404`), MalwSentinel seamlessly auto-recovers to `minimax/minimax-m3:free`.

---

## 🌐 Deploying to Vercel

MalwSentinel is architected to deploy directly to Vercel Serverless:

1. **Fork or Push** the repository to your GitHub account.
2. Go to **[vercel.com](https://vercel.com/)** and import your `malwsentinel` repository.
3. Configure the following build settings:
   - **Framework Preset**: Other
   - **Root Directory**: `./`
4. Add Environment Variables (optional, can also be configured directly in browser localStorage):
   - `OPENROUTER_API_KEY`
   - `GEMINI_API_KEY`
5. Click **Deploy**. Your instance will be live at `https://<your-project>.vercel.app`.

---

## 📡 API Endpoints Reference

| Method | Endpoint | Description | Request Parameters |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/providers` | Lists available AI providers, configuration status, and default models. | None |
| `GET` | `/api/presets` | Retrieves available demonstration binaries (simulated backdoor, clean calc). | None |
| `POST` | `/api/analyze` | Executes full static triage, policy evaluation, and AI threat report synthesis. | Form-data: `file` (Upload) OR `preset_path` (Path), `provider`, `model`, `api_key` |
| `POST` | `/api/test-violation` | Triggers containment policy intercept to demonstrate real-time blocking. | JSON: `action` (e.g. `{"tool_name": "run_command"}`) |

---

## 📁 Repository Structure

```
malwsentinel/
├── api/
│   └── index.py                    # Vercel serverless ASGI entrypoint
├── public/                         # Edge CDN static distribution for Vercel
│   ├── index.html
│   └── static/
│       ├── app.js
│       └── style.css
├── static/                         # Local development static assets
│   ├── index.html
│   ├── app.js
│   └── style.css
├── llm_engine.py                   # Multi-provider AI engine (Gemini, LM Studio, OpenRouter)
├── malware_triage_agent.py         # Static forensics primitives & policy containment hooks
├── server.py                       # Core Starlette ASGI web application
├── suspicious_sample.exe           # Staged demonstration PE binary (contained)
├── requirements.txt                # Python dependencies (starlette, pefile, etc.)
├── vercel.json                     # Vercel serverless routing configuration
├── .env.example                    # Environment variable template
└── README.md                       # Comprehensive documentation
```

---

## 🛡️ Responsible Disclosure & Safety Policy

> [!IMPORTANT]
> **Defensive Containment Notice:**
> MalwSentinel is developed strictly for defensive cybersecurity analysis, threat research, and educational triage. All sample inspections are executed statically without invoking binary code. Dynamic process spawning and system modifications are blocked by active guardrail hooks. Always execute malware analysis inside isolated sandbox environments.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
