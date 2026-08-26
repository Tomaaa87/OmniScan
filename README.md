# OmniScan — Vulnerability Intelligence Platform

<div align="center">

**A modular network vulnerability scanner with AI-powered analysis, built for security professionals.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20Windows-orange)]()

</div>

---

## Overview

OmniScan is a desktop application that brings professional-grade vulnerability intelligence to your fingertips. It combines two analysis modes in one modern, dark-themed interface:

1. **🌐 Network Security Analysis** — scan hosts and networks with **Nmap**, correlate discovered services with **known CVEs**, and get **AI-powered analysis** that explains risks and next steps.
2. **📁 Codebase Security Analysis (SAST)** — point OmniScan at a local project or source file and it audits the code for vulnerabilities, maps findings to **OWASP/CWE**, and suggests **secure refactorings** — all powered by DeepSeek.

Every analysis can run in **Blue Team** (defensive/remediation) or **Red Team** (adversary emulation) mode, and both modes produce professional **PDF reports**.

---

## Features

-  **GUI-Driven Nmap** — 10 built-in scan profiles (SYN scan, full port scan, aggressive scan, UDP, stealth, etc.) with a single click. No terminal commands needed.
-  **NSE Script Integration** — Select from 7 Nmap Scripting Engine categories (`vuln`, `exploit`, `brute`, `auth`, `discovery`, `safe`, `default`) to run targeted vulnerability detection, exploitation, and enumeration scripts against discovered services. NSE outputs are parsed and displayed in the enriched data view.
-  **Custom Nmap Flags (Absolute Override)** — Enter arbitrary Nmap flags to take full manual control, overriding the scan profile, ports, and NSE selector — with safety checks built in.
-  **Assume Online (`-Pn`) Toggle** — Treat all hosts as online, bypassing host discovery. Toggle it on/off without changing your scan profile.
-  **Custom Ports** — Override or extend any scan profile's port range with custom values.
-  **Auto-Detect Network** — One-click detection of your local subnet (`/24`) and automatic scanning of all hosts.
-  **Live CVE Correlation** — Every discovered service is checked against the CIRCL vulnerability database for known CVEs. Results are **cached locally** so repeat scans stay fast.
-  **Dual-Mode AI Analysis** — Toggle between:
  -  **Blue Team Mode** — Root-cause analysis, risk context, and actionable remediation steps (bash commands, firewall rules, config changes).
  -  **Red Team Mode** — Exploit feasibility, PoC availability, MITRE ATT&CK mapping, OWASP classification, and PTES/WSTG methodology references.
-  **PDF Export** — Generate polished, professional vulnerability intelligence reports with a single click.
-  **Scan History** — Every scan is saved on your machine. Load, review, and re-analyze any past scan at any time.
-  **Re-Analyze Button** — Re-run the AI analysis on any saved scan after switching between Blue/Red Team modes — no need to scan again.
-  **Landing Hero Screen** — On launch you get two interactive cards: **Network Security Analysis** and **Codebase Security Analysis**, with a persistent top navigation bar for one-click mode switching.
-  **Codebase Security Analysis (SAST)** — A dedicated static-code auditor:
  -  **Target Selector** — Pick a folder or a single source file via native file dialogs.
  -  **Recursive Source Discovery** — Walks your project while automatically skipping non-code directories (`.git`, `node_modules`, `venv`, `__pycache__`, `build`, `dist`).
  -  **13 Language Support** — Parses `.py`, `.js`, `.ts`, `.php`, `.java`, `.cpp`, `.c`, `.cs`, `.go`, `.html`, `.sql`, `.kt`, and `.sh`.
  -  **File Inspector** — Visual list of every discovered source file with line counts and truncation markers.
  -  **Built-in Code Viewer** — Click any file in the File Inspector to open its full source directly inside the app — no IDE required. A dedicated **Code Viewer** tab sits alongside the AI report.
  -  **Smart File Handling** — Large files are trimmed automatically so the AI can analyze the whole project efficiently.
  -  **DeepSeek SAST Specialist** — Severity matrix (Critical/High/Medium/Low), exact file & line identification, OWASP Top 10 + CWE mapping, and secure-refactoring diffs.
  -  **Red Team SAST Mode** — Adds exploitability vectors, bypass techniques, and attack-chain feasibility.
  -  **Codebase PDF Export** — Generate a professional SAST report (target, code summary, file inventory, and AI findings) with one click.

---

## How OmniScan Works

OmniScan's interface is built around three views — **Home**, **Network Security Analysis**, and **Codebase Security Analysis** — all connected by a persistent top navigation bar, so you can switch modes at any time.

### What Happens in Each Analysis

**Network analysis:**
1. OmniScan runs an **Nmap** scan (with optional **NSE scripts**) against your target.
2. Discovered services are matched against the **CIRCL vulnerability database** to surface known CVEs.
3. **DeepSeek** analyzes the results in your chosen Blue or Red Team mode.
4. Results are saved locally and can be exported as a **PDF report**.

**Codebase (SAST) analysis:**
1. Point OmniScan at a **folder** or a **single source file**.
2. OmniScan discovers the source files and lets you **preview them in-app**.
3. A **DeepSeek SAST specialist** audits the code for vulnerabilities and maps findings to OWASP/CWE.
4. Review the findings and export a professional **PDF report**.

---

## Prerequisites

| Requirement | What It's For |
|---|---|
| **Python 3.10+** | The runtime OmniScan runs on |
| **Nmap** | Performs the actual port scanning |
| **DejaVu Fonts** | Needed to render PDF reports (Linux) |
| **DeepSeek API Key** | Powers the AI analysis |

### System Packages (Debian/Ubuntu/Kali)

```bash
sudo apt update
sudo apt install nmap fonts-dejavu-core python3 python3-pip python3-venv -y
```

### System Packages (Arch)

```bash
sudo pacman -S nmap ttf-dejavu python python-pip
```

### System Packages (Fedora)

```bash
sudo dnf install nmap dejavu-sans-fonts dejavu-sans-mono-fonts python3 python3-pip -y
```

### System Packages (Windows)

1. Install **Python 3.10+** from [python.org](https://www.python.org/downloads/) — tick **"Add Python to PATH"** during installation.
2. Install **Nmap** from [nmap.org](https://nmap.org/download.html) using the official Windows installer.
   - During installation, keep the default path (`C:\Program Files (x86)\Nmap`) — OmniScan auto-detects it.
   - The installer bundles **Npcap** — leave it enabled. It is required for raw-socket scans.
3. (Optional) Add `C:\Program Files (x86)\Nmap` to your `PATH` if you want to run `nmap` from the terminal directly.

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/ommiscan.git
cd ommiscan
```

### 2. Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate    # Linux/macOS
```

Windows (PowerShell):

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Python Dependencies

```bash
pip install -r requirments.txt
```

### 4. Configure the DeepSeek API Key

Create a `.env` file in the project root:

```bash
echo 'DEEPSEEK_API_KEY=sk-your-deepseek-api-key-here' > .env
```

Windows (PowerShell):

```powershell
Set-Content -Path .env -Value 'DEEPSEEK_API_KEY=sk-your-deepseek-api-key-here'
```

>  Get your API key at [platform.deepseek.com](https://platform.deepseek.com/).  
>  The `.env` file is already in `.gitignore` — it will **never** be committed to the repository.

### 5. Launch OmniScan

```bash
python src/main.py
```

Windows (PowerShell) — for SYN/raw-socket scans, open **PowerShell as Administrator** first:

```powershell
.\venv\Scripts\python.exe src\main.py
```

---

## Usage Guide

### Landing Screen & Navigation

On launch, OmniScan presents a **hero landing screen** with two interactive cards:

| Card | What It Does |
|---|---|
| **🌐 Network Security Analysis** | Scan hosts, map CVEs, and get AI-driven analysis of your network. |
| **📁 Codebase Security Analysis** | Audit your source code for vulnerabilities with AI-powered analysis. |

A **persistent navigation header** stays at the top of every view, letting you jump between **Home**, **Network Security Analysis**, and **Codebase Security Analysis** at any time — without resetting active scan or analysis state.

### The Sidebar (Left Panel)

| Element | Purpose |
|---|---|
| **Target IP** | Enter a single IP (`192.168.1.50`) or a CIDR range (`192.168.1.0/24`) |
| **Scan Current Network** | Auto-detects your local `/24` subnet and populates the target field |
| **Scan Profile** | Choose from 10 predefined Nmap scan strategies |
| **Custom Ports** | Override ports (e.g., `80,443` or `1-1000`) |
| **NSE Scripts Category** | Select an NSE category to run (`vuln`, `exploit`, `brute`, `auth`, `discovery`, `safe`, `default`) |
| **Custom Nmap Flags** | Enter arbitrary flags to bypass the profile/NSE/ports selectors entirely (absolute override) |
| **Assume Online (-Pn)** | Toggle ON to skip host discovery (treat all hosts as alive) |
| **Initiate Scan** | Runs the complete scan — Nmap, CVE lookup, and AI analysis |
| **Blue/Red Team Switch** | Toggle between defensive and offensive analysis modes |
| **Re-analyze with AI** | Re-runs only the AI phase on stored scan data with the current mode |
| **Generate PDF Report** | Exports a professional PDF (enabled after scan completes) |
| **Scan History** | Dropdown to load, review, and re-analyze any past scan |

### Scan Workflow

1. Enter a target IP or click **"Scan Current Network"**.
2. Select a scan profile from the dropdown (default: *Service Detection*).
3. Optionally specify custom ports, choose an NSE script category, or enter custom Nmap flags.
4. Toggle **"Assume Online (-Pn)"** if needed.
5. Click **"Initiate Scan"**.
6. Watch the progress in the **Terminal Logs** tab.
7. Review enriched CVE data (including NSE script outputs) in the **Enriched Data (CVEs)** tab.
8. Read the AI analysis in the **AI Intelligence** tab.
9. Switch between Blue/Red Team modes and click **"Re-analyze with AI"** for a different perspective.
10. Click **"Generate PDF Report"** to export your findings.

### Scan Profiles

| Profile | Nmap Flags | Best For |
|---|---|---|
| Ping Sweep | `-sn` | Host discovery only (no port scan) |
| Quick Scan | `-F -T4` | Fast top-100 port scan |
| Standard SYN Scan | `-sS -T4` | Stealthy TCP SYN scan |
| **Service Detection** | **`-sS -sV -T4`** | **Default — detects service versions** |
| Full Port Scan | `-p- -T4` | All 65,535 TCP ports |
| Aggressive Scan | `-A -T4` | OS detection + version + scripts |
| UDP Quick Scan | `-sU -F -T4` | Fast UDP port scan |
| Intense Scan, No Ping | `-Pn -A -T4` | Aggressive, skips host discovery |
| Top 100 Ports | `--top-ports 100 -T4` | Targets the 100 most common ports |
| Stealth SYN | `-sS -T4 -f` | Fragment packets to evade firewalls |

### NSE Script Categories

| Category | Nmap Flag | What It Does |
|---|---|---|
| **None** | *(no scripts)* | No NSE scripts run — fastest scan |
| **default** | `--script=default` | Safe, informational scripts (Nmap's default set) |
| **vuln** | `--script=vuln` | Vulnerability detection — checks for known CVEs directly |
| **exploit** | `--script=exploit` | Active exploitation scripts — attempts to compromise services |
| **auth** | `--script=auth` | Authentication bypass and credential testing |
| **brute** | `--script=brute` | Brute-force credential attacks against services |
| **discovery** | `--script=discovery` | Network and service enumeration beyond port scanning |
| **safe** | `--script=safe` | Non-intrusive scripts that won't crash services |

> ⚠️ **Warning:** The `exploit` and `brute` categories are actively intrusive and may crash services, trigger IDS/IPS alerts, or lock accounts. Only use against systems you are explicitly authorized to test.

### Custom Nmap Flags (Absolute Override)

When the **Custom Nmap Flags** field is non-empty, it **completely replaces** the scan profile, custom ports, and NSE category selection. This gives you full control for advanced use cases:

```
# Example: combine multiple NSE scripts with version detection and a specific port range
-sS -sV -p 1-1000 --script=http-enum,ssl-enum-ciphers,ssh-auth-methods
```

>  Shell metacharacters (`;`, `|`, `&`, `` ` ``, `$`, etc.) are blocked for security. Only valid Nmap flag syntax is accepted.

---

### Codebase Security Analysis (SAST)

The **Codebase Security Analysis** view audits your source code for security weaknesses, powered by a DeepSeek *Senior Application Security Auditor*.

**Interface layout:**

| Element | Purpose |
|---|---|
| **Target Selector** | Browse a **folder** or a **single file** with native file dialogs; the selected path appears in the text box |
| **File Inspector** | Visual list of every discovered source file with relative path, line count, and a ✂ marker when a file was truncated — **click any entry to open its full source in the Code Viewer** |
| **Start Analysis** | Begins the AI-powered security audit of your code |
| **Export PDF** | Saves a professional codebase security report — target, code summary, file inventory, and AI findings (enabled after analysis completes) |
| **Blue/Red Team Switch** | Toggles between defensive SAST and adversary-emulation SAST output |
| **Output Viewer** | Two read-only tabs — **AI Report** (Markdown findings) and **Code Viewer** (full source of the selected file) — highlight and copy allowed, editing blocked |

**Codebase analysis workflow:**

1. Click **"📂 Browse Folder"** (or **"📄 Browse File"** for a single source file).
2. Review the discovered files in the **File Inspector**.
3. Click any file in the **File Inspector** to open its full source in the **Code Viewer** tab — review code without leaving OmniScan.
4. Optionally toggle **🔴 Red Team Mode**.
5. Click **"Start Analysis"** — a progress bar appears while the AI audits your code.
6. Read the report in the **AI Report** tab: a **severity matrix**, **file & line identifications**, **OWASP Top 10 + CWE mappings**, and **secure-refactoring diffs** (plus exploitability/attack-chain analysis in Red Team mode).
7. Click **"Export PDF"** to save a professional report containing the target, code summary, file inventory, and AI findings.

**Supported languages:** Python (`.py`), JavaScript (`.js`), TypeScript (`.ts`), PHP (`.php`), Java (`.java`), C++ (`.cpp`), C (`.c`), C# (`.cs`), Go (`.go`), HTML (`.html`), SQL (`.sql`), Kotlin (`.kt`), and Shell (`.sh`).

**Auto-ignored directories:** `.git`, `node_modules`, `venv`, `__pycache__`, `build`, and `dist` are skipped automatically, so dependency and build folders never slow down or clutter your analysis.

**Large-project safety:** very large files are trimmed automatically so the analysis stays fast and within limits, while still covering the files that matter.

---

## Your Data Stays Local

OmniScan stores everything on your own machine in a small SQLite database (`data/omniscan.db`). The only data sent over the internet is the target or code you choose to submit for AI analysis. Two kinds of records are kept:

### `cve_cache` — Product-Level CVE Cache

| Column | Description |
|---|---|
| `vendor_product` (PK) | CPE-style product key (e.g., `apache/http_server`) |
| `cve_data` | JSON blob of CVE IDs and summaries |
| `last_updated` | Cache timestamp |

- **Cache hit**: Returns stored CVEs instantly — zero API calls.
- **Cache miss**: Fetches from CIRCL API, then stores locally with `INSERT OR REPLACE`.
- The same product across different IPs or scans hits the **same** cache entry.

### `scan_history` — Append-Only Scan Log

| Column | Description |
|---|---|
| `id` (PK, auto-increment) | Unique scan ID |
| `target_ip` | The scanned IP or CIDR range |
| `scan_date` | Completion timestamp |
| `raw_data` | JSON blob of parsed Nmap results + CVE enrichment |
| `ai_report` | Full DeepSeek AI analysis text |

- Every scan creates a **new row** — no deduplication.
- The history dropdown lists all scans, newest first.
- Loading a historical scan restores the full data and AI report into the UI.

---

## Project Layout (for contributors)

```
ommiscan/
├── README.md                  ← This file
├── requirments.txt            ← Python dependencies
├── .gitignore                 ← Excludes .env, venv, *.db, __pycache__
├── .env                       ← Your DeepSeek API key (never committed)
├── data/                      ← Local SQLite database
├── reports/                   ← Exported PDF reports
└── src/
    ├── main.py                ← Application interface (Home, Network, Codebase views)
    ├── scanner.py             ← Nmap scanning
    ├── cve_mapper.py          ← CVE lookup & enrichment
    ├── ai_engine.py           ← DeepSeek integration (Blue/Red Team)
    ├── code_analyzer.py       ← Source-code discovery for SAST
    ├── database.py            ← Local data storage
    └── export.py              ← PDF report generation
```

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `python-nmap` | 0.7.1 | Python bindings for Nmap |
| `requests` | 2.32.3 | HTTP client for the CIRCL CVE API |
| `customtkinter` | 5.2.2 | Modern dark-themed GUI toolkit |
| `python-dotenv` | 1.0.1 | Load API keys from `.env` file |
| `openai` | 1.50.0 | DeepSeek API client (OpenAI-compatible SDK) |
| `httpx` | 0.27.2 | HTTP transport used by the OpenAI SDK (pinned for compatibility) |
| `fpdf2` | 2.8.7 | PDF report generation |

---

## Troubleshooting

### "Nmap not found" or scan fails immediately

OmniScan auto-detects Nmap in common locations (including `C:\Program Files (x86)\Nmap\nmap.exe` on Windows).

**Linux:**
```bash
which nmap
sudo apt install nmap -y       # Debian/Ubuntu/Kali
```

**Windows:** make sure Nmap is installed to the default location (`C:\Program Files (x86)\Nmap`). If you installed it elsewhere, add that folder to your `PATH` (OmniScan checks `PATH` too via `nmap.exe`).

### "DEEPSEEK_API_KEY environment variable is missing"

Create a `.env` file in the project root with your API key:
```bash
echo 'DEEPSEEK_API_KEY=sk-...' > .env        # Linux/macOS
Set-Content -Path .env -Value 'DEEPSEEK_API_KEY=sk-...'   # Windows PowerShell
```

### PDF export fails with font error

Install the DejaVu font package (Linux):
```bash
sudo apt install fonts-dejavu-core -y
```

### "No module named 'customtkinter'" (or any other module)

Ensure you're in the virtual environment:
```bash
source venv/bin/activate           # Linux/macOS
.\venv\Scripts\Activate.ps1        # Windows PowerShell
pip install -r requirments.txt
```

### `TypeError: Client.__init__() got an unexpected keyword argument 'proxies'`

The `openai` SDK (`1.50.0`) is incompatible with `httpx >= 0.28`. Pin the compatible version:
```bash
pip install httpx==0.27.2
```

### Permission errors when scanning (Linux)

Nmap requires raw socket privileges. Either:
- Run as root: `sudo python src/main.py` (not recommended)
- Or use `sudo setcap cap_net_raw+ep /usr/bin/nmap` to grant Nmap raw socket access without root.

### Permission errors / "winpcap is required" (Windows)

- Run OmniScan from **PowerShell as Administrator** for SYN (`-sS`) and UDP scans, which need raw sockets.
- If Nmap reports it cannot open devices or find Npcap, re-run the Nmap installer and make sure **Npcap** is installed (it's bundled by default).
- Basic TCP connect scans (`-sT`) do **not** require elevation.

---

## Security Notes

-  OmniScan runs Nmap **locally** — all scan data stays on your machine.
-  The `.env` file with your API key is excluded from Git via `.gitignore`.
-  CVE lookups are sent to **CIRCL** (`vulnerability.circl.lu`) — a trusted, open-source vulnerability database operated by CERT Luxembourg.
-  AI analysis is sent to **DeepSeek** — review their [privacy policy](https://platform.deepseek.com/) before use.
-  Codebase (SAST) analysis uploads **source-code snippets** to DeepSeek for analysis. Never scan proprietary code you are not authorized to share with third-party services.
-  The SQLite database and PDF reports are stored locally and excluded from version control.

---

## Disclaimer

> OmniScan is intended for **authorized security assessments only**. Always obtain explicit written permission before scanning any network or system you do not own. Unauthorized port scanning may violate laws and regulations. The authors assume no liability for misuse.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

<div align="center">
Made with  for the security community
</div>
