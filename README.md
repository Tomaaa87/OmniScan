# OmniScan — Vulnerability Intelligence Platform

<div align="center">

**A modular network vulnerability scanner with AI-powered analysis, built for security professionals.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20Windows-orange)]()

</div>

---

## Overview

OmniScan is a desktop vulnerability intelligence platform that combines **Nmap port scanning**, **CVE correlation via CIRCL's API**, and **AI-powered analysis via DeepSeek** into a single, modern GUI application. It supports both **Blue Team (defensive/remediation)** and **Red Team (adversary emulation)** operational modes, and generates professional PDF reports.

---

## Features

-  **GUI-Driven Nmap** — 10 built-in scan profiles (SYN scan, full port scan, aggressive scan, UDP, stealth, etc.) with a single click. No terminal commands needed.
-  **NSE Script Integration** — Select from 7 Nmap Scripting Engine categories (`vuln`, `exploit`, `brute`, `auth`, `discovery`, `safe`, `default`) to run targeted vulnerability detection, exploitation, and enumeration scripts against discovered services. NSE outputs are parsed and displayed in the enriched data view.
-  **Custom Nmap Flags (Absolute Override)** — Enter arbitrary Nmap flags to bypass the scan profile, custom ports, and NSE selector entirely. Full control for power users with built-in shell metacharacter sanitization.
-  **Assume Online (`-Pn`) Toggle** — Treat all hosts as online, bypassing host discovery. Toggle it on/off without changing your scan profile.
-  **Custom Ports** — Override or extend any scan profile's port range with custom values.
-  **Auto-Detect Network** — One-click detection of your local subnet (`/24`) and automatic scanning of all hosts.
-  **Live CVE Correlation** — Each discovered service is cross-referenced against the CIRCL vulnerability database (NVD 5.2 format). Results are **cached locally in SQLite** to avoid API rate limits on repeat scans.
-  **Dual-Mode AI Analysis** — Toggle between:
  -  **Blue Team Mode** — Root-cause analysis, risk context, and actionable remediation steps (bash commands, firewall rules, config changes).
  -  **Red Team Mode** — Exploit feasibility, PoC availability, MITRE ATT&CK mapping, OWASP classification, and PTES/WSTG methodology references.
-  **PDF Export** — Generate polished, professional vulnerability intelligence reports with a single click.
-  **Scan History** — All past scans are archived in a local SQLite database. Load, review, and re-analyze any historical scan at any time.
-  **Re-Analyze Button** — Re-run AI analysis on stored scan data after switching between Blue/Red Team modes — no need to re-scan.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    OmniScan GUI (CustomTkinter)          │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │  Scanner  │  │ CVE      │  │   AI     │  │  PDF    │ │
│  │ (python-  │──│ Mapper   │──│ Engine   │──│ Export  │ │
│  │  nmap +   │  │ (CIRCL)  │  │(DeepSeek)│  │ (fpdf2) │ │
│  │   NSE)    │  └────┬─────┘  └──────────┘  └─────────┘ │
│  └──────────┘       │                                    │
│                     │                                    │
│              ┌──────▼──────┐                             │
│              │  SQLite DB  │                             │
│              │ (scan hist  │                             │
│              │  + CVE cache)│                            │
│              └─────────────┘                             │
└──────────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Dependency | Why |
|---|---|
| **Python 3.10+** | Required by CustomTkinter and async features |
| **Nmap** | The actual port scanner (called via `python-nmap`) |
| **DejaVu Fonts** | Needed for Unicode PDF rendering |
| **DeepSeek API Key** | Powers the AI analysis engine |

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
| **Initiate Scan** | Starts the full pipeline (Nmap → CVE → AI) |
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

## Caching & Database

OmniScan uses SQLite (`data/omniscan.db`) with two tables:

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

## Project Structure

```
ommiscan/
├── README.md                  ← You are here
├── requirments.txt            ← Python dependencies
├── .gitignore                 ← Excludes .env, venv, *.db, __pycache__
├── .env                       ← DeepSeek API key (gitignored — create your own)
├── data/                      ← SQLite database (gitignored)
├── reports/                   ← Exported PDF reports (gitignored)
├── zapush.txt                 ← Development notes
├── zarun.txt                  ← Development notes
└── src/
    ├── main.py                ← CustomTkinter GUI & pipeline orchestrator
    ├── scanner.py             ← Async Nmap wrapper (python-nmap)
    ├── cve_mapper.py          ← CIRCL API client + CVE enrichment logic
    ├── ai_engine.py           ← DeepSeek API client (Blue/Red Team prompts)
    ├── database.py            ← SQLite manager (scan history + CVE cache)
    └── export.py              ← PDF report generator (fpdf2)
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
