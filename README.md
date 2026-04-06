<div align="center">

# 🛡️ LogSentinel Pro v3.0

### Enterprise SIEM Platform — *Security Information & Event Management*

**Pure C++ Qt6 Desktop Application** | C++ Log Engine | Python AI Forensics | Blockchain Audit Ledger

[![C++](https://img.shields.io/badge/C++-17-blue?logo=cplusplus&logoColor=white)](https://isocpp.org/)
[![Qt6](https://img.shields.io/badge/Qt-6.9-green?logo=qt&logoColor=white)](https://www.qt.io/)
[![Python](https://img.shields.io/badge/Python-3.10+-yellow?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-purple)](LICENSE)

---

*A professional, offline-first cybersecurity SIEM desktop application built with a native C++ Qt6 frontend and Python AI backend. Designed for real-time log analysis, threat detection, and forensic investigation with an immutable blockchain audit trail.*

</div>

---

## 📸 Design Reference

The UI follows the **CyberX** cybersecurity platform design language:
- Deep navy dark mode (`#0A0B1E`)
- Electric blue neon accent system
- Custom QPainter risk gauges with glow effects
- Glassmorphic card containers

## 🏗️ Architecture Pipeline

![System Architecture](LogSentinel-Pro/architecture.svg)

The platform perfectly embodies the enterprise SIEM pipeline logic from ingestion to response.

## ✨ Features

| Feature | Technology | Description |
|---------|-----------|-------------|
| **Desktop UI** | C++ Qt6 Widgets | CyberX-inspired dark navy professional interface |
| **Risk Gauge** | Custom QPainter | Circular gauge with neon glow arcs |
| **Stat Cards** | Qt6 QFrame | Glassmorphic event/threat/risk stat cards |
| **Log Parsing** | C++ QRegularExpression | 10+ regex patterns for syslog/auth.log |
| **Detection Engine** | C++ native | MITRE ATT&CK brute force/privesc/injection rules |
| **System Monitor** | /proc filesystem | CPU/RAM/DISK — zero external dependencies |
| **Network Monitor** | /proc/net/tcp | Native TCP connection parser |
| **Live Tracking** | QTimer polling | Real-time log file monitoring every 2s |
| **AI Analysis** | Python QProcess | Gemini 2.0 / OpenAI / Ollama LLM forensic reports |
| **Blockchain** | SHA-256 PoW | Proof-of-Work immutable audit ledger |
| **Report Export** | C++ QTextStream | Professional forensic text reports |
| **Severity Viz** | Custom QPainter | Animated severity distribution bar |

## 📁 Project Structure

```
LogSentinel-Pro/
├── build_and_run.sh              # One-click build & launch
├── .env                          # AI API keys (Gemini/OpenAI)
├── README.md                     # Project documentation
└── src/
    ├── ui/                       # ── C++ Qt6 Frontend ──
    │   ├── mainwindow.h          # Qt6 header (custom widgets + MainWindow)
    │   ├── mainwindow.cpp        # Full C++ implementation (700+ lines)
    │   └── logsentinel.pro       # qmake6 project file
    │
    ├── cpp/                      # ── C++ Shared Library ──
    │   ├── include/log_parser.h  # C FFI header
    │   └── src/log_parser.cpp    # High-speed regex log parser
    │
    └── python/                   # ── Python AI Backend ──
        ├── ai_runner.py          # QProcess entry point for AI
        └── core/
            ├── ai_explainer.py   # Multi-model AI (Gemini/OpenAI/Ollama)
            ├── blockchain.py     # PoW SHA-256 blockchain
            ├── detector.py       # MITRE ATT&CK heuristic engine
            ├── network_monitor.py# psutil network tracking
            └── report_generator.py # Forensic report export
```

## 🚀 Quick Start

### Prerequisites

| Requirement | Install Command |
|------------|----------------|
| Qt6 Dev | `sudo apt install qt6-base-dev` |
| g++ (C++17) | `sudo apt install g++` |
| Python 3.10+ | Pre-installed on most Linux |
| qmake6 | `sudo apt install qt6-base-dev-tools` |

### Build & Run

```bash
git clone https://github.com/Sharingan001/DeadCoderSociety.git
cd DeadCoderSociety/LogSentinel-Pro

# One-click build
chmod +x build_and_run.sh
./build_and_run.sh
```

### Manual Build

```bash
# Compile C++ Qt6 application
cd src/ui && mkdir -p build && cd build
qmake6 ../logsentinel.pro
make -j$(nproc)

# Launch
./logsentinel_pro
```

### AI Configuration (Optional)

Create a `.env` file in the project root:
```env
GEMINI_API_KEY=your_gemini_api_key_here
AI_MODEL=auto
```

## 🎨 Design System

| Token | Hex | Usage |
|-------|-----|-------|
| BG Primary | `#0A0B1E` | Main background |
| BG Sidebar | `#060714` | Navigation panel |
| BG Card | `#111228` | Content cards |
| Border | `#1e2044` | Container borders |
| Accent Blue | `#3b82f6` | Active elements, highlights |
| Accent Cyan | `#06b6d4` | Network/connections |
| Accent Green | `#10b981` | Safe/success states |
| Accent Red | `#ef4444` | Threat indicators |
| Accent Amber | `#f59e0b` | Warning states |
| Accent Purple | `#a855f7` | AI/blockchain elements |

## 🔒 Security Features

### MITRE ATT&CK Coverage

| Technique | ID | Detection |
|-----------|-----|-----------|
| Valid Accounts | T1078 | SSH login monitoring |
| Brute Force | T1110 | 5+ failures from same IP |
| Abuse Elevation | T1548 | sudo/su command detection |
| Command Interpreter | T1059 | Suspicious process execution |
| Network Discovery | T1046 | Port scan / firewall drop detection |
| Exploit Public App | T1190 | SQL injection detection |
| Exfiltration | T1041 | External IP connection tracking |

### Blockchain Integrity

Every suspicious event is cryptographically secured using a **Proof-of-Work SHA-256 blockchain**:
- Configurable mining difficulty
- Immutable audit trail
- Cryptographic chain verification
- JSON ledger export

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| **UI Framework** | Qt6 Widgets (C++) |
| **Custom Rendering** | QPainter (gauges, bars) |
| **Log Engine** | C++ QRegularExpression |
| **System Metrics** | `/proc/stat`, `/proc/meminfo`, `statvfs` |
| **Network Monitoring** | `/proc/net/tcp` |
| **AI Integration** | Google Gemini 2.0 / OpenAI GPT-4o / Ollama |
| **Blockchain** | Python SHA-256 PoW |
| **Build System** | qmake6 + g++ |

## 📊 Evaluation Criteria Alignment

| Criteria | Implementation |
|----------|---------------|
| **Innovation** | C++ Qt6 with custom QPainter gauges, /proc system monitoring, blockchain audit + AI analysis |
| **System Design** | Clean separation: C++ UI ← C++ Core ← Python AI backend via QProcess IPC |
| **Code Quality** | 700+ lines structured C++, proper Qt signals/slots, RAII patterns |
| **Completeness** | Log ingestion, detection, alerting, AI analysis, blockchain, reporting, network monitoring |
| **UX** | Professional CyberX-inspired dark theme, real-time updates, 5-page navigation |

## 👥 Team

**Dead Coder Society**

---

<div align="center">

*Built with ❤️ for cybersecurity*

**LogSentinel Pro** — *Because security logs should never be ignored.*

</div>
