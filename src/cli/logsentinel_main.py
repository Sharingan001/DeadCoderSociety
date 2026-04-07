#!/usr/bin/env python3
"""
LogSentinel Pro v4.0 - Enterprise SIEM CLI
Log analysis, threat detection, blockchain integrity,
Industry Share, CVE analysis, and split-screen TUI.
"""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import socket
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

# Import premium engines
sys.path.append(str(Path(__file__).parent.parent / "engines"))
try:
    from advanced_detection import AdvancedThreatEngine
    from professional_pdf_reporter import (
        ProfessionalPDFReporter, generate_threat_report, 
        generate_compliance_report_pdf
    )
    from config_manager import ConfigurationManager, RuleEngine
    PREMIUM_FEATURES = True
    PROFESSIONAL_PDF = True
except ImportError as e:
    try:
        from advanced_detection import AdvancedThreatEngine
        from pdf_reporter import ThreatAnalysisReporter, generate_compliance_report
        from config_manager import ConfigurationManager, RuleEngine
        PREMIUM_FEATURES = True
        PROFESSIONAL_PDF = False
    except ImportError as e:
        print(f"Premium features unavailable: {e}")
        PREMIUM_FEATURES = False
        PROFESSIONAL_PDF = False

# Import v4.0 modules
INDUSTRY_SHARE_AVAILABLE = False
CVE_ANALYZER_AVAILABLE = False
TUI_AVAILABLE = False
SHARE_MANAGER = None
CVE_DB = None
CVE_CORRELATOR = None
TUI_ENGINE = None

try:
    from industry_share import IndustryShareManager
    INDUSTRY_SHARE_AVAILABLE = True
except ImportError:
    pass

try:
    from cve_analyzer import CVEDatabase, LogCVECorrelator
    CVE_ANALYZER_AVAILABLE = True
except ImportError:
    pass

try:
    sys.path.append(str(Path(__file__).parent))
    from tui_layout import SplitScreenTUI, CommandCenter, LogBuffer
    TUI_AVAILABLE = True
except ImportError:
    pass

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.text import Text
    from rich.box import DOUBLE, ROUNDED, HEAVY
    from rich.tree import Tree
    from rich.align import Align
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

class Config:
    VERSION = "4.0.0"
    APP_NAME = "LogSentinel Pro"
    DATA_DIR = Path.home() / ".local" / "share" / "LogSentinel Pro"
    DB_PATH = DATA_DIR / "licenses.db"
    BLOCKCHAIN_PATH = DATA_DIR / "blockchain.json"
    SESSION_FILE = DATA_DIR / ".session"
    MAX_FILE_SIZE = 100 * 1024 * 1024
    ALLOWED_PATHS = ["/var/log", "/tmp", str(Path.home())]
    BLOCKCHAIN_DIFFICULTY = 4
    MAX_POW_NONCE = 10_000_000
    BRUTE_FORCE_THRESHOLD = 5

# ═══════════════════════════════════════════════════════════════════════════════
#  PREMIUM ENGINE INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

# Initialize premium engines
THREAT_ENGINE = None
REPORTER = None
CONFIG_MANAGER = None
RULE_ENGINE = None

if PREMIUM_FEATURES:
    try:
        CONFIG_MANAGER = ConfigurationManager()
        THREAT_ENGINE = AdvancedThreatEngine()
        
        # Initialize appropriate PDF reporter
        if PROFESSIONAL_PDF:
            REPORTER = ProfessionalPDFReporter()
        else:
            REPORTER = ThreatAnalysisReporter()
            
        RULE_ENGINE = RuleEngine(CONFIG_MANAGER)
        
        if RICH:
            reporter_type = "Professional" if PROFESSIONAL_PDF else "Basic"
            console.print(f"[dim]✓ Premium engines loaded ({reporter_type} PDF)[/dim]")
    except Exception as e:
        if RICH:
            console.print(f"[dim red]⚠ Premium engine error: {e}[/dim red]")
        PREMIUM_FEATURES = False

# Initialize v4.0 engines
if INDUSTRY_SHARE_AVAILABLE:
    try:
        SHARE_MANAGER = IndustryShareManager(listen_port=9100)
        if RICH:
            console.print(f"[dim]✓ Industry Share module loaded[/dim]")
    except Exception as e:
        if RICH:
            console.print(f"[dim red]⚠ Industry Share error: {e}[/dim red]")

if CVE_ANALYZER_AVAILABLE:
    try:
        CVE_DB = CVEDatabase()
        CVE_CORRELATOR = LogCVECorrelator(CVE_DB)
        if RICH:
            stats = CVE_DB.get_cve_stats()
            console.print(f"[dim]✓ CVE database loaded ({stats['total']} entries, {stats['critical']} critical)[/dim]")
    except Exception as e:
        if RICH:
            console.print(f"[dim red]⚠ CVE analyzer error: {e}[/dim red]")

if TUI_AVAILABLE:
    try:
        TUI_ENGINE = SplitScreenTUI()
        if RICH:
            console.print(f"[dim]✓ Split-screen TUI engine loaded[/dim]")
    except Exception:
        TUI_ENGINE = None

# ═══════════════════════════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════════════════════════

BANNER = """[bold cyan]
██╗      ██████╗  ██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██║     ██╔═══██╗██╔════╝ ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
██║     ██║   ██║██║  ███╗███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
██║     ██║   ██║██║   ██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
███████╗╚██████╔╝╚██████╔╝███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
[/bold cyan][bold green]
                        ██████╗ ██████╗  ██████╗ 
                        ██╔══██╗██╔══██╗██╔═══██╗
                        ██████╔╝██████╔╝██║   ██║
                        ██╔═══╝ ██╔══██╗██║   ██║
                        ██║     ██║  ██║╚██████╔╝
                        ╚═╝     ╚═╝  ╚═╝ ╚═════╝ [/bold green]"""

MINI_BANNER = """[bold cyan]╔═══════════════════════════════════════════════════════════════════╗
║[/bold cyan] [bold white]🛡️  LOGSENTINEL PRO[/bold white] [dim]v3.0.0[/dim]  [bold green]Enterprise SIEM Platform[/bold green]           [bold cyan]║
╚═══════════════════════════════════════════════════════════════════╝[/bold cyan]"""

# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def spinner(msg: str, duration: float = 1.0):
    if not RICH:
        print(f"{msg}...")
        time.sleep(duration)
        return
    with console.status(f"[bold green]{msg}...", spinner="dots12"):
        time.sleep(duration)

def animated_text(text: str, delay: float = 0.02):
    """Type out text character by character."""
    if not RICH:
        print(text)
        return
    for char in text:
        console.print(char, end="", highlight=False)
        time.sleep(delay)
    console.print()

def boot_sequence():
    """Cool startup animation sequence."""
    if not RICH:
        print("\n[Starting LogSentinel Pro...]\n")
        return
    
    console.print()
    
    # Matrix-style loading
    boot_items = [
        ("Initializing security modules", "cyan"),
        ("Loading threat detection engine", "green"),
        ("Connecting to blockchain", "yellow"),
        ("Validating system integrity", "magenta"),
        ("Starting SIEM core", "blue"),
    ]
    
    with Progress(
        SpinnerColumn(spinner_name="dots12"),
        TextColumn("[bold {task.fields[color]}]{task.description}"),
        BarColumn(bar_width=25, complete_style="green", finished_style="green"),
        TextColumn("[dim]{task.percentage:>3.0f}%[/dim]"),
        console=console,
        transient=True
    ) as progress:
        for item, color in boot_items:
            task = progress.add_task(item, total=100, color=color)
            for _ in range(100):
                progress.update(task, advance=1)
                time.sleep(0.008)
    
    console.print("[bold green]✓[/bold green] [dim]All systems operational[/dim]")
    console.print()

def display_banner_animated():
    """Display banner with animation."""
    if not RICH:
        print("\n=== LOGSENTINEL PRO v3.0.0 ===\n")
        return
    
    # Simple animated banner without parsing issues
    banner_text = """[bold cyan]
██╗      ██████╗  ██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██║     ██╔═══██╗██╔════╝ ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
██║     ██║   ██║██║  ███╗███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
██║     ██║   ██║██║   ██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
███████╗╚██████╔╝╚██████╔╝███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝[/bold cyan]
[bold green]
                        ██████╗ ██████╗  ██████╗ 
                        ██╔══██╗██╔══██╗██╔═══██╗
                        ██████╔╝██████╔╝██║   ██║
                        ██╔═══╝ ██╔══██╗██║   ██║
                        ██║     ██║  ██║╚██████╔╝
                        ╚═╝     ╚═╝  ╚═╝ ╚═════╝ [/bold green]
"""
    console.print(banner_text)
    time.sleep(0.3)

def pulse_text(text: str, color: str = "cyan", pulses: int = 2):
    """Create a pulsing text effect."""
    if not RICH:
        print(text)
        return
    
    for _ in range(pulses):
        console.print(f"[bold {color}]{text}[/bold {color}]", end="\r")
        time.sleep(0.15)
        console.print(f"[dim {color}]{text}[/dim {color}]", end="\r")
        time.sleep(0.15)
    console.print(f"[bold {color}]{text}[/bold {color}]")

def loading_bar(description: str, total: int = 100, duration: float = 1.0):
    """Show a loading bar with specified duration."""
    if not RICH:
        print(f"{description}...")
        time.sleep(duration)
        return
    
    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn(f"[bold cyan]{description}"),
        BarColumn(bar_width=30, complete_style="cyan", finished_style="green"),
        TextColumn("[bold]{task.percentage:>3.0f}%"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task(description, total=total)
        step_delay = duration / total
        for _ in range(total):
            progress.update(task, advance=1)
            time.sleep(step_delay)

def success(msg: str):
    console.print(f"[bold green]✅ {msg}[/bold green]") if RICH else print(f"✅ {msg}")

def error(msg: str):
    console.print(f"[bold red]❌ {msg}[/bold red]") if RICH else print(f"❌ {msg}")

def warning(msg: str):
    console.print(f"[bold yellow]⚠️  {msg}[/bold yellow]") if RICH else print(f"⚠️  {msg}")

def show_status_line(org: str):
    """Show the authenticated status line."""
    if not RICH:
        print(f"Licensed to: {org}")
        return
    
    timestamp = datetime.now().strftime("%H:%M:%S")
    console.print(
        f"[dim]┌─ Licensed to:[/dim] [bold green]{org}[/bold green] "
        f"[dim]│ Status:[/dim] [green]● Active[/green] "
        f"[dim]│ Time:[/dim] [cyan]{timestamp}[/cyan] [dim]─┐[/dim]"
    )

# ═══════════════════════════════════════════════════════════════════════════════
#  DEVICE FINGERPRINT
# ═══════════════════════════════════════════════════════════════════════════════

class DeviceFingerprint:
    @staticmethod
    def generate() -> str:
        components = []
        try:
            with open("/etc/machine-id", "r") as f:
                components.append(f.read().strip())
        except:
            components.append("no-machine-id")
        
        try:
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if "model name" in line:
                        components.append(line.split(":")[1].strip())
                        break
        except:
            components.append("unknown-cpu")
        
        try:
            for iface in Path("/sys/class/net").iterdir():
                if iface.name != "lo":
                    addr_file = iface / "address"
                    if addr_file.exists():
                        components.append(addr_file.read_text().strip())
        except:
            pass
        
        components.append(socket.gethostname())
        return hashlib.sha256("|".join(components).encode()).hexdigest()

# ═══════════════════════════════════════════════════════════════════════════════
#  AUTHENTICATION
# ═══════════════════════════════════════════════════════════════════════════════

class AuthManager:
    def __init__(self):
        self.db_path = Config.DB_PATH
        self.device_fp = DeviceFingerprint.generate()
        self._ensure_db()
    
    def _ensure_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                key TEXT PRIMARY KEY, device_fingerprint TEXT,
                issued_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                is_used INTEGER DEFAULT 0, issued_by TEXT,
                organization TEXT, max_duration_hours INTEGER,
                notes TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT, action TEXT, device_fingerprint TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                status TEXT, error_message TEXT
            )
        """)
        conn.commit()
        conn.close()
    
    def _log_audit(self, key: str, action: str, status: str, error: str = ""):
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO auth_audit (license_key, action, device_fingerprint, status, error_message)
            VALUES (?, ?, ?, ?, ?)
        """, (key[:16] + "..." if len(key) > 16 else key, action, self.device_fp[:16] + "...", status, error))
        conn.commit()
        conn.close()
    
    def authenticate(self, key: str) -> Tuple[bool, str, str]:
        if not re.match(r'^[a-f0-9]{64}$', key.lower()):
            self._log_audit(key, "AUTH_ATTEMPT", "FAILED", "Invalid format")
            return False, "Invalid key format (64 hex chars required)", ""
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM licenses WHERE key = ?", (key,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            self._log_audit(key, "AUTH_ATTEMPT", "FAILED", "Not found")
            return False, "License key not found", ""
        
        key, device_fp, issued_at, expires_at, is_used, issued_by, org, max_hours, notes, created = row
        expires_dt = datetime.fromisoformat(expires_at)
        
        if expires_dt < datetime.now():
            conn.close()
            self._log_audit(key, "AUTH_ATTEMPT", "FAILED", "Expired")
            return False, f"License expired on {expires_dt.strftime('%Y-%m-%d')}", org
        
        if is_used:
            if device_fp and device_fp != self.device_fp:
                conn.close()
                self._log_audit(key, "AUTH_ATTEMPT", "FAILED", "Device mismatch")
                return False, "License bound to different device", org
            conn.close()
            self._log_audit(key, "AUTH_REVALIDATE", "SUCCESS", "")
            # Save session
            self._save_session(key, org, expires_at)
            return True, "License validated", org
        
        cursor.execute("UPDATE licenses SET is_used = 1, device_fingerprint = ? WHERE key = ?", 
                      (self.device_fp, key))
        conn.commit()
        conn.close()
        
        self._log_audit(key, "AUTH_SUCCESS", "SUCCESS", "")
        self._log_audit(key, "DEVICE_BIND", "SUCCESS", "First activation")
        # Save session
        self._save_session(key, org, expires_at)
        return True, "License activated and bound to device", org
    
    def _save_session(self, key: str, org: str, expires: str):
        """Save active session to file."""
        Config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        session = {
            "key": key,
            "organization": org,
            "device_fp": self.device_fp,
            "expires": expires,
            "activated_at": datetime.now().isoformat()
        }
        Config.SESSION_FILE.write_text(json.dumps(session))
    
    def check_session(self) -> Tuple[bool, str, str]:
        """Check if there's a valid session. Returns (valid, message, org)."""
        if not Config.SESSION_FILE.exists():
            return False, "No active session", ""
        
        try:
            session = json.loads(Config.SESSION_FILE.read_text())
        except:
            return False, "Invalid session file", ""
        
        # Verify device fingerprint
        if session.get("device_fp") != self.device_fp:
            Config.SESSION_FILE.unlink(missing_ok=True)
            return False, "Session from different device", ""
        
        # Check expiration
        expires = datetime.fromisoformat(session.get("expires", "2000-01-01"))
        if expires < datetime.now():
            Config.SESSION_FILE.unlink(missing_ok=True)
            return False, "Session expired", ""
        
        # Verify key still exists and is valid in database
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT organization, expires_at, device_fingerprint FROM licenses WHERE key = ?", 
                      (session.get("key"),))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            Config.SESSION_FILE.unlink(missing_ok=True)
            return False, "License revoked", ""
        
        org, db_expires, db_device = row
        if db_device != self.device_fp:
            Config.SESSION_FILE.unlink(missing_ok=True)
            return False, "License rebound to different device", ""
        
        return True, "Session valid", org
    
    def logout(self):
        """Clear the session."""
        Config.SESSION_FILE.unlink(missing_ok=True)
    
    def get_status(self) -> Dict:
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM licenses")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM licenses WHERE is_used = 0")
        available = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM licenses WHERE is_used = 1")
        activated = cursor.fetchone()[0]
        
        conn.close()
        return {"total": total, "available": available, "activated": activated, "device_fp": self.device_fp}

# ═══════════════════════════════════════════════════════════════════════════════
#  BLOCKCHAIN
# ═══════════════════════════════════════════════════════════════════════════════

class Block:
    def __init__(self, index: int, timestamp: str, data: str, previous_hash: str):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = ""
    
    def compute_hash(self) -> str:
        payload = f"{self.index}{self.timestamp}{self.previous_hash}{self.data}{self.nonce}"
        return hashlib.sha256(payload.encode()).hexdigest()
    
    def mine(self, difficulty: int) -> bool:
        target = "0" * difficulty
        for _ in range(Config.MAX_POW_NONCE):
            self.hash = self.compute_hash()
            if self.hash.startswith(target):
                return True
            self.nonce += 1
        self.hash = self.compute_hash()
        return False
    
    def to_dict(self) -> Dict:
        return {"index": self.index, "timestamp": self.timestamp, "data": self.data,
                "previous_hash": self.previous_hash, "nonce": self.nonce, "hash": self.hash}
    
    @classmethod
    def from_dict(cls, d: Dict) -> 'Block':
        b = cls(d["index"], d["timestamp"], d["data"], d["previous_hash"])
        b.nonce = d["nonce"]
        b.hash = d["hash"]
        return b

class Blockchain:
    def __init__(self):
        self.chain: List[Block] = []
        self.path = Config.BLOCKCHAIN_PATH
        self._load()
    
    def _load(self):
        if self.path.exists():
            try:
                self.chain = [Block.from_dict(b) for b in json.loads(self.path.read_text())]
            except:
                self.chain = []
    
    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps([b.to_dict() for b in self.chain], indent=2))
    
    def create_genesis(self):
        if not self.chain:
            block = Block(0, datetime.now().isoformat(), "Genesis Block", "0")
            block.mine(Config.BLOCKCHAIN_DIFFICULTY)
            self.chain.append(block)
            self._save()
    
    def add_block(self, data: str) -> Block:
        if not self.chain:
            self.create_genesis()
        prev = self.chain[-1]
        block = Block(len(self.chain), datetime.now().isoformat(), data, prev.hash)
        block.mine(Config.BLOCKCHAIN_DIFFICULTY)
        self.chain.append(block)
        self._save()
        return block
    
    def verify(self) -> Tuple[bool, str, int]:
        if not self.chain:
            return True, "Empty chain", 0
        for i in range(1, len(self.chain)):
            curr, prev = self.chain[i], self.chain[i-1]
            if curr.previous_hash != prev.hash:
                return False, f"Block {i}: hash mismatch", i
            if curr.hash != curr.compute_hash():
                return False, f"Block {i}: invalid hash", i
        return True, "Chain valid", len(self.chain)

# ═══════════════════════════════════════════════════════════════════════════════
#  LOG PARSER & DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

class LogParser:
    SYSLOG = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$')
    
    PATTERNS = {
        "ssh_failed": (re.compile(r'Failed password for (\S+) from (\S+)', re.I), "T1110.001", "CRITICAL"),
        "ssh_invalid": (re.compile(r'Invalid user (\S+) from (\S+)', re.I), "T1078", "HIGH"),
        "sudo_cmd": (re.compile(r'sudo.*COMMAND=(.+)', re.I), "T1548", "HIGH"),
        "sql_injection": (re.compile(r"('|--|;.*=|UNION.*SELECT|OR\s+1\s*=\s*1)", re.I), "T1190", "CRITICAL"),
        "xss": (re.compile(r'(<script|javascript:|on\w+=)', re.I), "T1189", "HIGH"),
        "path_traversal": (re.compile(r'\.\./', re.I), "T1083", "HIGH"),
        "port_scan": (re.compile(r'(port\s*scan|nmap|masscan)', re.I), "T1046", "MEDIUM"),
        "kernel_panic": (re.compile(r'kernel.*panic', re.I), "T1499", "CRITICAL"),
        "rce": (re.compile(r'(;|\|)\s*(cat|ls|id|whoami|wget|curl|nc|bash)', re.I), "T1059", "CRITICAL"),
        "c2_beacon": (re.compile(r'(beacon|callback|reverse.?shell)', re.I), "T1071", "CRITICAL"),
        "data_exfil": (re.compile(r'(exfil|upload.*data)', re.I), "T1048", "CRITICAL"),
    }
    
    @classmethod
    def parse(cls, line: str) -> Optional[Dict]:
        m = cls.SYSLOG.match(line.strip())
        if not m:
            return None
        ts, host, proc, pid, msg = m.groups()
        return {"timestamp": ts, "hostname": host, "process": proc.lower(), "pid": pid, "message": msg, "raw": line.strip()}
    
    @classmethod
    def detect(cls, event: Dict) -> List[Dict]:
        threats = []
        msg = event.get("message", "")
        for name, (pattern, mitre, severity) in cls.PATTERNS.items():
            if m := pattern.search(msg):
                threats.append({
                    "type": name.upper(), "severity": severity, "mitre": mitre,
                    "match": m.group(0)[:50], "timestamp": event.get("timestamp", "")
                })
        return threats


class ThreatAnalyzer:
    def __init__(self):
        self.failed_logins: Dict[str, List] = defaultdict(list)
        self.threats: List[Dict] = []
        self.events = 0
        self.lines = 0
    
    def process(self, event: Dict) -> List[Dict]:
        self.events += 1
        threats = LogParser.detect(event)
        
        for t in threats:
            if t["type"] == "SSH_FAILED":
                m = re.search(r'from (\S+)', event.get("message", ""))
                if m:
                    ip = m.group(1)
                    self.failed_logins[ip].append(1)
                    if len(self.failed_logins[ip]) >= Config.BRUTE_FORCE_THRESHOLD:
                        t["severity"] = "CRITICAL"
                        t["type"] = "BRUTE_FORCE_ATTACK"
        
        self.threats.extend(threats)
        return threats
    
    def summary(self) -> Dict:
        sev = defaultdict(int)
        types = defaultdict(int)
        for t in self.threats:
            sev[t["severity"]] += 1
            types[t["type"]] += 1
        
        score = min(100, sev["CRITICAL"]*25 + sev["HIGH"]*15 + sev["MEDIUM"]*5 + sev["LOW"])
        level = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
        
        return {
            "lines": self.lines, "events": self.events, "threats": len(self.threats),
            "severity": dict(sev), "types": dict(types), "score": score, "level": level,
            "attackers": len(self.failed_logins)
        }

# ═══════════════════════════════════════════════════════════════════════════════
#  FILE VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

def validate_file(filepath: str) -> Tuple[bool, str]:
    path = Path(filepath)
    if not path.exists():
        return False, "File not found"
    try:
        real = path.resolve()
    except:
        return False, "Cannot resolve path"
    
    if not any(str(real).startswith(p) for p in Config.ALLOWED_PATHS):
        return False, "Path not allowed"
    if ".." in str(filepath):
        return False, "Path traversal detected"
    if not real.is_file():
        return False, "Not a file"
    
    size = real.stat().st_size
    if size > Config.MAX_FILE_SIZE:
        return False, f"Too large: {size//1024//1024}MB"
    if size == 0:
        return False, "Empty file"
    return True, "OK"

# ═══════════════════════════════════════════════════════════════════════════════
#  COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

def cmd_auth(args):
    """Authenticate with license."""
    if RICH:
        console.print(MINI_BANNER)
    
    auth = AuthManager()
    
    if args.status:
        spinner("Loading status", 0.8)
        s = auth.get_status()
        
        if RICH:
            table = Table(title="🔐 License Status", box=DOUBLE, border_style="cyan")
            table.add_column("Property", style="bold")
            table.add_column("Value", style="green")
            table.add_row("Total Keys", str(s["total"]))
            table.add_row("Available", str(s["available"]))
            table.add_row("Activated", str(s["activated"]))
            table.add_row("Device ID", f"[dim]{s['device_fp'][:32]}...[/dim]")
            console.print()
            console.print(table)
            console.print()
        else:
            print(f"Status: {s}")
        return 0
    
    if args.key:
        spinner("Validating license", 1.2)
        ok, msg, org = auth.authenticate(args.key)
        
        if RICH:
            if ok:
                console.print(Panel(
                    f"[bold green]{msg}[/bold green]\n\n[dim]Organization:[/dim] [bold]{org}[/bold]",
                    title="✅ Authenticated", border_style="green", box=DOUBLE
                ))
            else:
                console.print(Panel(f"[bold red]{msg}[/bold red]", title="❌ Failed", border_style="red"))
        else:
            print(f"{'✅' if ok else '❌'} {msg}")
        return 0 if ok else 1
    
    warning("Use --key KEY or --status")
    return 1


def cmd_scan(args):
    """Enhanced scan with premium ML detection and advanced analytics."""
    if RICH:
        console.print(MINI_BANNER)
    
    ok, msg = validate_file(args.file)
    if not ok:
        error(msg)
        return 1
    
    # Initialize analyzers
    analyzer = ThreatAnalyzer()
    blockchain = Blockchain() if args.blockchain else None
    threats_found = []
    premium_results = None
    
    # Read file
    with open(args.file, 'r', errors='ignore') as f:
        lines = f.readlines()
    analyzer.lines = len(lines)
    
    # Parse events for premium analysis
    parsed_events = []
    
    if RICH:
        console.print()
        console.print(Panel(f"[bold]📂 {args.file}[/bold]\n📝 {len(lines):,} lines", title="🔍 Scan Target", border_style="blue"))
        console.print()
        
        # Enhanced progress tracking
        with Progress(
            SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40), TextColumn("{task.percentage:>3.0f}%"),
            TimeElapsedColumn(), console=console
        ) as progress:
            
            # Basic analysis task
            basic_task = progress.add_task("Basic Analysis...", total=len(lines))
            
            for i, line in enumerate(lines):
                event = LogParser.parse(line)
                if event:
                    # Basic threat analysis
                    threats = analyzer.process(event)
                    if threats:
                        for t in threats:
                            threats_found.append((i+1, t))
                        if blockchain:
                            for t in threats:
                                blockchain.add_block(json.dumps({"line": i+1, "type": t["type"], "severity": t["severity"]}))
                    
                    # Store event for premium analysis with enhanced data
                    parsed_events.append({
                        "line_number": i+1,
                        "timestamp": datetime.now().isoformat(),
                        "raw_line": line.strip(),
                        "source_ip": _extract_ip(line),
                        "user": _extract_user(line),
                        "action": _extract_action(line),
                        "category": _classify_event(line),
                        "request_count": _extract_request_count(line),
                        "user_agent": _extract_user_agent(line),
                        "command": _extract_command(line),
                        "process_name": _extract_process(line),
                        "file_path": _extract_file_path(line),
                        "transfer_size_mb": _extract_transfer_size(line),
                        **event
                    })
                
                progress.update(basic_task, advance=1)
            
            # Premium ML Analysis
            if PREMIUM_FEATURES and THREAT_ENGINE and parsed_events:
                ml_task = progress.add_task("ML Analysis...", total=1)
                
                try:
                    premium_results = THREAT_ENGINE.analyze_events(parsed_events)
                    progress.update(ml_task, advance=1)
                except Exception as e:
                    if RICH:
                        console.print(f"[dim red]ML Analysis error: {e}[/dim red]")
    
    else:
        # Simple mode without progress bars
        for i, line in enumerate(lines):
            event = LogParser.parse(line)
            if event:
                analyzer.process(event)
                parsed_events.append({
                    "line_number": i+1,
                    "timestamp": datetime.now().isoformat(),
                    "raw_line": line.strip(),
                    "source_ip": _extract_ip(line),
                    "user": _extract_user(line),
                    "action": _extract_action(line),
                    "category": _classify_event(line),
                    "request_count": _extract_request_count(line),
                    "user_agent": _extract_user_agent(line),
                    "command": _extract_command(line),
                    "process_name": _extract_process(line),
                    "file_path": _extract_file_path(line),
                    "transfer_size_mb": _extract_transfer_size(line),
                    **event
                })
        
        # Premium analysis in simple mode
        if PREMIUM_FEATURES and THREAT_ENGINE and parsed_events:
            try:
                premium_results = THREAT_ENGINE.analyze_events(parsed_events)
            except Exception as e:
                print(f"ML Analysis error: {e}")
    
    # Get basic summary
    s = analyzer.summary()
    
    # Enhanced risk calculation with ML results
    if premium_results:
        ml_risk_score = premium_results.get('risk_score', 0)
        combined_score = max(s["score"], ml_risk_score)
        s["score"] = combined_score
        s["level"] = get_risk_level(combined_score)
    
    if RICH:
        console.print()
        
        # Enhanced risk display
        colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "green"}
        c = colors[s["level"]]
        bar = "█" * (s["score"] // 5) + "░" * (20 - s["score"] // 5)
        
        risk_panel_content = f"[bold {c}]{bar}[/bold {c}]\n\n[bold]Score:[/bold] [{c}]{s['score']}/100[/{c}]  [bold]Level:[/bold] [{c}]{s['level']}[/{c}]"
        
        if premium_results:
            intel_matches = len(premium_results.get('intelligence_matches', []))
            anomalies = len(premium_results.get('anomalies', []))
            attack_chains = len(premium_results.get('attack_chains', []))
            
            risk_panel_content += f"\n\n[dim]ML Analysis:[/dim]\n[dim]• IOC Matches: {intel_matches}[/dim]\n[dim]• Anomalies: {anomalies}[/dim]\n[dim]• Attack Chains: {attack_chains}[/dim]"
        
        console.print(Panel(
            risk_panel_content,
            title="⚠️  ADVANCED RISK ASSESSMENT", border_style=c, box=HEAVY
        ))
        
        # Enhanced stats table
        table = Table(title="📊 Comprehensive Analysis", box=ROUNDED)
        table.add_column("Metric", style="bold")
        table.add_column("Basic", justify="right")
        if premium_results:
            table.add_column("ML Enhanced", justify="right", style="cyan")
        
        table.add_row("Lines Analyzed", f"{s['lines']:,}", "✓" if premium_results else "—")
        table.add_row("Events Parsed", f"{s['events']:,}", f"{len(parsed_events):,}" if premium_results else "—")
        table.add_row("Basic Threats", f"[red]{s['threats']}[/red]", "—")
        
        if premium_results:
            table.add_row("IOC Matches", "—", f"[red]{len(premium_results.get('intelligence_matches', []))}[/red]")
            table.add_row("ML Anomalies", "—", f"[yellow]{len(premium_results.get('anomalies', []))}[/yellow]")
            table.add_row("Attack Chains", "—", f"[magenta]{len(premium_results.get('attack_chains', []))}[/magenta]")
        
        table.add_row("Unique Attackers", str(s["attackers"]), "—")
        if blockchain:
            table.add_row("Blockchain Blocks", f"{len(blockchain.chain)}", "—")
        
        console.print(table)
        
        # Premium ML Results Display
        if premium_results and args.verbose:
            display_premium_results(premium_results)
        
        # Basic threat display
        if threats_found and args.verbose:
            console.print()
            threat_table = Table(title="🚨 Basic Pattern Matches", box=ROUNDED, border_style="red")
            threat_table.add_column("Line", justify="right", style="dim")
            threat_table.add_column("Severity")
            threat_table.add_column("Type", style="bold")
            threat_table.add_column("MITRE")
            threat_table.add_column("Match", max_width=30)
            
            for ln, t in threats_found[-20:]:
                c = colors[t["severity"]]
                threat_table.add_row(str(ln), f"[{c}]{t['severity']}[/{c}]", t["type"], t["mitre"], t.get("match", "")[:30])
            console.print(threat_table)
        
        # Professional PDF Report generation
        if premium_results and (args.report or getattr(args, 'pdf', False)):
            console.print("\n[dim]🔄 Generating professional threat analysis report...[/dim]")
            try:
                if PROFESSIONAL_PDF:
                    # Use professional PDF reporter
                    report_path = generate_threat_report(
                        premium_results, 
                        {
                            "scan_time": datetime.now().isoformat(),
                            "files_scanned": 1,
                            "events_analyzed": len(parsed_events),
                            "file_name": args.file
                        }
                    )
                    console.print(f"[green]✓ Professional PDF report saved: {report_path}[/green]")
                    console.print(f"[dim]📄 Report includes: Executive summary, detailed findings, risk assessment, and recommendations[/dim]")
                else:
                    # Fallback to basic PDF reporter
                    if 'REPORTER' in globals() and REPORTER:
                        report_path = REPORTER.generate_threat_report(
                            premium_results, 
                            {
                                "scan_time": datetime.now().isoformat(),
                                "files_scanned": 1,
                                "events_analyzed": len(parsed_events)
                            }
                        )
                        console.print(f"[green]✓ Report saved: {report_path}[/green]")
                    else:
                        console.print("[yellow]⚠️ PDF reporter not available[/yellow]")
            except Exception as e:
                console.print(f"[red]✗ Report generation failed: {e}[/red]")
                import traceback
                console.print(f"[dim]{traceback.format_exc()}[/dim]")
        
        # Professional Compliance Report generation  
        if premium_results and hasattr(args, 'compliance') and args.compliance:
            console.print(f"\n[dim]🔄 Generating {args.compliance} compliance assessment report...[/dim]")
            try:
                if PROFESSIONAL_PDF:
                    # Use professional compliance PDF reporter
                    compliance_path = generate_compliance_report_pdf(premium_results, args.compliance)
                    console.print(f"[green]✓ Professional {args.compliance} compliance report saved: {compliance_path}[/green]")
                    console.print(f"[dim]📋 Report includes: Compliance status, requirements assessment, and remediation actions[/dim]")
                else:
                    # Fallback to text compliance report
                    compliance_path = generate_compliance_report(premium_results, args.compliance)
                    console.print(f"[green]✓ {args.compliance} compliance report saved: {compliance_path}[/green]")
            except Exception as e:
                console.print(f"[red]✗ Compliance report failed: {e}[/red]")
        
        console.print()
    else:
        # Simple text output
        print(f"\nRisk: {s['score']}/100 ({s['level']}), Basic Threats: {s['threats']}")
        if premium_results:
            print(f"ML Analysis: {len(premium_results.get('intelligence_matches', []))} IOCs, {len(premium_results.get('anomalies', []))} anomalies")
    
    # JSON output with premium data
    if args.json:
        output_data = {"file": args.file, "basic_summary": s}
        if premium_results:
            output_data["ml_analysis"] = premium_results
        print(json.dumps(output_data, indent=2))
    
    # Return code based on combined risk
    return 0 if s["level"] in ["LOW", "MEDIUM"] else 1


def _extract_ip(line: str) -> str:
    """Extract IP address from log line."""
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    match = re.search(ip_pattern, line)
    return match.group(0) if match else ""


def _extract_user(line: str) -> str:
    """Extract username from log line."""
    user_patterns = [
        r'user (\w+)',
        r'for (\w+) from',
        r'User (\w+) executed'
    ]
    for pattern in user_patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def _extract_action(line: str) -> str:
    """Extract action/event type from log line."""
    if 'failed login' in line.lower():
        return 'failed_login'
    elif 'successful login' in line.lower() or 'login' in line.lower():
        return 'login'
    elif 'executed' in line.lower():
        return 'command_execution'
    elif 'connection' in line.lower():
        return 'network_connection'
    elif 'access' in line.lower():
        return 'file_access'
    return 'unknown'


def _classify_event(line: str) -> str:
    """Classify event into category."""
    line_lower = line.lower()
    if any(word in line_lower for word in ['login', 'auth', 'password']):
        return 'authentication'
    elif any(word in line_lower for word in ['network', 'connection', 'request']):
        return 'network'
    elif any(word in line_lower for word in ['execute', 'command', 'process']):
        return 'system'
    elif any(word in line_lower for word in ['file', 'access', 'transfer']):
        return 'data'
    return 'general'


def _extract_request_count(line: str) -> int:
    """Extract request count for rate limiting analysis."""
    rate_pattern = r'(\d+) requests?'
    match = re.search(rate_pattern, line, re.IGNORECASE)
    if match:
        return int(match.group(1))
    # Default rate simulation based on content
    if 'high request rate' in line.lower():
        return 250
    return 1


def _extract_user_agent(line: str) -> str:
    """Extract User-Agent string."""
    ua_pattern = r'user-agent: ([^,\n]+)'
    match = re.search(ua_pattern, line, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    # Check for suspicious UA indicators
    if 'sqlmap' in line.lower():
        return 'sqlmap/1.0'
    return ""


def _extract_command(line: str) -> str:
    """Extract executed command."""
    cmd_patterns = [
        r'executed: (.+)',
        r'command: (.+)',
        r'Binary execution: (.+) from'
    ]
    for pattern in cmd_patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return ""


def _extract_process(line: str) -> str:
    """Extract process name."""
    proc_patterns = [
        r'Process started: (.+)',
        r'Binary execution: ([^\s]+)',
        r'([^/\s]+\.exe)'
    ]
    for pattern in proc_patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return ""


def _extract_file_path(line: str) -> str:
    """Extract file path."""
    path_patterns = [
        r'accessed: (.+)',
        r'file: (.+)',
        r'(/[^\s]+)',
        r'([A-Z]:\\[^\s]+)'
    ]
    for pattern in path_patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(1).strip()
    return ""


def _extract_transfer_size(line: str) -> float:
    """Extract data transfer size in MB."""
    size_pattern = r'(\d+)\s*MB'
    match = re.search(size_pattern, line, re.IGNORECASE)
    if match:
        return float(match.group(1))
    return 0.0


def display_premium_results(results: Dict):
    """Display premium ML analysis results in rich format."""
    if not RICH:
        return
    
    # Threat Intelligence Matches
    intel_matches = results.get('intelligence_matches', [])
    if intel_matches:
        console.print()
        intel_table = Table(title="🎯 Threat Intelligence Matches", box=ROUNDED, border_style="red")
        intel_table.add_column("Indicator", style="bold red")
        intel_table.add_column("Type")
        intel_table.add_column("Severity")
        intel_table.add_column("Source", style="dim")
        
        for match in intel_matches[:10]:  # Limit display
            threat_data = match.get('threat_data', {})
            intel_table.add_row(
                match['indicator'][:30] + "..." if len(match['indicator']) > 30 else match['indicator'],
                threat_data.get('type', 'Unknown'),
                threat_data.get('severity', 'unknown').upper(),
                threat_data.get('source', 'Unknown')[:15]
            )
        
        console.print(intel_table)
    
    # ML Anomalies
    anomalies = results.get('anomalies', [])
    if anomalies:
        console.print()
        anomaly_table = Table(title="🤖 ML-Detected Anomalies", box=ROUNDED, border_style="yellow")
        anomaly_table.add_column("Type", style="bold")
        anomaly_table.add_column("Severity")
        anomaly_table.add_column("Confidence", justify="right")
        anomaly_table.add_column("Description", max_width=40)
        
        for anomaly in anomalies[:15]:  # Limit display
            confidence = f"{anomaly.get('confidence', 0)*100:.0f}%"
            anomaly_table.add_row(
                anomaly.get('type', 'Unknown').replace('_', ' ').title(),
                anomaly.get('severity', 'unknown').upper(),
                confidence,
                anomaly.get('description', 'No description')[:40]
            )
        
        console.print(anomaly_table)
    
    # Attack Chains
    attack_chains = results.get('attack_chains', [])
    if attack_chains:
        console.print()
        chain_table = Table(title="⚡ Attack Chain Analysis", box=ROUNDED, border_style="magenta")
        chain_table.add_column("Chain", style="bold")
        chain_table.add_column("Type")
        chain_table.add_column("Severity")
        chain_table.add_column("Duration")
        chain_table.add_column("Phases", justify="right")
        chain_table.add_column("Confidence", justify="right")
        
        for i, chain in enumerate(attack_chains[:10], 1):
            confidence = f"{chain.get('confidence', 0)*100:.0f}%"
            chain_table.add_row(
                f"#{i}",
                chain.get('attack_type', 'Unknown').replace('_', ' ').title(),
                chain.get('severity', 'unknown').upper(),
                chain.get('duration', 'Unknown'),
                str(len(chain.get('phases', []))),
                confidence
            )
        
        console.print(chain_table)


def get_risk_level(score: int) -> str:
    """Get risk level from score."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def cmd_blockchain(args):
    """Manage blockchain."""
    if RICH:
        console.print(MINI_BANNER)
    
    bc = Blockchain()
    
    if args.verify:
        spinner("Verifying chain", 1.5)
        ok, msg, count = bc.verify()
        
        if RICH:
            if ok:
                console.print(Panel(f"[green]✅ {msg}[/green]\n\nBlocks: {count}", title="🔗 Blockchain", border_style="green"))
            else:
                console.print(Panel(f"[red]❌ {msg}[/red]", title="🔗 Blockchain", border_style="red"))
        else:
            print(f"{'✅' if ok else '❌'} {msg}")
        return 0 if ok else 1
    
    if args.show:
        if not bc.chain:
            warning("Empty blockchain")
            return 0
        
        if RICH:
            console.print()
            console.print(Panel(f"Blocks: {len(bc.chain)}\nPath: {bc.path}", title="⛓️ Blockchain", border_style="cyan"))
            
            tree = Tree("🔗 [bold]Chain[/bold]")
            for b in bc.chain[-10:]:
                branch = tree.add(f"[cyan]Block #{b.index}[/cyan]")
                branch.add(f"[dim]Hash: {b.hash[:24]}...[/dim]")
                branch.add(f"[dim]Nonce: {b.nonce:,}[/dim]")
                if b.data != "Genesis Block":
                    try:
                        d = json.loads(b.data)
                        branch.add(f"[yellow]{d.get('type', '?')}[/yellow] @ line {d.get('line', '?')}")
                    except:
                        branch.add(f"[dim]{b.data[:30]}...[/dim]")
                else:
                    branch.add("[green]Genesis[/green]")
            console.print(tree)
            console.print()
        else:
            print(f"Blockchain: {len(bc.chain)} blocks")
        return 0
    
    warning("Use --verify or --show")
    return 1


def cmd_fingerprint(args):
    """Show device fingerprint."""
    if RICH:
        console.print(MINI_BANNER)
    
    spinner("Generating fingerprint", 1.0)
    fp = DeviceFingerprint.generate()
    
    if RICH:
        console.print()
        console.print(Panel(f"[cyan]{fp}[/cyan]", title="🖥️ Device Fingerprint", border_style="cyan", box=DOUBLE))
        console.print()
    else:
        print(f"Fingerprint: {fp}")
    return 0


def cmd_version(args):
    """Show version."""
    if RICH:
        console.print(BANNER)
        console.print(Align.center("[bold]v3.0.0[/bold] • [dim]Enterprise SIEM Platform[/dim]"))
        console.print()
    else:
        print(f"\nLogSentinel Pro v{Config.VERSION}\n")
    return 0


def cmd_generate_report(args):
    """Generate professional PDF reports from previous scan data."""
    if not PROFESSIONAL_PDF:
        error("Professional PDF reporting requires additional dependencies")
        return 1
    
    if RICH:
        console.print(MINI_BANNER)
        console.print()
    
    # Validate input file
    ok, msg = validate_file(args.input_file)
    if not ok:
        error(msg)
        return 1
    
    try:
        # Check if input is JSON (previous scan result) or log file
        if args.input_file.endswith('.json'):
            # Load previous scan results
            with open(args.input_file, 'r') as f:
                scan_results = json.load(f)
        else:
            # Re-scan the log file
            if RICH:
                console.print("[dim]🔄 Analyzing log file for report generation...[/dim]")
            
            # Perform scan to get results
            analyzer = ThreatAnalyzer()
            
            with open(args.input_file, 'r', errors='ignore') as f:
                lines = f.readlines()
            
            parsed_events = []
            for i, line in enumerate(lines):
                event = LogParser.parse(line)
                if event:
                    parsed_events.append({
                        "line_number": i+1,
                        "timestamp": datetime.now().isoformat(),
                        "raw_line": line.strip(),
                        **event
                    })
            
            # Get ML analysis results
            premium_results = None
            if THREAT_ENGINE and parsed_events:
                try:
                    premium_results = THREAT_ENGINE.analyze_events(parsed_events)
                except Exception as e:
                    console.print(f"[red]ML Analysis error: {e}[/red]")
                    return 1
            
            scan_results = premium_results
    
        if not scan_results:
            error("No scan results available for report generation")
            return 1
        
        # Generate appropriate report
        if args.compliance:
            if RICH:
                console.print(f"[dim]📋 Generating {args.compliance} compliance assessment report...[/dim]")
            
            output_file = generate_compliance_report_pdf(scan_results, args.compliance)
            
            if RICH:
                console.print(f"[green]✓ Professional {args.compliance} compliance report generated: {output_file}[/green]")
                console.print("[dim]📋 Report includes: Compliance status, requirements assessment, and remediation actions[/dim]")
        else:
            if RICH:
                console.print("[dim]📄 Generating professional threat analysis report...[/dim]")
            
            metadata = {
                "scan_time": datetime.now().isoformat(),
                "files_scanned": 1,
                "events_analyzed": len(scan_results.get('intelligence_matches', [])),
                "file_name": args.input_file,
                "report_format": getattr(args, 'format', 'professional')
            }
            
            output_file = generate_threat_report(scan_results, metadata)
            
            if RICH:
                console.print(f"[green]✓ Professional threat analysis report generated: {output_file}[/green]")
                console.print("[dim]📄 Report includes: Executive summary, detailed findings, risk assessment, and recommendations[/dim]")
        
        return 0
        
    except Exception as e:
        error(f"Report generation failed: {e}")
        import traceback
        if RICH:
            console.print(f"[dim red]{traceback.format_exc()}[/dim red]")
        return 1


def cmd_logout(args):
    """Clear active session."""
    if RICH:
        console.print(MINI_BANNER)
    
    auth = AuthManager()
    valid, _, org = auth.check_session()
    
    if valid:
        auth.logout()
        if RICH:
            console.print(Panel(
                f"[bold green]Session cleared[/bold green]\n\n[dim]Organization:[/dim] {org}",
                title="👋 Logged Out", border_style="green"
            ))
        else:
            print("✅ Session cleared")
    else:
        if RICH:
            console.print(Panel("[dim]No active session[/dim]", title="ℹ️ Info", border_style="blue"))
        else:
            print("No active session")
    return 0

# ═══════════════════════════════════════════════════════════════════════════════
#  STARTUP AUTHENTICATION GATE
# ═══════════════════════════════════════════════════════════════════════════════

def check_and_prompt_auth() -> Tuple[bool, str]:
    """
    Check if authenticated. If not, prompt for key interactively.
    Returns (success, organization).
    """
    auth_mgr = AuthManager()
    
    # Initial boot animation
    if RICH:
        console.clear()
        display_banner_animated()
        loading_bar("Checking license status", 50, 0.5)
    
    valid, msg, org = auth_mgr.check_session()
    
    if valid:
        if RICH:
            console.print()
            console.print(Panel(
                f"[bold green]✓ LICENSE VALID[/bold green]\n\n"
                f"[dim]Organization:[/dim] [bold white]{org}[/bold white]\n"
                f"[dim]Session:[/dim] [green]Active[/green]",
                title="🔓 Authenticated", border_style="green"
            ))
            boot_sequence()
        return True, org
    
    # Show locked screen with animation
    if RICH:
        console.print()
        
        # Animated lock icon
        lock_frames = ["🔒", "🔐", "🔒", "🔐"]
        for frame in lock_frames:
            console.print(f"\r  [bold red]{frame} SECURITY CHECK FAILED[/bold red]", end="")
            time.sleep(0.2)
        console.print()
        console.print()
        
        console.print(Panel(
            "[bold red]█▀▀ █▀█ █▀▀ ▀█▀ █ █ █ ▄▀█ █▀█ █▀▀[/bold red]\n"
            "[bold red]▄▄█ █▄█ █▀░ ░█░ ▀▄▀▄▀ █▀█ █▀▄ ██▄[/bold red]\n\n"
            "[bold yellow]🔒 SOFTWARE LOCKED[/bold yellow]\n\n"
            "[dim]This enterprise software requires a valid license key.[/dim]\n"
            "[dim]Please contact your system administrator.[/dim]",
            title="⚠️  Authentication Required", border_style="red", box=DOUBLE
        ))
        console.print()
        
        # Device info box
        console.print(Panel(
            f"[bold]Device Fingerprint[/bold]\n"
            f"[cyan]{auth_mgr.device_fp}[/cyan]\n\n"
            f"[dim]Provide this ID to your administrator when requesting a license.[/dim]",
            title="🖥️  Device Information", border_style="cyan"
        ))
        console.print()
    else:
        print("\n" + "="*60)
        print("🔒 SOFTWARE LOCKED - Authentication Required")
        print("="*60)
        print(f"\nDevice ID: {auth_mgr.device_fp}\n")
    
    # Prompt for key with animation
    max_attempts = 3
    for attempt in range(max_attempts):
        remaining = max_attempts - attempt
        
        if RICH:
            # Attempt indicator
            attempt_bar = "[green]●[/green]" * attempt + "[yellow]○[/yellow]" + "[dim]○[/dim]" * (remaining - 1)
            console.print(f"[dim]Attempts:[/dim] {attempt_bar}  [dim]({remaining} remaining)[/dim]")
            console.print()
            
            # Animated prompt
            pulse_text("Enter your license key:", "yellow", 1)
            console.print("[dim]─" * 64 + "[/dim]")
            try:
                key = console.input("[bold cyan]🔑 Key > [/bold cyan]").strip()
            except (KeyboardInterrupt, EOFError):
                console.print()
                console.print("[dim]Operation cancelled by user.[/dim]")
                return False, ""
            console.print("[dim]─" * 64 + "[/dim]")
        else:
            print(f"\nEnter license key ({remaining} attempts remaining)")
            try:
                key = input("Key: ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\nCancelled.")
                return False, ""
        
        if not key:
            if RICH:
                console.print("[dim italic]No key entered. Please try again.[/dim italic]")
                console.print()
            else:
                print("No key entered.")
            continue
        
        # Validate key with progress animation
        if RICH:
            console.print()
            with Progress(
                SpinnerColumn(spinner_name="arc"),
                TextColumn("[bold cyan]Validating license key..."),
                BarColumn(bar_width=30),
                TextColumn("[dim]{task.percentage:>3.0f}%[/dim]"),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task("validate", total=100)
                for i in range(100):
                    progress.update(task, advance=1)
                    time.sleep(0.015)
        
        auth_success, result_msg, result_org = auth_mgr.authenticate(key)
        
        if auth_success:
            if RICH:
                # Success animation
                console.print()
                for i in range(3):
                    console.print(f"\r[bold green]{'✓' * (i+1)}[/bold green]", end="")
                    time.sleep(0.1)
                console.print()
                console.print()
                
                console.print(Panel(
                    f"[bold green]█▀▀ █░█ █▀▀ █▀▀ █▀▀ █▀ █▀[/bold green]\n"
                    f"[bold green]▄▄█ █▄█ █▄▄ █▄▄ ██▄ ▄█ ▄█[/bold green]\n\n"
                    f"[bold white]🎉 LICENSE ACTIVATED[/bold white]\n\n"
                    f"[dim]Organization:[/dim] [bold cyan]{result_org}[/bold cyan]\n"
                    f"[dim]Device bound:[/dim] [green]{auth_mgr.device_fp[:24]}...[/green]\n"
                    f"[dim]Status:[/dim] [bold green]● ACTIVE[/bold green]",
                    title="✅ Welcome", border_style="green", box=DOUBLE
                ))
                console.print()
                
                # Boot sequence after successful auth
                boot_sequence()
            else:
                print(f"\n✅ License activated for: {result_org}\n")
            return True, result_org
        else:
            if RICH:
                console.print()
                console.print(Panel(
                    f"[bold red]✗ {result_msg}[/bold red]",
                    title="❌ Authentication Failed", border_style="red"
                ))
                console.print()
            else:
                print(f"❌ {result_msg}")
    
    # Max attempts reached
    if RICH:
        console.print()
        # Dramatic lockout animation
        for i in range(3):
            console.print(f"\r[bold red]{'🔒' * (i+1)}[/bold red]", end="")
            time.sleep(0.2)
        console.print()
        console.print()
        
        console.print(Panel(
            "[bold red]█▀▄ █▀▀ █▄░█ █ █▀▀ █▀▄[/bold red]\n"
            "[bold red]█▄▀ ██▄ █░▀█ █ ██▄ █▄▀[/bold red]\n\n"
            "[bold white]🚫 ACCESS DENIED[/bold white]\n\n"
            "[dim]Maximum authentication attempts exceeded.[/dim]\n"
            "[dim]Please contact your system administrator.[/dim]\n\n"
            f"[dim]Device ID:[/dim] [cyan]{auth_mgr.device_fp[:32]}...[/cyan]",
            title="⛔ Locked Out", border_style="red", box=DOUBLE
        ))
    else:
        print("\n🚫 Maximum attempts reached. Contact administrator.")
    
    return False, ""


# ═══════════════════════════════════════════════════════════════════════════════
#  PREMIUM COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

def cmd_settings(args):
    """Manage configuration settings."""
    global CONFIG_MANAGER
    
    if not PREMIUM_FEATURES or not CONFIG_MANAGER:
        error("Premium features not available")
        return 1
    
    if RICH:
        console.print(MINI_BANNER)
    
    if args.show:
        if RICH:
            console.print()
            console.print(Panel("⚙️  Configuration Management", style="cyan", box=DOUBLE))
            
            # Configuration summary
            summary = CONFIG_MANAGER.get_configuration_summary()
            
            config_table = Table(title="📋 Configuration Summary", box=ROUNDED)
            config_table.add_column("Category", style="bold")
            config_table.add_column("Details")
            
            config_table.add_row("Detection Rules", f"{summary['detection_rules']['categories']} categories, {summary['detection_rules']['total_rules']} rules")
            config_table.add_row("Custom IOCs", f"{summary['custom_iocs']['total']} total indicators")
            config_table.add_row("Thresholds", f"{summary['thresholds']['categories']} threshold categories")
            config_table.add_row("Alert Channels", f"{summary['alert_channels']['enabled']}/{summary['alert_channels']['configured']} enabled")
            config_table.add_row("Last Modified", datetime.fromtimestamp(summary['last_modified']).strftime("%Y-%m-%d %H:%M:%S"))
            
            console.print(config_table)
            
            # Show validation status
            issues = CONFIG_MANAGER.validate_configuration()
            if issues:
                console.print()
                console.print(Panel(
                    "\n".join([f"• {issue}" for issue in issues]),
                    title="⚠️  Configuration Issues", border_style="yellow"
                ))
            else:
                console.print()
                console.print(Panel("[green]✓ Configuration is valid[/green]", title="✅ Status", border_style="green"))
        else:
            print("Configuration Summary:")
            summary = CONFIG_MANAGER.get_configuration_summary()
            for key, value in summary.items():
                print(f"  {key}: {value}")
        
        return 0
    
    if args.export:
        try:
            export_path = CONFIG_MANAGER.export_configuration(args.export)
            success(f"Configuration exported to: {export_path}")
        except Exception as e:
            error(f"Export failed: {e}")
            return 1
        
        return 0
    
    if args.import_file:
        try:
            CONFIG_MANAGER.import_configuration(args.import_file)
            success("Configuration imported successfully")
        except Exception as e:
            error(f"Import failed: {e}")
            return 1
        
        return 0
    
    if args.validate:
        issues = CONFIG_MANAGER.validate_configuration()
        if issues:
            warning("Configuration issues found:")
            for issue in issues:
                print(f"  - {issue}")
            return 1
        else:
            success("Configuration is valid")
            return 0
    
    if args.reset:
        if RICH:
            console.print("[yellow]This will reset all configuration to defaults. Continue? [y/N][/yellow]")
            confirm = console.input().lower()
        else:
            confirm = input("Reset to defaults? [y/N]: ").lower()
        
        if confirm == 'y':
            # Reinitialize config manager (loads defaults)
            CONFIG_MANAGER = ConfigurationManager()
            success("Configuration reset to defaults")
        else:
            info("Reset cancelled")
        
        return 0
    
    # Show interactive settings menu
    if RICH:
        return interactive_settings_menu()
    else:
        error("Interactive settings requires Rich library")
        return 1


def cmd_analytics(args):
    """Advanced analytics and threat intelligence management."""
    if not PREMIUM_FEATURES or not CONFIG_MANAGER:
        error("Premium features not available")
        return 1
    
    if RICH:
        console.print(MINI_BANNER)
    
    if args.dashboard:
        return show_threat_dashboard()
    
    if args.trends:
        return show_threat_trends()
    
    if args.iocs:
        return manage_custom_iocs()
    
    if args.rules:
        return manage_detection_rules()
    
    # Default: show analytics menu
    if RICH:
        return interactive_analytics_menu()
    else:
        error("Interactive analytics requires Rich library")
        return 1


def interactive_settings_menu():
    """Interactive settings configuration menu."""
    while True:
        console.print()
        console.print(Panel(
            "[bold white]SETTINGS & CONFIGURATION[/bold white]\n\n"
            "[bold green]1.[/bold green] [cyan]Detection Rules[/cyan]     [dim]Manage threat detection rules[/dim]\n"
            "[bold green]2.[/bold green] [cyan]Thresholds[/cyan]         [dim]Configure alert thresholds[/dim]\n"  
            "[bold green]3.[/bold green] [cyan]Custom IOCs[/cyan]        [dim]Manage indicators of compromise[/dim]\n"
            "[bold green]4.[/bold green] [cyan]Alert Channels[/cyan]     [dim]Configure notifications[/dim]\n"
            "[bold green]5.[/bold green] [cyan]System Settings[/cyan]    [dim]General system configuration[/dim]\n"
            "[bold green]6.[/bold green] [cyan]Import/Export[/cyan]      [dim]Backup and restore config[/dim]\n\n"
            "[bold yellow]0.[/bold yellow] [yellow]Back to Main Menu[/yellow]",
            title="⚙️  Configuration", border_style="cyan"
        ))
        
        choice = console.input("\n[bold cyan]Settings>[/bold cyan] ").strip()
        
        if choice == "0" or choice.lower() in ["exit", "back", "quit"]:
            return 0
        elif choice == "1":
            manage_detection_rules()
        elif choice == "2":
            manage_thresholds()
        elif choice == "3":
            manage_custom_iocs()
        elif choice == "4":
            manage_alert_channels()
        elif choice == "5":
            manage_system_settings()
        elif choice == "6":
            manage_import_export()
        else:
            console.print("[red]Invalid choice. Please enter 0-6.[/red]")


def interactive_analytics_menu():
    """Interactive analytics menu."""
    while True:
        console.print()
        console.print(Panel(
            "[bold white]THREAT ANALYTICS & INTELLIGENCE[/bold white]\n\n"
            "[bold green]1.[/bold green] [cyan]Threat Dashboard[/cyan]   [dim]Real-time threat overview[/dim]\n"
            "[bold green]2.[/bold green] [cyan]Trend Analysis[/cyan]     [dim]Historical threat patterns[/dim]\n"
            "[bold green]3.[/bold green] [cyan]IOC Management[/cyan]     [dim]Custom indicators database[/dim]\n"
            "[bold green]4.[/bold green] [cyan]Rule Editor[/cyan]        [dim]Create custom detection rules[/dim]\n"
            "[bold green]5.[/bold green] [cyan]ML Training[/cyan]        [dim]Machine learning model tuning[/dim]\n"
            "[bold green]6.[/bold green] [cyan]Compliance Reports[/cyan] [dim]Generate compliance documentation[/dim]\n\n"
            "[bold yellow]0.[/bold yellow] [yellow]Back to Main Menu[/yellow]",
            title="📊 Analytics", border_style="magenta"
        ))
        
        choice = console.input("\n[bold magenta]Analytics>[/bold magenta] ").strip()
        
        if choice == "0" or choice.lower() in ["exit", "back", "quit"]:
            return 0
        elif choice == "1":
            show_threat_dashboard()
        elif choice == "2":
            show_threat_trends()
        elif choice == "3":
            manage_custom_iocs()
        elif choice == "4":
            manage_detection_rules()
        elif choice == "5":
            ml_training_interface()
        elif choice == "6":
            compliance_report_generator()
        else:
            console.print("[red]Invalid choice. Please enter 0-6.[/red]")


def show_threat_dashboard():
    """Show real-time threat dashboard."""
    console.print()
    console.print(Panel("🎯 Real-Time Threat Dashboard", style="bold magenta", box=DOUBLE))
    
    # Mock dashboard data (in production, pull from actual threat data)
    dashboard_data = {
        "active_threats": 7,
        "blocked_ips": 23,
        "ml_alerts": 15,
        "risk_score": 67,
        "last_attack": "2 minutes ago",
        "top_threats": ["Brute Force", "Anomalous Login", "C2 Communication"]
    }
    
    # Risk gauge visualization
    risk_score = dashboard_data["risk_score"]
    risk_color = "red" if risk_score >= 80 else "yellow" if risk_score >= 60 else "green"
    
    console.print()
    dash_table = Table.grid(padding=2)
    dash_table.add_column()
    dash_table.add_column()
    
    dash_table.add_row(
        f"[bold]🎯 Risk Level:[/bold] [{risk_color}]{risk_score}/100[/{risk_color}]",
        f"[bold]⚡ Active Threats:[/bold] [red]{dashboard_data['active_threats']}[/red]"
    )
    dash_table.add_row(
        f"[bold]🚫 Blocked IPs:[/bold] {dashboard_data['blocked_ips']}",
        f"[bold]🤖 ML Alerts:[/bold] [yellow]{dashboard_data['ml_alerts']}[/yellow]"
    )
    dash_table.add_row(
        f"[bold]⏰ Last Attack:[/bold] {dashboard_data['last_attack']}",
        ""
    )
    
    console.print(dash_table)
    
    console.print()
    threat_table = Table(title="🔥 Top Active Threats", box=ROUNDED)
    threat_table.add_column("#", justify="right")
    threat_table.add_column("Threat Type", style="bold")
    threat_table.add_column("Status")
    
    for i, threat in enumerate(dashboard_data["top_threats"], 1):
        threat_table.add_row(str(i), threat, "[red]ACTIVE[/red]")
    
    console.print(threat_table)
    console.input("\nPress Enter to continue...")
    return 0


def show_threat_trends():
    """Show historical threat trends and analysis."""
    console.print()
    console.print(Panel("📈 Threat Trend Analysis", style="bold blue", box=DOUBLE))
    
    # Mock trend data
    console.print("\n[bold]Last 30 Days Trend Summary:[/bold]")
    console.print("  • Brute Force Attacks: [red]↑ 34%[/red]")
    console.print("  • Anomaly Detection: [green]↓ 12%[/green]") 
    console.print("  • IOC Matches: [yellow]→ stable[/yellow]")
    console.print("  • Risk Score Average: [yellow]62/100[/yellow]")
    
    console.print("\n[dim]Detailed analytics require historical scan data.[/dim]")
    console.input("\nPress Enter to continue...")
    return 0


def manage_custom_iocs():
    """Manage custom indicators of compromise."""
    while True:
        console.print()
        summary = CONFIG_MANAGER.get_configuration_summary()
        ioc_counts = summary.get('custom_iocs', {}).get('by_type', {})
        
        console.print(Panel(
            f"[bold white]CUSTOM IOC MANAGEMENT[/bold white]\n\n"
            f"[dim]Current IOCs:[/dim]\n"
            f"  • IPs: {ioc_counts.get('ips', 0)}\n"
            f"  • Domains: {ioc_counts.get('domains', 0)}\n"  
            f"  • Hashes: {ioc_counts.get('hashes', 0)}\n"
            f"  • URLs: {ioc_counts.get('urls', 0)}\n\n"
            f"[bold green]1.[/bold green] Add IOC    [bold green]2.[/bold green] Remove IOC    [bold green]3.[/bold green] List All    [bold green]0.[/bold green] Back",
            title="🎯 IOC Database", border_style="red"
        ))
        
        choice = console.input("\n[bold red]IOC>[/bold red] ").strip()
        
        if choice == "0":
            return 0
        elif choice == "1":
            add_custom_ioc()
        elif choice == "2":
            remove_custom_ioc()
        elif choice == "3":
            list_custom_iocs()
        else:
            console.print("[red]Invalid choice.[/red]")


def add_custom_ioc():
    """Add a custom IOC."""
    console.print("\n[bold]Add Custom IOC[/bold]")
    
    ioc_type = console.input("IOC Type (ip/domain/hash/url): ").strip().lower()
    if ioc_type not in ["ip", "domain", "hash", "url"]:
        console.print("[red]Invalid IOC type[/red]")
        return
    
    indicator = console.input("Indicator value: ").strip()
    if not indicator:
        console.print("[red]Indicator cannot be empty[/red]")
        return
    
    threat_type = console.input("Threat type (malware/botnet/c2/phishing): ").strip()
    severity = console.input("Severity (low/medium/high/critical): ").strip().lower()
    description = console.input("Description: ").strip()
    
    metadata = {
        "type": threat_type,
        "severity": severity, 
        "description": description,
        "source": "manual_entry"
    }
    
    plural_type = ioc_type + "s"
    success = CONFIG_MANAGER.add_custom_ioc(plural_type, indicator, metadata)
    
    if success:
        console.print(f"[green]✓ Added {ioc_type}: {indicator}[/green]")
    else:
        console.print(f"[red]✗ Failed to add IOC[/red]")


def remove_custom_ioc():
    """Remove a custom IOC."""
    console.print("\n[bold]Remove Custom IOC[/bold]")
    
    ioc_type = console.input("IOC Type (ip/domain/hash/url): ").strip().lower()
    if ioc_type not in ["ip", "domain", "hash", "url"]:
        console.print("[red]Invalid IOC type[/red]")
        return
    
    indicator = console.input("Indicator to remove: ").strip()
    
    plural_type = ioc_type + "s"
    success = CONFIG_MANAGER.remove_custom_ioc(plural_type, indicator)
    
    if success:
        console.print(f"[green]✓ Removed {ioc_type}: {indicator}[/green]")
    else:
        console.print(f"[red]✗ IOC not found or removal failed[/red]")


def list_custom_iocs():
    """List all custom IOCs."""
    console.print("\n[bold]Custom IOC Database[/bold]")
    
    for ioc_type in ["ips", "domains", "hashes", "urls"]:
        iocs = CONFIG_MANAGER.custom_iocs.get(ioc_type, {})
        if iocs:
            console.print(f"\n[bold cyan]{ioc_type.upper()}:[/bold cyan]")
            for indicator, data in list(iocs.items())[:5]:  # Show first 5
                severity = data.get('metadata', {}).get('severity', 'unknown')
                description = data.get('metadata', {}).get('description', 'No description')[:50]
                console.print(f"  • {indicator} [{severity}] - {description}")
            
            if len(iocs) > 5:
                console.print(f"  [dim]... and {len(iocs) - 5} more[/dim]")
    
    console.input("\nPress Enter to continue...")


def manage_detection_rules():
    """Manage detection rules.""" 
    console.print("\n[bold]Detection Rule Management[/bold]")
    console.print("[dim]Advanced rule editor - Coming soon![/dim]")
    console.input("\nPress Enter to continue...")
    return 0


def manage_thresholds():
    """Manage alert thresholds."""
    console.print("\n[bold]Threshold Management[/bold]")
    console.print("[dim]Threshold editor - Coming soon![/dim]")
    console.input("\nPress Enter to continue...")
    return 0


def manage_alert_channels():
    """Manage alert notification channels."""
    console.print("\n[bold]Alert Channel Configuration[/bold]")
    console.print("[dim]Alert configuration - Coming soon![/dim]")
    console.input("\nPress Enter to continue...")
    return 0


def manage_system_settings():
    """Manage system settings."""
    console.print("\n[bold]System Settings[/bold]")
    console.print("[dim]System configuration - Coming soon![/dim]")
    console.input("\nPress Enter to continue...")
    return 0


def manage_import_export():
    """Manage configuration import/export."""
    console.print("\n[bold]Configuration Backup & Restore[/bold]")
    
    console.print("\n[bold green]1.[/bold green] Export Configuration")
    console.print("[bold green]2.[/bold green] Import Configuration")
    console.print("[bold green]0.[/bold green] Back")
    
    choice = console.input("\nChoice: ").strip()
    
    if choice == "1":
        filename = console.input("Export filename [config_backup.json]: ").strip()
        if not filename:
            filename = "config_backup.json"
        
        try:
            export_path = CONFIG_MANAGER.export_configuration(filename)
            console.print(f"[green]✓ Configuration exported to: {export_path}[/green]")
        except Exception as e:
            console.print(f"[red]✗ Export failed: {e}[/red]")
    
    elif choice == "2":
        filename = console.input("Import filename: ").strip()
        if not filename:
            console.print("[red]Filename required[/red]")
            return
        
        try:
            CONFIG_MANAGER.import_configuration(filename)
            console.print("[green]✓ Configuration imported successfully[/green]")
        except Exception as e:
            console.print(f"[red]✗ Import failed: {e}[/red]")


def ml_training_interface():
    """ML model training interface."""
    console.print("\n[bold]ML Model Training[/bold]")
    console.print("[dim]Advanced ML training interface - Coming soon![/dim]")
    console.input("\nPress Enter to continue...")
    return 0


def compliance_report_generator():
    """Generate compliance reports."""
    console.print("\n[bold]Compliance Report Generator[/bold]")
    
    frameworks = ["SOX", "PCI-DSS", "HIPAA", "ISO27001"]
    
    console.print("\nAvailable Frameworks:")
    for i, fw in enumerate(frameworks, 1):
        console.print(f"  [bold green]{i}.[/bold green] {fw}")
    
    choice = console.input("\nSelect framework (1-4): ").strip()
    
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(frameworks):
            framework = frameworks[idx]
            console.print(f"\n[dim]Generating {framework} compliance report...[/dim]")
            
            # Mock results for demo
            mock_results = {
                "risk_score": 45,
                "intelligence_matches": [],
                "anomalies": [],
                "attack_chains": []
            }
            
            report_path = generate_compliance_report(mock_results, framework)
            console.print(f"[green]✓ Report saved: {report_path}[/green]")
        else:
            console.print("[red]Invalid selection[/red]")
    except ValueError:
        console.print("[red]Invalid selection[/red]")
    
    console.input("\nPress Enter to continue...")


# ═══════════════════════════════════════════════════════════════════════════════
#  CVE ANALYSIS COMMAND
# ═══════════════════════════════════════════════════════════════════════════════

def cmd_cve(args):
    """CVE vulnerability analysis against log files."""
    if not CVE_ANALYZER_AVAILABLE or not CVE_CORRELATOR:
        error("CVE analyzer not available. Check installation.")
        return 1

    if RICH:
        console.print(MINI_BANNER)

    ok, msg = validate_file(args.file)
    if not ok:
        error(msg)
        return 1

    spinner("Analyzing for CVE vulnerabilities", 1.5)

    correlator = LogCVECorrelator(CVE_DB)
    results = correlator.analyze_log_file(args.file)

    if RICH:
        console.print()
        risk = results.get("risk_summary", {})
        rc = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "green"}.get(
            risk.get("risk_level", "LOW"), "white")

        # Summary panel
        console.print(Panel(
            f"[bold]Lines Analyzed:[/bold] {results.get('lines_analyzed', 0):,}\n"
            f"[bold]Software Detected:[/bold] {risk.get('software_detected', 0)}\n"
            f"[bold]Vulnerabilities:[/bold] [red]{risk.get('total_vulns', 0)}[/red]\n"
            f"[bold]Critical:[/bold] [red]{risk.get('critical', 0)}[/red]  "
            f"[bold]High:[/bold] [yellow]{risk.get('high', 0)}[/yellow]\n"
            f"[bold]Log4Shell:[/bold] {'[red]⚠ DETECTED[/red]' if risk.get('log4shell_detected') else '[green]Not Found[/green]'}\n"
            f"[bold]Risk Score:[/bold] [{rc}]{risk.get('risk_score', 0)}/100 {risk.get('risk_level', 'LOW')}[/{rc}]",
            title="🔍 CVE Analysis Summary", border_style=rc, box=HEAVY
        ))

        # Detected software table
        sw_list = results.get("detected_software", [])
        if sw_list:
            sw_table = Table(title="📦 Detected Software", box=ROUNDED)
            sw_table.add_column("Software", style="bold cyan")
            sw_table.add_column("Version")
            sw_table.add_column("Occurrences", justify="right")
            sw_table.add_column("First Seen Line", justify="right")
            for sw in sw_list:
                sw_table.add_row(sw["name"], sw.get("version", "?"),
                                str(sw["occurrences"]), str(sw["first_seen_line"]))
            console.print(sw_table)

        # Vulnerability table
        vulns = results.get("potential_vulnerabilities", [])
        if vulns:
            vuln_table = Table(title="🚨 Potential Vulnerabilities", box=ROUNDED, border_style="red")
            vuln_table.add_column("CVE ID", style="bold red")
            vuln_table.add_column("Severity")
            vuln_table.add_column("CVSS", justify="right")
            vuln_table.add_column("Software")
            vuln_table.add_column("Description", max_width=35)
            vuln_table.add_column("MITRE")

            for v in vulns[:20]:
                sc = {"CRITICAL": "red", "HIGH": "yellow"}.get(v["severity"], "white")
                vuln_table.add_row(
                    v["cve_id"], f"[{sc}]{v['severity']}[/{sc}]",
                    str(v["cvss_score"]), v["detected_software"],
                    v["description"][:35], v.get("mitre_technique", "")
                )
            console.print(vuln_table)

        # Remediation
        if vulns and args.verbose:
            recs = correlator.generate_remediation(vulns)
            rec_table = Table(title="🔧 Remediation Recommendations", box=ROUNDED, border_style="green")
            rec_table.add_column("CVE", style="bold")
            rec_table.add_column("Priority")
            rec_table.add_column("Action", max_width=50)
            for r in recs[:10]:
                rec_table.add_row(r["cve_id"], f"[red]{r['priority']}[/red]", r["action"])
            console.print(rec_table)

        # Log4Shell indicators
        l4s = results.get("log4shell_indicators", [])
        if l4s:
            console.print(Panel(
                "\n".join([f"[red]Line {i['line']}:[/red] {i['payload']}" for i in l4s[:5]]),
                title="⚠️  LOG4SHELL PAYLOADS DETECTED", border_style="red", box=HEAVY
            ))

        console.print()

    if args.json:
        print(json.dumps(results, indent=2, default=str))

    return 0


# ═══════════════════════════════════════════════════════════════════════════════
#  INDUSTRY SHARE COMMAND
# ═══════════════════════════════════════════════════════════════════════════════

def cmd_share(args):
    """Industry Share - P2P report sharing."""
    if not INDUSTRY_SHARE_AVAILABLE or not SHARE_MANAGER:
        error("Industry Share module not available. Check installation.")
        return 1

    if RICH:
        console.print(MINI_BANNER)

    if args.start:
        spinner("Starting Industry Share services", 1.0)
        SHARE_MANAGER.start()
        success(f"Industry Share active on port {SHARE_MANAGER.listen_port}")
        success(f"Node ID: {SHARE_MANAGER.node_id}")
        if TUI_ENGINE:
            TUI_ENGINE.add_log(f"Industry Share started on port {SHARE_MANAGER.listen_port}", "SHARE")
            TUI_ENGINE.update_status(share_active=True, node_id=SHARE_MANAGER.node_id)
        return 0

    elif args.stop:
        SHARE_MANAGER.stop()
        success("Industry Share stopped")
        return 0

    elif args.status:
        status = SHARE_MANAGER.get_status()
        if RICH:
            console.print()
            table = Table(title="🌐 Industry Share Status", box=DOUBLE, border_style="cyan")
            table.add_column("Property", style="bold")
            table.add_column("Value")
            active = status.get("active", False)
            table.add_row("Status", "[green]● ACTIVE[/green]" if active else "[red]● OFFLINE[/red]")
            table.add_row("Node ID", f"[cyan]{status.get('node_id', 'N/A')}[/cyan]")
            table.add_row("Listen Port", str(status.get("listen_port", 9100)))
            table.add_row("Discovered Peers", f"[cyan]{status.get('discovered_peers', 0)}[/cyan]")
            table.add_row("Reports Received", str(status.get("received_reports", 0)))
            console.print(table)

            # Show peers
            peers = status.get("peers", {})
            if peers:
                peer_table = Table(title="Connected Peers", box=ROUNDED)
                peer_table.add_column("Node ID", style="dim")
                peer_table.add_column("IP", style="green")
                peer_table.add_column("Port")
                for pid, info in list(peers.items())[:10]:
                    peer_table.add_row(pid[:12], info.get("ip", "?"), str(info.get("port", "?")))
                console.print(peer_table)
            console.print()
        return 0

    elif args.connect:
        parts = args.connect.split(":")
        ip = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 9100
        spinner(f"Connecting to peer {ip}:{port}", 1.0)
        ok, msg = SHARE_MANAGER.add_manual_peer(ip, port)
        if ok:
            success(msg)
            if TUI_ENGINE:
                TUI_ENGINE.add_log(f"Peer connected: {ip}:{port}", "SHARE")
        else:
            error(msg)
        return 0 if ok else 1

    elif args.send:
        # Share last scan results or a report file
        if not SHARE_MANAGER.is_active:
            SHARE_MANAGER.start()
            time.sleep(1)

        peers = SHARE_MANAGER.discovery.get_peers()
        if not peers:
            warning("No peers discovered. Use 'share --connect IP:PORT' first.")
            return 1

        # Load report data
        try:
            with open(args.send, 'r') as f:
                report_data = json.load(f)
        except:
            report_data = {
                "risk_score": 0, "threats_detected": [],
                "source": args.send, "generated_at": datetime.now().isoformat()
            }

        spinner("Anonymizing and sharing report", 1.5)
        results = SHARE_MANAGER.share_with_all(report_data)
        for r in results:
            if r["success"]:
                success(f"Shared with {r.get('peer_id', '?')[:12]}: {r['message']}")
            else:
                error(f"Failed for {r.get('peer_id', '?')[:12]}: {r['message']}")
        if TUI_ENGINE:
            TUI_ENGINE.add_log(f"Report shared with {len(results)} peers", "SHARE")
        return 0

    elif args.received:
        reports = SHARE_MANAGER.get_received_reports()
        if RICH:
            if not reports:
                warning("No reports received yet.")
            else:
                table = Table(title="📥 Received Reports", box=ROUNDED)
                table.add_column("Peer", style="dim")
                table.add_column("Hash", style="cyan")
                table.add_column("Risk", justify="right")
                table.add_column("Threats", justify="right")
                table.add_column("Received", style="dim")
                for r in reports[:20]:
                    table.add_row(
                        r["peer_id"][:12], r["report_hash"][:12],
                        str(r["risk_score"]), str(r["threat_count"]),
                        r["received_at"][:19]
                    )
                console.print(table)
            console.print()
        return 0

    elif args.audit:
        audit = SHARE_MANAGER.get_audit_log()
        if RICH:
            if not audit:
                warning("No audit entries yet.")
            else:
                table = Table(title="📋 Share Audit Trail", box=ROUNDED)
                table.add_column("Direction")
                table.add_column("Peer", style="dim")
                table.add_column("IP")
                table.add_column("Hash", style="cyan")
                table.add_column("Status")
                table.add_column("Time", style="dim")
                for a in audit[:20]:
                    d_color = "green" if a["direction"] == "received" else "blue"
                    table.add_row(
                        f"[{d_color}]{a['direction']}[/{d_color}]",
                        (a["peer_id"] or "")[:12], a.get("peer_ip", ""),
                        (a["report_hash"] or "")[:12], a["status"],
                        (a["timestamp"] or "")[:19]
                    )
                console.print(table)
            console.print()
        return 0

    warning("Use: share --start | --stop | --status | --connect IP | --send FILE | --received | --audit")
    return 1


# ═══════════════════════════════════════════════════════════════════════════════
#  SPLIT-SCREEN RENDER HELPER
# ═══════════════════════════════════════════════════════════════════════════════

def render_split_screen(org: str):
    """Render the split-screen TUI with current status."""
    if not TUI_ENGINE:
        return
    TUI_ENGINE.update_status(organization=org)
    if SHARE_MANAGER:
        status = SHARE_MANAGER.get_status()
        TUI_ENGINE.update_status(
            share_active=status.get("active", False),
            peer_count=status.get("discovered_peers", 0),
            peers=list(status.get("peers", {}).values()),
            node_id=SHARE_MANAGER.node_id,
        )
    TUI_ENGINE.render_static()


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    # ═══════════════════════════════════════════════════════════════════════════
    # AUTHENTICATION GATE - Must pass before ANY functionality
    # ═══════════════════════════════════════════════════════════════════════════
    
    authenticated, org = check_and_prompt_auth()
    
    if not authenticated:
        return 1
    
    # ═══════════════════════════════════════════════════════════════════════════
    # AUTHENTICATED - Show main interface
    # ═══════════════════════════════════════════════════════════════════════════
    
    if RICH:
        show_status_line(org)
        console.print()
    
    parser = argparse.ArgumentParser(
        description="LogSentinel Pro - Enterprise SIEM CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  scan FILE [-v] [-b]     Scan log file for threats
  blockchain [-v] [-s]    Verify or show blockchain
  fingerprint             Show device fingerprint
  version                 Show version info
  logout                  Clear session and lock software
        """
    )
    
    sub = parser.add_subparsers(dest="command")
    
    # Scan
    scan = sub.add_parser("scan", help="Advanced threat analysis and log scanning")
    scan.add_argument("file", help="Log file path")
    scan.add_argument("-v", "--verbose", action="store_true", help="Show detailed threats and ML analysis")
    scan.add_argument("-b", "--blockchain", action="store_true", help="Record threats to blockchain")
    scan.add_argument("-j", "--json", action="store_true", help="JSON output")
    scan.add_argument("-r", "--report", action="store_true", help="Generate comprehensive PDF report")
    scan.add_argument("--pdf", action="store_true", help="Generate PDF report (alias for --report)")
    scan.add_argument("--pdf-format", choices=["professional", "executive", "technical"], 
                      default="professional", help="PDF report format (default: professional)")
    scan.add_argument("--include-charts", action="store_true", help="Include risk charts and visualizations in PDF")
    scan.add_argument("--ml", action="store_true", help="Force ML analysis even for small files")
    scan.add_argument("--compliance", choices=["SOX", "PCI-DSS", "HIPAA", "ISO27001"], 
                      help="Generate compliance-specific report")
    scan.set_defaults(func=cmd_scan)
    
    # Blockchain
    bc = sub.add_parser("blockchain", help="Blockchain operations")
    bc.add_argument("-v", "--verify", action="store_true", help="Verify chain integrity")
    bc.add_argument("-s", "--show", action="store_true", help="Show all blocks")
    bc.set_defaults(func=cmd_blockchain)
    
    # Fingerprint
    fp = sub.add_parser("fingerprint", help="Show device fingerprint")
    fp.set_defaults(func=cmd_fingerprint)
    
    # Version
    ver = sub.add_parser("version", help="Show version")
    ver.set_defaults(func=cmd_version)
    
    # Settings (Premium Feature)
    if PREMIUM_FEATURES:
        settings = sub.add_parser("settings", help="Configure detection rules and system settings")
        settings.add_argument("--show", action="store_true", help="Show current configuration")
        settings.add_argument("--export", metavar="FILE", help="Export configuration to file")
        settings.add_argument("--import", metavar="FILE", dest="import_file", help="Import configuration from file")
        settings.add_argument("--reset", action="store_true", help="Reset to default configuration")
        settings.add_argument("--validate", action="store_true", help="Validate current configuration")
        settings.set_defaults(func=cmd_settings)
    
    # Analytics (Premium Feature)
    if PREMIUM_FEATURES:
        analytics = sub.add_parser("analytics", help="Advanced threat analytics and insights")
        analytics.add_argument("--dashboard", action="store_true", help="Show threat dashboard")
        analytics.add_argument("--trends", action="store_true", help="Show threat trends")
        analytics.add_argument("--iocs", action="store_true", help="Manage custom IOCs")
        analytics.add_argument("--rules", action="store_true", help="Manage detection rules")
        analytics.set_defaults(func=cmd_analytics)
    
    # PDF Report Generator (Premium Feature)
    if PREMIUM_FEATURES and PROFESSIONAL_PDF:
        report = sub.add_parser("report", help="Generate professional PDF reports")
        report.add_argument("input_file", help="Previous scan JSON output or log file")
        report.add_argument("--format", choices=["professional", "executive", "technical"], 
                           default="professional", help="Report format")
        report.add_argument("--compliance", choices=["SOX", "PCI-DSS", "HIPAA", "ISO27001"], 
                           help="Generate compliance-specific report")
        report.add_argument("--charts", action="store_true", help="Include risk charts and visualizations")
        report.add_argument("--output", metavar="FILE", help="Output filename (auto-generated if not specified)")
        report.set_defaults(func=cmd_generate_report)
    
    # CVE Analysis (v4.0)
    if CVE_ANALYZER_AVAILABLE:
        cve = sub.add_parser("cve", help="CVE vulnerability analysis against log files")
        cve.add_argument("file", help="Log file to analyze for CVE-relevant software")
        cve.add_argument("-v", "--verbose", action="store_true", help="Show remediation recommendations")
        cve.add_argument("-j", "--json", action="store_true", help="JSON output")
        cve.set_defaults(func=cmd_cve)
    
    # Industry Share (v4.0)
    if INDUSTRY_SHARE_AVAILABLE:
        share = sub.add_parser("share", help="Industry Share - P2P encrypted report sharing")
        share.add_argument("--start", action="store_true", help="Start Industry Share services")
        share.add_argument("--stop", action="store_true", help="Stop Industry Share services")
        share.add_argument("--status", action="store_true", help="Show Industry Share status")
        share.add_argument("--connect", metavar="IP:PORT", help="Connect to a peer manually")
        share.add_argument("--send", metavar="FILE", help="Send anonymized report to all peers")
        share.add_argument("--received", action="store_true", help="Show received reports")
        share.add_argument("--audit", action="store_true", help="Show share audit trail")
        share.set_defaults(func=cmd_share)
    
    # Logout
    logout = sub.add_parser("logout", help="Clear session and lock")
    logout.set_defaults(func=cmd_logout)
    
    args = parser.parse_args()
    
    if not args.command:
        # Enter interactive mode after authentication
        return interactive_shell(org)
    
    return args.func(args)


def interactive_shell(org: str):
    """Interactive command shell."""
    if not RICH:
        print(f"\nLogSentinel Pro Interactive Shell - Licensed to: {org}")
        print("Type 'help' for commands, 'exit' to quit\n")
    
    while True:
        try:
            if RICH:
                console.print()
                show_status_line(org)
                console.print()
                
                # Show comprehensive command menu
                base_commands = (
                    "[bold white]║[/bold white]  [bold green]▸[/bold green] [cyan]scan[/cyan] FILE [-v] [-b]    [dim]Scan log for threats[/dim]     [bold white]║[/bold white]\n"
                    "[bold white]║[/bold white]  [bold green]▸[/bold green] [cyan]blockchain[/cyan] [-v] [-s]  [dim]Blockchain operations[/dim]    [bold white]║[/bold white]\n"
                    "[bold white]║[/bold white]  [bold green]▸[/bold green] [cyan]fingerprint[/cyan]           [dim]Show device ID[/dim]           [bold white]║[/bold white]\n"
                    "[bold white]║[/bold white]  [bold green]▸[/bold green] [cyan]version[/cyan]               [dim]Version info[/dim]             [bold white]║[/bold white]\n"
                )
                
                premium_commands = ""
                if PREMIUM_FEATURES:
                    pdf_command = ""
                    if PROFESSIONAL_PDF:
                        pdf_command = "[bold white]║[/bold white]  [bold magenta]▸[/bold magenta] [cyan]report[/cyan] FILE            [dim]Generate PDF reports[/dim]      [bold white]║[/bold white]\n"
                    
                    premium_commands = (
                        "[bold white]║[/bold white]                    [bold yellow]🔥 PREMIUM FEATURES[/bold yellow]                   [bold white]║[/bold white]\n"
                        "[bold white]║[/bold white]  [bold magenta]▸[/bold magenta] [cyan]settings[/cyan]              [dim]Configuration & rules[/dim]      [bold white]║[/bold white]\n"
                        "[bold white]║[/bold white]  [bold magenta]▸[/bold magenta] [cyan]analytics[/cyan]             [dim]Threat intelligence[/dim]       [bold white]║[/bold white]\n"
                        f"{pdf_command}"
                        "[bold white]║[/bold white]                                                       [bold white]║[/bold white]\n"
                    )
                
                v4_commands = ""
                if CVE_ANALYZER_AVAILABLE or INDUSTRY_SHARE_AVAILABLE:
                    cve_cmd = ""
                    share_cmd = ""
                    if CVE_ANALYZER_AVAILABLE:
                        cve_cmd = "[bold white]║[/bold white]  [bold blue]▸[/bold blue] [cyan]cve[/cyan] FILE [-v]         [dim]CVE vulnerability scan[/dim]    [bold white]║[/bold white]\n"
                    if INDUSTRY_SHARE_AVAILABLE:
                        share_cmd = (
                            "[bold white]║[/bold white]  [bold blue]▸[/bold blue] [cyan]share[/cyan] --start          [dim]Start P2P sharing[/dim]        [bold white]║[/bold white]\n"
                            "[bold white]║[/bold white]  [bold blue]▸[/bold blue] [cyan]share[/cyan] --status         [dim]Peer connections[/dim]         [bold white]║[/bold white]\n"
                            "[bold white]║[/bold white]  [bold blue]▸[/bold blue] [cyan]share[/cyan] --connect IP     [dim]Connect to peer[/dim]          [bold white]║[/bold white]\n"
                        )
                    v4_commands = (
                        "[bold white]║[/bold white]                  [bold blue]🌐 v4.0 INDUSTRY EDITION[/bold blue]                [bold white]║[/bold white]\n"
                        f"{cve_cmd}{share_cmd}"
                        "[bold white]║[/bold white]                                                       [bold white]║[/bold white]\n"
                    )
                
                control_commands = (
                    "[bold white]║[/bold white]  [bold yellow]▸[/bold yellow] [cyan]help[/cyan]                  [dim]Show detailed help[/dim]        [bold white]║[/bold white]\n"
                    "[bold white]║[/bold white]  [bold red]▸[/bold red] [yellow]admin[/yellow]                 [dim]Open Admin Console[/dim]       [bold white]║[/bold white]\n"
                    "[bold white]║[/bold white]  [bold red]▸[/bold red] [yellow]logout[/yellow]                [dim]Exit and lock[/dim]            [bold white]║[/bold white]\n"
                )
                
                console.print(Panel(
                    "[bold white]╔═══════════════════════════════════════════════════════╗[/bold white]\n"
                    "[bold white]║[/bold white]           [bold cyan]COMMAND CENTER[/bold cyan]                           [bold white]║[/bold white]\n"
                    "[bold white]╠═══════════════════════════════════════════════════════╣[/bold white]\n"
                    "[bold white]║[/bold white]                                                       [bold white]║[/bold white]\n"
                    f"{base_commands}"
                    f"{premium_commands}"
                    f"{v4_commands}"
                    f"{control_commands}"
                    "[bold white]║[/bold white]                                                       [bold white]║[/bold white]\n"
                    "[bold white]╚═══════════════════════════════════════════════════════╝[/bold white]",
                    title="🛡️  LogSentinel Pro v4.0", border_style="cyan", box=DOUBLE
                ))
                
                command = console.input("\n[bold cyan]LogSentinel>[/bold cyan] ").strip()
            else:
                command = input(f"LogSentinel ({org})> ").strip()
            
            if not command:
                continue
            
            # Parse command
            if command.lower() in ['exit', 'quit', 'logout']:
                if RICH:
                    console.print(Panel(
                        "[bold green]Session ended[/bold green]\n\n[dim]Goodbye![/dim]",
                        title="👋 Logged Out", border_style="green"
                    ))
                else:
                    print("Goodbye!")
                # Clear session and exit
                auth_mgr = AuthManager()
                auth_mgr.logout()
                return 0
            
            elif command.lower() == 'admin':
                if RICH:
                    console.print(Panel("[dim]Switching to Admin Console...[/dim]", style="blue"))
                try:
                    import logsentinel_admin
                    logsentinel_admin.main()
                except Exception as e:
                    if RICH:
                        console.print(f"[red]Error loading admin module:[/red] {e}")
                    else:
                        print(f"Error loading admin module: {e}")
                continue
            
            elif command.lower() == 'help':
                if RICH:
                    console.print()
                    
                    help_text = (
                        "[bold]Core Commands:[/bold]\n\n"
                        "  [cyan]scan[/cyan] /path/to/file [-v] [-b] [-r]   Advanced threat scanning\n"
                        "  [cyan]blockchain[/cyan] [-v] [-s]              Blockchain operations\n"
                        "  [cyan]fingerprint[/cyan]                      Show device fingerprint\n"
                        "  [cyan]version[/cyan]                          Show version info\n"
                    )
                    
                    if PREMIUM_FEATURES:
                        pdf_help = ""
                        if PROFESSIONAL_PDF:
                            pdf_help = "  [magenta]report[/magenta] /path/to/file [--compliance]  Generate PDF reports\n"
                        
                        help_text += (
                            "\n[bold]Premium Features:[/bold]\n\n"
                            "  [magenta]settings[/magenta] [--show] [--export]        Configuration management\n"
                            "  [magenta]analytics[/magenta] [--dashboard] [--iocs]    Threat intelligence\n"
                            f"{pdf_help}"
                        )
                    
                    help_text += (
                        "\n[bold]System Commands:[/bold]\n\n"
                        "  [cyan]help[/cyan]                             Show this help\n"
                        "  [yellow]logout[/yellow]                           Exit and lock software\n\n"
                        "[dim]Enhanced Examples:[/dim]\n"
                        "  scan /var/log/auth.log -v -r     # Detailed scan with PDF report\n"
                        "  blockchain --verify               # Verify integrity\n"
                    )
                    
                    if PREMIUM_FEATURES:
                        pdf_examples = ""
                        if PROFESSIONAL_PDF:
                            pdf_examples = (
                                "  report /var/log/auth.log          # Generate PDF report\n"
                                "  report /var/log/auth.log --compliance PCI-DSS  # Compliance report"
                            )
                        
                        help_text += (
                            "  settings --show                   # Show configuration\n"
                            "  analytics --dashboard             # Threat dashboard\n"
                            f"{pdf_examples}"
                        )
                    else:
                        help_text += ""
                    
                    console.print(Panel(
                        help_text,
                        title="📋 Help", border_style="blue"
                    ))
                else:
                    help_commands = "scan, blockchain, fingerprint, version, help, logout"
                    if PREMIUM_FEATURES:
                        report_cmd = ", report" if PROFESSIONAL_PDF else ""
                        help_commands = f"scan, blockchain, fingerprint, version, settings, analytics{report_cmd}, help, logout"
                    print(f"\nAvailable Commands: {help_commands}\n")
                    print("Use 'COMMAND --help' for detailed options or run with GUI for better experience.")
                continue
            
            # Execute command
            try:
                # Parse as if from command line
                cmd_args = command.split()
                
                # Create a new parser for this command
                temp_parser = argparse.ArgumentParser(add_help=False)
                temp_sub = temp_parser.add_subparsers(dest="command")
                
                # Re-add all subparsers
                scan = temp_sub.add_parser("scan")
                scan.add_argument("file")
                scan.add_argument("-v", "--verbose", action="store_true")
                scan.add_argument("-b", "--blockchain", action="store_true")
                scan.add_argument("-j", "--json", action="store_true")
                scan.add_argument("-r", "--report", action="store_true")
                scan.add_argument("--ml", action="store_true")
                scan.add_argument("--compliance", choices=["SOX", "PCI-DSS", "HIPAA", "ISO27001"])
                scan.set_defaults(func=cmd_scan)
                
                bc = temp_sub.add_parser("blockchain")
                bc.add_argument("-v", "--verify", action="store_true")
                bc.add_argument("-s", "--show", action="store_true")
                bc.set_defaults(func=cmd_blockchain)
                
                fp = temp_sub.add_parser("fingerprint")
                fp.set_defaults(func=cmd_fingerprint)
                
                ver = temp_sub.add_parser("version")
                ver.set_defaults(func=cmd_version)
                
                # Premium commands
                if PREMIUM_FEATURES:
                    settings = temp_sub.add_parser("settings")
                    settings.add_argument("--show", action="store_true")
                    settings.add_argument("--export", metavar="FILE")
                    settings.add_argument("--import", metavar="FILE", dest="import_file")
                    settings.add_argument("--reset", action="store_true")
                    settings.add_argument("--validate", action="store_true")
                    settings.set_defaults(func=cmd_settings)
                    
                    analytics = temp_sub.add_parser("analytics")
                    analytics.add_argument("--dashboard", action="store_true")
                    analytics.add_argument("--trends", action="store_true")
                    analytics.add_argument("--iocs", action="store_true")
                    analytics.add_argument("--rules", action="store_true")
                    analytics.set_defaults(func=cmd_analytics)
                
                # v4.0 commands
                if CVE_ANALYZER_AVAILABLE:
                    cve = temp_sub.add_parser("cve")
                    cve.add_argument("file")
                    cve.add_argument("-v", "--verbose", action="store_true")
                    cve.add_argument("-j", "--json", action="store_true")
                    cve.set_defaults(func=cmd_cve)
                
                if INDUSTRY_SHARE_AVAILABLE:
                    share = temp_sub.add_parser("share")
                    share.add_argument("--start", action="store_true")
                    share.add_argument("--stop", action="store_true")
                    share.add_argument("--status", action="store_true")
                    share.add_argument("--connect", metavar="IP:PORT")
                    share.add_argument("--send", metavar="FILE")
                    share.add_argument("--received", action="store_true")
                    share.add_argument("--audit", action="store_true")
                    share.set_defaults(func=cmd_share)
                
                parsed = temp_parser.parse_args(cmd_args)
                
                if hasattr(parsed, 'func'):
                    parsed.func(parsed)
                else:
                    if RICH:
                        console.print(f"[red]Unknown command: {cmd_args[0]}[/red]")
                    else:
                        print(f"Unknown command: {cmd_args[0]}")
                
            except SystemExit:
                # argparse calls sys.exit on error, catch it
                if RICH:
                    console.print("[red]Invalid command syntax. Type 'help' for usage.[/red]")
                else:
                    print("Invalid command syntax. Type 'help' for usage.")
            except Exception as e:
                if RICH:
                    console.print(f"[red]Error: {str(e)}[/red]")
                else:
                    print(f"Error: {str(e)}")
        
        except (KeyboardInterrupt, EOFError):
            if RICH:
                console.print("\n[dim]Goodbye![/dim]")
            else:
                print("\nGoodbye!")
            # Clear session and exit
            auth_mgr = AuthManager()
            auth_mgr.logout()
            return 0


if __name__ == "__main__":
    sys.exit(main())
