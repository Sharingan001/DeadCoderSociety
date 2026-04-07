#!/usr/bin/env python3
"""
LogSentinel Pro v3.0 - Enterprise SIEM CLI
Beautiful terminal interface with animations and rich formatting.
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
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

# Rich imports for beautiful CLI
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich.style import Style
    from rich.box import DOUBLE, ROUNDED, HEAVY
    from rich import print as rprint
    from rich.tree import Tree
    from rich.markdown import Markdown
    from rich.align import Align
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Initialize console
console = Console() if RICH_AVAILABLE else None

# Add parent paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))
sys.path.insert(0, str(Path(__file__).parent.parent / "python" / "core"))

# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

class Config:
    VERSION = "3.0.0"
    APP_NAME = "LogSentinel Pro"
    DB_PATH = Path.home() / ".local" / "share" / "LogSentinel Pro" / "licenses.db"
    BLOCKCHAIN_PATH = Path.home() / ".local" / "share" / "LogSentinel Pro" / "blockchain.json"
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    ALLOWED_PATHS = ["/var/log", "/tmp", str(Path.home())]
    BLOCKCHAIN_DIFFICULTY = 4
    MAX_POW_NONCE = 10_000_000
    BRUTE_FORCE_THRESHOLD = 5

# ═══════════════════════════════════════════════════════════════════════════════
#  ANIMATED BANNER & UI HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

BANNER = """
[bold cyan]
██╗      ██████╗  ██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██║     ██╔═══██╗██╔════╝ ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
██║     ██║   ██║██║  ███╗███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
██║     ██║   ██║██║   ██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
███████╗╚██████╔╝╚██████╔╝███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
[/bold cyan]
[bold red]                              ██████╗ ██████╗  ██████╗ 
                              ██╔══██╗██╔══██╗██╔═══██╗
                              ██████╔╝██████╔╝██║   ██║
                              ██╔═══╝ ██╔══██╗██║   ██║
                              ██║     ██║  ██║╚██████╔╝
                              ╚═╝     ╚═╝  ╚═╝ ╚═════╝[/bold red]
"""

MINI_BANNER = """[bold cyan]╔═══════════════════════════════════════════════════════════════════╗
║[/bold cyan] [bold white]🛡️  LOGSENTINEL PRO[/bold white] [dim]v3.0.0[/dim]  [bold yellow]Enterprise SIEM Platform[/bold yellow]           [bold cyan]║
╚═══════════════════════════════════════════════════════════════════╝[/bold cyan]"""

def animate_text(text: str, delay: float = 0.02):
    """Animate text typing effect."""
    if not RICH_AVAILABLE:
        print(text)
        return
    for char in text:
        console.print(char, end="", style="bold green")
        time.sleep(delay)
    console.print()

def show_spinner(message: str, duration: float = 1.5):
    """Show animated spinner."""
    if not RICH_AVAILABLE:
        print(f"{message}...")
        time.sleep(duration)
        return
    
    with console.status(f"[bold green]{message}...", spinner="dots12"):
        time.sleep(duration)

def print_success(msg: str):
    if RICH_AVAILABLE:
        console.print(f"[bold green]✅ {msg}[/bold green]")
    else:
        print(f"✅ {msg}")

def print_error(msg: str):
    if RICH_AVAILABLE:
        console.print(f"[bold red]❌ {msg}[/bold red]")
    else:
        print(f"❌ {msg}")

def print_warning(msg: str):
    if RICH_AVAILABLE:
        console.print(f"[bold yellow]⚠️  {msg}[/bold yellow]")
    else:
        print(f"⚠️  {msg}")

def print_info(msg: str):
    if RICH_AVAILABLE:
        console.print(f"[bold blue]ℹ️  {msg}[/bold blue]")
    else:
        print(f"ℹ️  {msg}")

# ═══════════════════════════════════════════════════════════════════════════════
#  DEVICE FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════════════

class DeviceFingerprint:
    @staticmethod
    def generate() -> str:
        """Generate unique device fingerprint from hardware identifiers."""
        components = []
        
        # Machine ID
        try:
            with open("/etc/machine-id", "r") as f:
                components.append(f.read().strip())
        except:
            components.append("no-machine-id")
        
        # CPU Info
        try:
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if "model name" in line:
                        components.append(line.split(":")[1].strip())
                        break
        except:
            components.append("unknown-cpu")
        
        # MAC Addresses
        try:
            for iface in Path("/sys/class/net").iterdir():
                if iface.name != "lo":
                    addr_file = iface / "address"
                    if addr_file.exists():
                        components.append(addr_file.read_text().strip())
        except:
            pass
        
        # Hostname
        components.append(socket.gethostname())
        
        combined = "|".join(components)
        return hashlib.sha256(combined.encode()).hexdigest()

# ═══════════════════════════════════════════════════════════════════════════════
#  AUTHENTICATION MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class AuthManager:
    def __init__(self):
        self.db_path = Config.DB_PATH
        self.device_fp = DeviceFingerprint.generate()
        self._ensure_db()
    
    def _ensure_db(self):
        """Ensure database exists with proper schema."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                key TEXT PRIMARY KEY,
                device_fingerprint TEXT,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                is_used INTEGER DEFAULT 0,
                issued_by TEXT,
                organization TEXT,
                max_duration_hours INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT,
                action TEXT,
                device_fingerprint TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                status TEXT,
                error_message TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def _log_audit(self, key: str, action: str, status: str, error: str = ""):
        """Log authentication event to audit trail."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO auth_audit (license_key, action, device_fingerprint, status, error_message)
            VALUES (?, ?, ?, ?, ?)
        """, (key[:16] + "..." if len(key) > 16 else key, action, self.device_fp[:16] + "...", status, error))
        conn.commit()
        conn.close()
    
    def authenticate(self, license_key: str) -> Tuple[bool, str, str]:
        """Authenticate with license key. Returns (success, message, org)."""
        # Validate key format
        if not re.match(r'^[a-f0-9]{64}$', license_key.lower()):
            self._log_audit(license_key, "AUTH_ATTEMPT", "FAILED", "Invalid key format")
            return False, "Invalid key format (must be 64 hex characters)", ""
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Check key exists
        cursor.execute("SELECT * FROM licenses WHERE key = ?", (license_key,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            self._log_audit(license_key, "AUTH_ATTEMPT", "FAILED", "Key not found")
            return False, "License key not found in database", ""
        
        key, device_fp, issued_at, expires_at, is_used, issued_by, org, max_hours, created = row
        
        # Check expiration
        expires_dt = datetime.fromisoformat(expires_at)
        if expires_dt < datetime.now():
            conn.close()
            self._log_audit(license_key, "AUTH_ATTEMPT", "FAILED", "Key expired")
            return False, f"License expired on {expires_dt.strftime('%Y-%m-%d %H:%M')}", org
        
        # Check if already used
        if is_used:
            # If used, check device binding
            if device_fp and device_fp != self.device_fp:
                conn.close()
                self._log_audit(license_key, "AUTH_ATTEMPT", "FAILED", "Device mismatch")
                return False, "License is bound to a different device", org
            # Same device, allow re-auth
            conn.close()
            self._log_audit(license_key, "AUTH_REVALIDATE", "SUCCESS", "")
            return True, "License validated (already bound to this device)", org
        
        # First time use - bind to device
        cursor.execute("""
            UPDATE licenses SET is_used = 1, device_fingerprint = ? WHERE key = ?
        """, (self.device_fp, license_key))
        conn.commit()
        conn.close()
        
        self._log_audit(license_key, "AUTH_SUCCESS", "SUCCESS", "")
        self._log_audit(license_key, "DEVICE_BIND", "SUCCESS", "First activation")
        
        return True, "License activated and bound to this device", org
    
    def get_status(self) -> Dict:
        """Get authentication system status."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM licenses")
        total = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM licenses WHERE is_used = 0")
        active = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM licenses WHERE is_used = 1")
        used = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM auth_audit")
        audit_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM licenses WHERE datetime(expires_at) < datetime('now')")
        expired = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_keys": total,
            "active_keys": active,
            "used_keys": used,
            "expired_keys": expired,
            "audit_entries": audit_count,
            "device_fingerprint": self.device_fp
        }
    
    def get_licenses(self) -> List[Dict]:
        """Get all licenses."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT key, organization, is_used, device_fingerprint, expires_at, issued_at FROM licenses ORDER BY created_at DESC")
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                "key": r[0],
                "organization": r[1],
                "is_used": r[2],
                "device_fingerprint": r[3],
                "expires_at": r[4],
                "issued_at": r[5]
            }
            for r in rows
        ]
    
    def get_audit_trail(self, limit: int = 20) -> List[Dict]:
        """Get audit trail."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, license_key, action, device_fingerprint, timestamp, status, error_message
            FROM auth_audit ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                "id": r[0],
                "license_key": r[1],
                "action": r[2],
                "device_fingerprint": r[3],
                "timestamp": r[4],
                "status": r[5],
                "error": r[6]
            }
            for r in rows
        ]

# ═══════════════════════════════════════════════════════════════════════════════
#  BLOCKCHAIN INTEGRITY
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
    
    def mine(self, difficulty: int, progress_callback=None) -> bool:
        target = "0" * difficulty
        for i in range(Config.MAX_POW_NONCE):
            self.hash = self.compute_hash()
            if self.hash.startswith(target):
                return True
            self.nonce += 1
            if progress_callback and i % 10000 == 0:
                progress_callback(i)
        self.hash = self.compute_hash()
        return False
    
    def to_dict(self) -> Dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash
        }
    
    @classmethod
    def from_dict(cls, d: Dict) -> 'Block':
        block = cls(d["index"], d["timestamp"], d["data"], d["previous_hash"])
        block.nonce = d["nonce"]
        block.hash = d["hash"]
        return block


class Blockchain:
    def __init__(self):
        self.chain: List[Block] = []
        self.path = Config.BLOCKCHAIN_PATH
        self._load()
    
    def _load(self):
        """Load blockchain from disk."""
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text())
                self.chain = [Block.from_dict(b) for b in data]
            except:
                self.chain = []
    
    def _save(self):
        """Save blockchain to disk."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = [b.to_dict() for b in self.chain]
        self.path.write_text(json.dumps(data, indent=2))
    
    def create_genesis(self):
        """Create genesis block."""
        if not self.chain:
            block = Block(0, datetime.now().isoformat(), "Genesis Block", "0")
            block.mine(Config.BLOCKCHAIN_DIFFICULTY)
            self.chain.append(block)
            self._save()
    
    def add_block(self, data: str) -> Block:
        """Add new block to chain."""
        if not self.chain:
            self.create_genesis()
        
        prev = self.chain[-1]
        block = Block(len(self.chain), datetime.now().isoformat(), data, prev.hash)
        block.mine(Config.BLOCKCHAIN_DIFFICULTY)
        self.chain.append(block)
        self._save()
        return block
    
    def verify(self) -> Tuple[bool, str, int]:
        """Verify chain integrity. Returns (valid, message, block_count)."""
        if not self.chain:
            return True, "Chain is empty", 0
        
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]
            
            # Check hash linkage
            if curr.previous_hash != prev.hash:
                return False, f"Block {i}: Previous hash mismatch", i
            
            # Verify hash
            computed = curr.compute_hash()
            if curr.hash != computed:
                return False, f"Block {i}: Hash verification failed", i
        
        return True, "All blocks verified", len(self.chain)

# ═══════════════════════════════════════════════════════════════════════════════
#  LOG PARSER & DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

class LogParser:
    # Syslog pattern
    SYSLOG_PATTERN = re.compile(
        r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$'
    )
    
    # Detection patterns with MITRE ATT&CK mapping
    PATTERNS = {
        "ssh_failed": (re.compile(r'Failed password for (\S+) from (\S+)', re.I), "T1110.001", "Brute Force"),
        "ssh_invalid": (re.compile(r'Invalid user (\S+) from (\S+)', re.I), "T1078", "Valid Accounts"),
        "sudo_command": (re.compile(r'sudo.*COMMAND=(.+)', re.I), "T1548", "Privilege Escalation"),
        "su_attempt": (re.compile(r'su\[.*\].*session opened for user (\S+)', re.I), "T1548", "Privilege Escalation"),
        "sql_injection": (re.compile(r"('|\"|;|--|\bOR\b.*=|\bAND\b.*=|\bUNION\b|\bSELECT\b.*FROM)", re.I), "T1190", "SQL Injection"),
        "xss_attempt": (re.compile(r'(<script|javascript:|on\w+=)', re.I), "T1189", "XSS Attack"),
        "path_traversal": (re.compile(r'\.\./', re.I), "T1083", "Path Traversal"),
        "port_scan": (re.compile(r'(port\s*scan|nmap|masscan|SYN flood)', re.I), "T1046", "Port Scan"),
        "kernel_panic": (re.compile(r'kernel.*panic', re.I), "T1499", "System Crash"),
        "oom_killer": (re.compile(r'Out of memory.*Killed', re.I), "T1499", "Resource Exhaustion"),
        "segfault": (re.compile(r'segfault at', re.I), "T1203", "Exploitation"),
        "rce_attempt": (re.compile(r'(;|\||`|\$\(|&&)\s*(cat|ls|id|whoami|wget|curl|nc|bash)', re.I), "T1059", "Command Injection"),
        "c2_beacon": (re.compile(r'(beacon|callback|reverse.?shell|meterpreter)', re.I), "T1071", "C2 Communication"),
        "data_exfil": (re.compile(r'(exfil|upload.*sensitive|POST.*\/api.*data)', re.I), "T1048", "Data Exfiltration"),
    }
    
    @classmethod
    def parse_line(cls, line: str) -> Optional[Dict]:
        """Parse single log line into structured event."""
        match = cls.SYSLOG_PATTERN.match(line.strip())
        if not match:
            return None
        
        timestamp, hostname, process, pid, message = match.groups()
        
        return {
            "timestamp": timestamp,
            "hostname": hostname,
            "process": process.lower(),
            "pid": pid,
            "message": message,
            "raw": line.strip()
        }
    
    @classmethod
    def detect_threats(cls, event: Dict) -> List[Dict]:
        """Detect threats in parsed event."""
        threats = []
        msg = event.get("message", "")
        process = event.get("process", "")
        
        for threat_name, (pattern, mitre, description) in cls.PATTERNS.items():
            match = pattern.search(msg)
            if match:
                severity = cls._get_severity(threat_name)
                threats.append({
                    "type": threat_name.upper(),
                    "severity": severity,
                    "mitre": mitre,
                    "description": description,
                    "match": match.group(0)[:50] if match else "",
                    "process": process,
                    "timestamp": event.get("timestamp", "")
                })
        
        return threats
    
    @classmethod
    def _get_severity(cls, threat_type: str) -> str:
        critical = ["sql_injection", "rce_attempt", "kernel_panic", "c2_beacon", "data_exfil"]
        high = ["ssh_failed", "sudo_command", "xss_attempt", "path_traversal", "oom_killer"]
        medium = ["ssh_invalid", "port_scan", "segfault"]
        
        if threat_type in critical:
            return "CRITICAL"
        elif threat_type in high:
            return "HIGH"
        elif threat_type in medium:
            return "MEDIUM"
        return "LOW"


class ThreatAnalyzer:
    """Aggregates and analyzes threats across multiple events."""
    
    def __init__(self):
        self.failed_logins: Dict[str, List] = defaultdict(list)
        self.threats: List[Dict] = []
        self.events_processed = 0
        self.lines_total = 0
    
    def process_event(self, event: Dict) -> List[Dict]:
        """Process event and return detected threats."""
        self.events_processed += 1
        threats = LogParser.detect_threats(event)
        
        # Track failed logins for brute force detection
        for threat in threats:
            if threat["type"] == "SSH_FAILED":
                match = re.search(r'from (\S+)', event.get("message", ""))
                if match:
                    ip = match.group(1)
                    self.failed_logins[ip].append(event.get("timestamp"))
                    
                    # Check threshold
                    if len(self.failed_logins[ip]) >= Config.BRUTE_FORCE_THRESHOLD:
                        threat["severity"] = "CRITICAL"
                        threat["type"] = "BRUTE_FORCE_ATTACK"
                        threat["description"] = f"Brute force from {ip} ({len(self.failed_logins[ip])} attempts)"
        
        self.threats.extend(threats)
        return threats
    
    def get_summary(self) -> Dict:
        """Get analysis summary."""
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)
        mitre_tactics = defaultdict(int)
        
        for threat in self.threats:
            severity_counts[threat["severity"]] += 1
            type_counts[threat["type"]] += 1
            mitre_tactics[threat["mitre"]] += 1
        
        risk_score = (
            severity_counts["CRITICAL"] * 25 +
            severity_counts["HIGH"] * 15 +
            severity_counts["MEDIUM"] * 5 +
            severity_counts["LOW"] * 1
        )
        risk_score = min(100, risk_score)
        
        if risk_score >= 75:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            "lines_total": self.lines_total,
            "events_processed": self.events_processed,
            "threats_detected": len(self.threats),
            "severity_breakdown": dict(severity_counts),
            "threat_types": dict(type_counts),
            "mitre_tactics": dict(mitre_tactics),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "unique_attackers": len(self.failed_logins)
        }

# ═══════════════════════════════════════════════════════════════════════════════
#  FILE VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

def validate_file(filepath: str) -> Tuple[bool, str]:
    """Validate file path for security."""
    path = Path(filepath)
    
    if not path.exists():
        return False, f"File not found: {filepath}"
    
    # Resolve symlinks
    try:
        real_path = path.resolve()
    except:
        return False, f"Cannot resolve path: {filepath}"
    
    # Check allowed paths
    allowed = False
    for allowed_path in Config.ALLOWED_PATHS:
        if str(real_path).startswith(allowed_path):
            allowed = True
            break
    
    if not allowed:
        return False, f"Path not in allowed directories"
    
    # Check for path traversal
    if ".." in str(filepath):
        return False, "Path traversal detected"
    
    # Check if regular file
    if not real_path.is_file():
        return False, "Not a regular file"
    
    # Check size
    size = real_path.stat().st_size
    if size > Config.MAX_FILE_SIZE:
        return False, f"File too large: {size / 1024 / 1024:.1f}MB (max: {Config.MAX_FILE_SIZE / 1024 / 1024:.0f}MB)"
    
    if size == 0:
        return False, "File is empty"
    
    return True, "OK"

# ═══════════════════════════════════════════════════════════════════════════════
#  CLI COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

def cmd_auth(args):
    """Handle authentication command."""
    if RICH_AVAILABLE:
        console.print(MINI_BANNER)
    
    auth = AuthManager()
    
    if args.status:
        show_spinner("Loading authentication status", 0.8)
        status = auth.get_status()
        
        if RICH_AVAILABLE:
            table = Table(title="🔐 Authentication System Status", box=DOUBLE, border_style="cyan")
            table.add_column("Property", style="bold white")
            table.add_column("Value", style="bold green")
            
            table.add_row("Total Keys", str(status['total_keys']))
            table.add_row("Active Keys", f"[green]{status['active_keys']}[/green]")
            table.add_row("Used Keys", f"[yellow]{status['used_keys']}[/yellow]")
            table.add_row("Expired Keys", f"[red]{status['expired_keys']}[/red]")
            table.add_row("Audit Entries", str(status['audit_entries']))
            table.add_row("Device Fingerprint", f"[dim]{status['device_fingerprint'][:32]}...[/dim]")
            
            console.print()
            console.print(table)
            console.print()
        else:
            print(f"\nAuth Status: {status}")
        return 0
    
    if args.key:
        show_spinner("Validating license key", 1.0)
        success, message, org = auth.authenticate(args.key)
        
        if success:
            if RICH_AVAILABLE:
                panel = Panel(
                    f"[bold green]{message}[/bold green]\n\n"
                    f"[dim]Organization:[/dim] [bold white]{org}[/bold white]\n"
                    f"[dim]Device bound:[/dim] [bold cyan]{auth.device_fp[:32]}...[/bold cyan]",
                    title="✅ Authentication Successful",
                    border_style="green",
                    box=DOUBLE
                )
                console.print(panel)
            else:
                print(f"\n✅ {message}")
            return 0
        else:
            if RICH_AVAILABLE:
                panel = Panel(
                    f"[bold red]{message}[/bold red]",
                    title="❌ Authentication Failed",
                    border_style="red",
                    box=DOUBLE
                )
                console.print(panel)
            else:
                print(f"\n❌ {message}")
            return 1
    
    print_info("Use --key LICENSE_KEY to authenticate or --status to check status")
    return 1


def cmd_scan(args):
    """Handle log scan command."""
    if RICH_AVAILABLE:
        console.print(MINI_BANNER)
    
    # Validate file
    valid, msg = validate_file(args.file)
    if not valid:
        print_error(msg)
        return 1
    
    file_size = Path(args.file).stat().st_size
    
    analyzer = ThreatAnalyzer()
    blockchain = Blockchain() if args.blockchain else None
    threats_found = []
    
    if RICH_AVAILABLE:
        # Count lines first
        with open(args.file, 'r', errors='ignore') as f:
            total_lines = sum(1 for _ in f)
        analyzer.lines_total = total_lines
        
        console.print()
        console.print(Panel(f"[bold]📂 File:[/bold] {args.file}\n[bold]📊 Size:[/bold] {file_size/1024:.1f} KB\n[bold]📝 Lines:[/bold] {total_lines:,}", 
                           title="🔍 Scan Target", border_style="blue"))
        console.print()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TextColumn("[bold red]{task.fields[threats]}[/bold red] threats"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Scanning logs...", total=total_lines, threats=0)
            
            with open(args.file, 'r', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    event = LogParser.parse_line(line)
                    if event:
                        threats = analyzer.process_event(event)
                        
                        if threats:
                            for threat in threats:
                                threats_found.append((line_num, threat))
                            
                            # Add to blockchain
                            if blockchain:
                                for threat in threats:
                                    data = json.dumps({
                                        "line": line_num,
                                        "type": threat["type"],
                                        "severity": threat["severity"],
                                        "mitre": threat["mitre"]
                                    })
                                    blockchain.add_block(data)
                    
                    progress.update(task, advance=1, threats=len(analyzer.threats))
    else:
        # Non-rich fallback
        print(f"\n🔍 Scanning: {args.file}")
        with open(args.file, 'r', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                analyzer.lines_total += 1
                event = LogParser.parse_line(line)
                if event:
                    threats = analyzer.process_event(event)
                    if threats:
                        for threat in threats:
                            threats_found.append((line_num, threat))
    
    # Print summary
    summary = analyzer.get_summary()
    
    if RICH_AVAILABLE:
        console.print()
        
        # Risk gauge
        risk_color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "green"}[summary['risk_level']]
        risk_bar = "█" * (summary['risk_score'] // 5) + "░" * (20 - summary['risk_score'] // 5)
        
        console.print(Panel(
            f"[bold {risk_color}]{risk_bar}[/bold {risk_color}]\n\n"
            f"[bold]Score:[/bold] [bold {risk_color}]{summary['risk_score']}/100[/bold {risk_color}]  "
            f"[bold]Level:[/bold] [bold {risk_color}]{summary['risk_level']}[/bold {risk_color}]",
            title="⚠️  RISK ASSESSMENT",
            border_style=risk_color,
            box=HEAVY
        ))
        
        # Summary table
        table = Table(title="📊 Scan Summary", box=ROUNDED, border_style="cyan")
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")
        
        table.add_row("Lines Scanned", f"{summary['lines_total']:,}")
        table.add_row("Events Parsed", f"{summary['events_processed']:,}")
        table.add_row("Threats Detected", f"[bold red]{summary['threats_detected']}[/bold red]")
        table.add_row("Unique Attackers", str(summary['unique_attackers']))
        if blockchain:
            table.add_row("Blockchain Blocks", str(len(blockchain.chain)))
        
        console.print(table)
        
        # Severity breakdown
        if summary['severity_breakdown']:
            sev_table = Table(title="🎯 Severity Breakdown", box=ROUNDED)
            sev_table.add_column("Severity", style="bold")
            sev_table.add_column("Count", justify="right")
            sev_table.add_column("Bar")
            
            max_count = max(summary['severity_breakdown'].values()) if summary['severity_breakdown'] else 1
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = summary['severity_breakdown'].get(sev, 0)
                bar_len = int((count / max_count) * 20) if max_count > 0 else 0
                color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "green"}[sev]
                bar = f"[{color}]{'█' * bar_len}{'░' * (20-bar_len)}[/{color}]"
                sev_table.add_row(f"[{color}]{sev}[/{color}]", str(count), bar)
            
            console.print(sev_table)
        
        # Threat types
        if summary['threat_types'] and args.verbose:
            type_table = Table(title="🔥 Threat Types", box=ROUNDED)
            type_table.add_column("Type", style="bold")
            type_table.add_column("Count", justify="right")
            type_table.add_column("MITRE", style="dim")
            
            for threat_type, count in sorted(summary['threat_types'].items(), key=lambda x: -x[1]):
                mitre = summary['mitre_tactics'].get(threat_type, "")
                type_table.add_row(threat_type, str(count), mitre if mitre else "-")
            
            console.print(type_table)
        
        # Recent threats
        if threats_found and args.verbose:
            threat_table = Table(title="🚨 Detected Threats (Recent)", box=ROUNDED, border_style="red")
            threat_table.add_column("Line", justify="right", style="dim")
            threat_table.add_column("Severity")
            threat_table.add_column("Type", style="bold")
            threat_table.add_column("MITRE")
            threat_table.add_column("Match", max_width=30)
            
            for line_num, threat in threats_found[-15:]:  # Last 15
                sev = threat['severity']
                color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "green"}[sev]
                threat_table.add_row(
                    str(line_num),
                    f"[{color}]{sev}[/{color}]",
                    threat['type'],
                    threat['mitre'],
                    threat.get('match', '')[:30]
                )
            
            console.print(threat_table)
        
        console.print()
    else:
        # Plain text output
        print(f"\n{'='*60}")
        print(f"  Risk Score: {summary['risk_score']}/100 ({summary['risk_level']})")
        print(f"  Threats: {summary['threats_detected']}")
        print(f"{'='*60}\n")
    
    # JSON output
    if args.json:
        output = {
            "file": args.file,
            "summary": summary,
            "threats": [{"line": l, "threat": t} for l, t in threats_found] if args.verbose else []
        }
        print(json.dumps(output, indent=2))
    
    return 0 if summary['risk_level'] in ['LOW', 'MEDIUM'] else 1


def cmd_blockchain(args):
    """Handle blockchain command."""
    if RICH_AVAILABLE:
        console.print(MINI_BANNER)
    
    blockchain = Blockchain()
    
    if args.verify:
        show_spinner("Verifying blockchain integrity", 1.5)
        valid, msg, count = blockchain.verify()
        
        if RICH_AVAILABLE:
            if valid:
                console.print(Panel(
                    f"[bold green]✅ {msg}[/bold green]\n\n"
                    f"[dim]Blocks verified:[/dim] [bold]{count}[/bold]\n"
                    f"[dim]Chain integrity:[/dim] [bold green]INTACT[/bold green]",
                    title="🔗 Blockchain Verification",
                    border_style="green",
                    box=DOUBLE
                ))
            else:
                console.print(Panel(
                    f"[bold red]❌ {msg}[/bold red]\n\n"
                    f"[dim]Chain integrity:[/dim] [bold red]COMPROMISED[/bold red]",
                    title="🔗 Blockchain Verification",
                    border_style="red",
                    box=DOUBLE
                ))
        else:
            print(f"\n{'✅' if valid else '❌'} {msg}\n")
        
        return 0 if valid else 1
    
    if args.show:
        if not blockchain.chain:
            print_warning("Blockchain is empty")
            return 0
        
        if RICH_AVAILABLE:
            console.print()
            console.print(Panel(
                f"[bold]Total Blocks:[/bold] {len(blockchain.chain)}\n"
                f"[bold]Storage:[/bold] {blockchain.path}",
                title="⛓️  Blockchain Status",
                border_style="cyan"
            ))
            
            # Show as tree
            tree = Tree("🔗 [bold]Blockchain[/bold]")
            for block in blockchain.chain[-10:]:  # Last 10 blocks
                block_branch = tree.add(f"[bold cyan]Block #{block.index}[/bold cyan]")
                block_branch.add(f"[dim]Hash:[/dim] {block.hash[:24]}...")
                block_branch.add(f"[dim]Prev:[/dim] {block.previous_hash[:24]}...")
                block_branch.add(f"[dim]Nonce:[/dim] {block.nonce:,}")
                if block.data != "Genesis Block":
                    try:
                        data = json.loads(block.data)
                        block_branch.add(f"[bold yellow]{data.get('type', 'N/A')}[/bold yellow] @ line {data.get('line', 'N/A')}")
                    except:
                        block_branch.add(f"[dim]{block.data[:40]}...[/dim]")
                else:
                    block_branch.add("[bold green]Genesis Block[/bold green]")
            
            console.print(tree)
            console.print()
        else:
            print(f"\nBlockchain: {len(blockchain.chain)} blocks")
        
        return 0
    
    print_info("Use --verify to check integrity or --show to display blocks")
    return 1


def cmd_keygen(args):
    """Handle key generation command."""
    if RICH_AVAILABLE:
        console.print(MINI_BANNER)
    
    show_spinner("Generating cryptographic key", 1.2)
    
    auth = AuthManager()
    
    # Generate key
    import uuid
    combined = str(uuid.uuid4()) + str(uuid.uuid4()) + str(datetime.now().timestamp())
    key = hashlib.sha256(combined.encode()).hexdigest()
    
    # Calculate expiration
    expires = datetime.now() + timedelta(hours=args.hours)
    
    # Insert into database
    conn = sqlite3.connect(str(Config.DB_PATH))
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO licenses (key, issued_at, expires_at, is_used, issued_by, organization, max_duration_hours)
        VALUES (?, ?, ?, 0, ?, ?, ?)
    """, (key, datetime.now().isoformat(), expires.isoformat(), args.issuer, args.org, args.hours))
    
    conn.commit()
    conn.close()
    
    if RICH_AVAILABLE:
        console.print()
        
        # Key display with copy-friendly format
        key_panel = Panel(
            f"[bold green]{key}[/bold green]",
            title="🔑 License Key",
            border_style="green",
            box=HEAVY
        )
        console.print(key_panel)
        
        # Details table
        table = Table(box=ROUNDED, border_style="cyan")
        table.add_column("Property", style="bold")
        table.add_column("Value")
        
        table.add_row("Organization", f"[bold]{args.org}[/bold]")
        table.add_row("Issued By", args.issuer)
        table.add_row("Valid For", f"{args.hours} hours")
        table.add_row("Expires", expires.strftime('%Y-%m-%d %H:%M:%S'))
        table.add_row("Status", "[bold green]ACTIVE[/bold green]")
        
        console.print(table)
        
        console.print()
        console.print("[bold yellow]⚠️  IMPORTANT:[/bold yellow] Save this key! It can only be used [bold]ONCE[/bold] on [bold]ONE[/bold] device.")
        console.print()
    else:
        print(f"\nNew Key: {key}")
        print(f"Organization: {args.org}")
        print(f"Expires: {expires}\n")
    
    return 0


def cmd_audit(args):
    """Show audit trail."""
    if RICH_AVAILABLE:
        console.print(MINI_BANNER)
    
    show_spinner("Loading audit trail", 0.8)
    
    auth = AuthManager()
    entries = auth.get_audit_trail(args.limit)
    
    if not entries:
        print_warning("No audit entries found")
        return 0
    
    if RICH_AVAILABLE:
        console.print()
        
        table = Table(title="📋 Authentication Audit Trail", box=ROUNDED, border_style="cyan")
        table.add_column("ID", justify="right", style="dim")
        table.add_column("Timestamp", style="dim")
        table.add_column("Action")
        table.add_column("Status")
        table.add_column("Device", max_width=20)
        table.add_column("Error", max_width=25)
        
        for entry in entries:
            status = entry['status']
            status_color = "green" if status == "SUCCESS" else "red"
            action = entry['action']
            action_style = ""
            if "SUCCESS" in action or "BIND" in action:
                action_style = "green"
            elif "FAILED" in action or "ATTEMPT" in action:
                action_style = "yellow"
            
            table.add_row(
                str(entry['id']),
                entry['timestamp'][:19] if entry['timestamp'] else "-",
                f"[{action_style}]{action}[/{action_style}]" if action_style else action,
                f"[{status_color}]{status}[/{status_color}]",
                entry['device_fingerprint'] or "-",
                entry['error'] or "-"
            )
        
        console.print(table)
        console.print()
    else:
        for entry in entries:
            print(f"{entry['id']} | {entry['action']} | {entry['status']} | {entry['error'] or '-'}")
    
    return 0


def cmd_fingerprint(args):
    """Show device fingerprint."""
    if RICH_AVAILABLE:
        console.print(MINI_BANNER)
    
    show_spinner("Generating device fingerprint", 1.0)
    
    fp = DeviceFingerprint.generate()
    
    if RICH_AVAILABLE:
        console.print()
        console.print(Panel(
            f"[bold cyan]{fp}[/bold cyan]",
            title="🖥️  Device Fingerprint",
            subtitle="[dim]SHA-256 hash of hardware identifiers[/dim]",
            border_style="cyan",
            box=DOUBLE
        ))
        console.print()
    else:
        print(f"\nDevice Fingerprint: {fp}\n")
    
    return 0


def cmd_version(args):
    """Show version with banner."""
    if RICH_AVAILABLE:
        console.print(BANNER)
        console.print(Align.center("[bold white]v3.0.0[/bold white] • [dim]Enterprise SIEM Platform[/dim]"))
        console.print(Align.center("[dim]Terminal Edition • Built with Python & Rich[/dim]"))
        console.print()
        
        # System info
        table = Table(box=ROUNDED, show_header=False)
        table.add_column("", style="dim")
        table.add_column("")
        table.add_row("Python", f"{sys.version.split()[0]}")
        table.add_row("Platform", sys.platform)
        table.add_row("Terminal", os.environ.get("TERM", "unknown"))
        
        console.print(Align.center(table))
        console.print()
    else:
        print(f"\n{Config.APP_NAME} v{Config.VERSION}")
        print("Enterprise SIEM Platform - CLI Edition\n")
    
    return 0


def cmd_dashboard(args):
    """Show live dashboard."""
    if not RICH_AVAILABLE:
        print("Dashboard requires 'rich' library")
        return 1
    
    console.print(MINI_BANNER)
    show_spinner("Loading dashboard", 1.0)
    
    auth = AuthManager()
    blockchain = Blockchain()
    
    status = auth.get_status()
    
    # Create layout
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main"),
        Layout(name="footer", size=3)
    )
    
    layout["main"].split_row(
        Layout(name="left"),
        Layout(name="right")
    )
    
    # Header
    layout["header"].update(Panel("[bold cyan]LogSentinel Pro Dashboard[/bold cyan]", style="cyan"))
    
    # Auth status
    auth_table = Table(title="🔐 Auth System", box=ROUNDED)
    auth_table.add_column("Metric")
    auth_table.add_column("Value", justify="right")
    auth_table.add_row("Total Keys", str(status['total_keys']))
    auth_table.add_row("Active", f"[green]{status['active_keys']}[/green]")
    auth_table.add_row("Used", f"[yellow]{status['used_keys']}[/yellow]")
    layout["left"].update(auth_table)
    
    # Blockchain status
    bc_table = Table(title="⛓️ Blockchain", box=ROUNDED)
    bc_table.add_column("Metric")
    bc_table.add_column("Value", justify="right")
    bc_table.add_row("Blocks", str(len(blockchain.chain)))
    valid, _, _ = blockchain.verify()
    bc_table.add_row("Status", "[green]VALID[/green]" if valid else "[red]INVALID[/red]")
    layout["right"].update(bc_table)
    
    # Footer
    layout["footer"].update(Panel(f"[dim]Device: {status['device_fingerprint'][:48]}...[/dim]", style="dim"))
    
    console.print(layout)
    return 0

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description=f"{Config.APP_NAME} v{Config.VERSION} - Enterprise SIEM CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  logsentinel auth --key YOUR_LICENSE_KEY    Authenticate with license
  logsentinel scan /var/log/auth.log -v      Scan log file with details
  logsentinel scan /tmp/test.log -v -b       Scan with blockchain recording
  logsentinel keygen -o "Acme Corp" -H 720   Generate 30-day license key
  logsentinel blockchain --verify            Verify blockchain integrity
  logsentinel audit                          Show authentication audit trail
  logsentinel dashboard                      Show system dashboard
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Auth command
    auth_parser = subparsers.add_parser("auth", help="Authenticate with license key")
    auth_parser.add_argument("--key", "-k", help="License key (64 hex chars)")
    auth_parser.add_argument("--status", "-s", action="store_true", help="Show auth system status")
    auth_parser.set_defaults(func=cmd_auth)
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan log file for threats")
    scan_parser.add_argument("file", help="Log file to scan")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed threat info")
    scan_parser.add_argument("--blockchain", "-b", action="store_true", help="Record threats to blockchain")
    scan_parser.add_argument("--json", "-j", action="store_true", help="Output JSON summary")
    scan_parser.set_defaults(func=cmd_scan)
    
    # Blockchain command
    bc_parser = subparsers.add_parser("blockchain", help="Manage blockchain")
    bc_parser.add_argument("--verify", "-v", action="store_true", help="Verify chain integrity")
    bc_parser.add_argument("--show", "-s", action="store_true", help="Show blockchain status")
    bc_parser.set_defaults(func=cmd_blockchain)
    
    # Keygen command
    kg_parser = subparsers.add_parser("keygen", help="Generate license key (admin only)")
    kg_parser.add_argument("--org", "-o", required=True, help="Organization name")
    kg_parser.add_argument("--hours", "-H", type=int, default=720, help="Validity in hours (default: 720)")
    kg_parser.add_argument("--issuer", "-i", default="CLI Admin", help="Issuer name")
    kg_parser.set_defaults(func=cmd_keygen)
    
    # Audit command
    audit_parser = subparsers.add_parser("audit", help="Show audit trail")
    audit_parser.add_argument("--limit", "-l", type=int, default=20, help="Number of entries (default: 20)")
    audit_parser.set_defaults(func=cmd_audit)
    
    # Fingerprint command
    fp_parser = subparsers.add_parser("fingerprint", help="Show device fingerprint")
    fp_parser.set_defaults(func=cmd_fingerprint)
    
    # Version command
    ver_parser = subparsers.add_parser("version", help="Show version")
    ver_parser.set_defaults(func=cmd_version)
    
    # Dashboard command
    dash_parser = subparsers.add_parser("dashboard", help="Show system dashboard")
    dash_parser.set_defaults(func=cmd_dashboard)
    
    args = parser.parse_args()
    
    if not args.command:
        if RICH_AVAILABLE:
            console.print(BANNER)
            console.print(Align.center("[bold]Enterprise SIEM Platform[/bold] • [dim]v3.0.0[/dim]"))
            console.print()
        parser.print_help()
        return 1
    
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
