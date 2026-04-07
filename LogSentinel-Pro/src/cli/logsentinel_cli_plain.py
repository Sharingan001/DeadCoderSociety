#!/usr/bin/env python3
"""
LogSentinel Pro v3.0 - Enterprise SIEM CLI
Main command-line interface for log analysis and threat detection.
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
    
    def authenticate(self, license_key: str) -> Tuple[bool, str]:
        """Authenticate with license key. Returns (success, message)."""
        # Validate key format
        if not re.match(r'^[a-f0-9]{64}$', license_key.lower()):
            self._log_audit(license_key, "AUTH_ATTEMPT", "FAILED", "Invalid key format")
            return False, "Invalid key format (must be 64 hex characters)"
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Check key exists
        cursor.execute("SELECT * FROM licenses WHERE key = ?", (license_key,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            self._log_audit(license_key, "AUTH_ATTEMPT", "FAILED", "Key not found")
            return False, "License key not found"
        
        key, device_fp, issued_at, expires_at, is_used, issued_by, org, max_hours, created = row
        
        # Check expiration
        expires_dt = datetime.fromisoformat(expires_at)
        if expires_dt < datetime.now():
            conn.close()
            self._log_audit(license_key, "AUTH_ATTEMPT", "FAILED", "Key expired")
            return False, f"License expired on {expires_dt.strftime('%Y-%m-%d %H:%M')}"
        
        # Check if already used
        if is_used:
            # If used, check device binding
            if device_fp and device_fp != self.device_fp:
                conn.close()
                self._log_audit(license_key, "AUTH_ATTEMPT", "FAILED", "Device mismatch")
                return False, "License bound to different device"
            # Same device, allow re-auth
            conn.close()
            self._log_audit(license_key, "AUTH_REVALIDATE", "SUCCESS", "")
            return True, f"License valid (bound to this device) - Org: {org}"
        
        # First time use - bind to device
        cursor.execute("""
            UPDATE licenses SET is_used = 1, device_fingerprint = ? WHERE key = ?
        """, (self.device_fp, license_key))
        conn.commit()
        conn.close()
        
        self._log_audit(license_key, "AUTH_SUCCESS", "SUCCESS", "")
        self._log_audit(license_key, "DEVICE_BIND", "SUCCESS", "First activation")
        
        return True, f"License activated and bound to this device - Org: {org}"
    
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
        
        conn.close()
        
        return {
            "total_keys": total,
            "active_keys": active,
            "used_keys": used,
            "audit_entries": audit_count,
            "device_fingerprint": self.device_fp[:32] + "..."
        }

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
    
    def verify(self) -> Tuple[bool, str]:
        """Verify chain integrity."""
        if not self.chain:
            return True, "Chain is empty"
        
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]
            
            # Check hash linkage
            if curr.previous_hash != prev.hash:
                return False, f"Block {i}: Previous hash mismatch"
            
            # Verify hash
            computed = curr.compute_hash()
            if curr.hash != computed:
                return False, f"Block {i}: Hash verification failed"
        
        return True, f"Chain valid ({len(self.chain)} blocks)"

# ═══════════════════════════════════════════════════════════════════════════════
#  LOG PARSER & DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

class LogParser:
    # Syslog pattern
    SYSLOG_PATTERN = re.compile(
        r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$'
    )
    
    # Detection patterns
    PATTERNS = {
        "ssh_failed": re.compile(r'Failed password for (\S+) from (\S+)', re.I),
        "ssh_invalid": re.compile(r'Invalid user (\S+) from (\S+)', re.I),
        "sudo_command": re.compile(r'sudo.*COMMAND=(.+)', re.I),
        "su_attempt": re.compile(r'su\[.*\].*session opened for user (\S+)', re.I),
        "sql_injection": re.compile(r"('|\"|;|--|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b)", re.I),
        "xss_attempt": re.compile(r'(<script|javascript:|on\w+=)', re.I),
        "path_traversal": re.compile(r'\.\./', re.I),
        "port_scan": re.compile(r'(port\s*scan|nmap|masscan)', re.I),
        "kernel_panic": re.compile(r'kernel.*panic', re.I),
        "oom_killer": re.compile(r'Out of memory.*Killed', re.I),
        "segfault": re.compile(r'segfault at', re.I),
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
        
        # SSH brute force
        if match := cls.PATTERNS["ssh_failed"].search(msg):
            threats.append({
                "type": "SSH_BRUTE_FORCE",
                "severity": "HIGH",
                "user": match.group(1),
                "source_ip": match.group(2),
                "mitre": "T1110.001"
            })
        
        # Invalid SSH user
        if match := cls.PATTERNS["ssh_invalid"].search(msg):
            threats.append({
                "type": "SSH_INVALID_USER",
                "severity": "MEDIUM",
                "user": match.group(1),
                "source_ip": match.group(2),
                "mitre": "T1078"
            })
        
        # Privilege escalation
        if match := cls.PATTERNS["sudo_command"].search(msg):
            threats.append({
                "type": "PRIVILEGE_ESCALATION",
                "severity": "HIGH",
                "command": match.group(1)[:100],
                "mitre": "T1548"
            })
        
        # SQL Injection
        if cls.PATTERNS["sql_injection"].search(msg):
            threats.append({
                "type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "mitre": "T1190"
            })
        
        # XSS
        if cls.PATTERNS["xss_attempt"].search(msg):
            threats.append({
                "type": "XSS_ATTEMPT",
                "severity": "HIGH",
                "mitre": "T1189"
            })
        
        # Path traversal
        if cls.PATTERNS["path_traversal"].search(msg):
            threats.append({
                "type": "PATH_TRAVERSAL",
                "severity": "HIGH",
                "mitre": "T1083"
            })
        
        # Port scan
        if cls.PATTERNS["port_scan"].search(msg):
            threats.append({
                "type": "PORT_SCAN",
                "severity": "MEDIUM",
                "mitre": "T1046"
            })
        
        # System issues
        if cls.PATTERNS["kernel_panic"].search(msg):
            threats.append({
                "type": "KERNEL_PANIC",
                "severity": "CRITICAL",
                "mitre": "T1499"
            })
        
        if cls.PATTERNS["oom_killer"].search(msg):
            threats.append({
                "type": "OOM_KILLER",
                "severity": "HIGH",
                "mitre": "T1499"
            })
        
        return threats


class ThreatAnalyzer:
    """Aggregates and analyzes threats across multiple events."""
    
    def __init__(self):
        self.failed_logins: Dict[str, List] = defaultdict(list)
        self.threats: List[Dict] = []
        self.events_processed = 0
    
    def process_event(self, event: Dict) -> List[Dict]:
        """Process event and return detected threats."""
        self.events_processed += 1
        threats = LogParser.detect_threats(event)
        
        # Track failed logins for brute force detection
        for threat in threats:
            if threat["type"] == "SSH_BRUTE_FORCE":
                ip = threat.get("source_ip", "unknown")
                self.failed_logins[ip].append(event.get("timestamp"))
                
                # Check threshold
                if len(self.failed_logins[ip]) >= Config.BRUTE_FORCE_THRESHOLD:
                    threat["severity"] = "CRITICAL"
                    threat["type"] = "BRUTE_FORCE_ATTACK"
                    threat["attempt_count"] = len(self.failed_logins[ip])
        
        self.threats.extend(threats)
        return threats
    
    def get_summary(self) -> Dict:
        """Get analysis summary."""
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)
        
        for threat in self.threats:
            severity_counts[threat["severity"]] += 1
            type_counts[threat["type"]] += 1
        
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
            "events_processed": self.events_processed,
            "threats_detected": len(self.threats),
            "severity_breakdown": dict(severity_counts),
            "threat_types": dict(type_counts),
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
        return False, f"Path not in allowed directories: {Config.ALLOWED_PATHS}"
    
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
    auth = AuthManager()
    
    if args.status:
        status = auth.get_status()
        print("\n╔══════════════════════════════════════════════════════════╗")
        print("║           AUTHENTICATION SYSTEM STATUS                   ║")
        print("╠══════════════════════════════════════════════════════════╣")
        print(f"║  Total Keys:        {status['total_keys']:>5}                             ║")
        print(f"║  Active Keys:       {status['active_keys']:>5}                             ║")
        print(f"║  Used Keys:         {status['used_keys']:>5}                             ║")
        print(f"║  Audit Entries:     {status['audit_entries']:>5}                             ║")
        print(f"║  Device FP:  {status['device_fingerprint']:<27}     ║")
        print("╚══════════════════════════════════════════════════════════╝\n")
        return 0
    
    if args.key:
        success, message = auth.authenticate(args.key)
        if success:
            print(f"\n✅ {message}\n")
            return 0
        else:
            print(f"\n❌ Authentication failed: {message}\n")
            return 1
    
    print("Use --key LICENSE_KEY to authenticate or --status to check status")
    return 1


def cmd_scan(args):
    """Handle log scan command."""
    # Validate file
    valid, msg = validate_file(args.file)
    if not valid:
        print(f"\n❌ {msg}\n")
        return 1
    
    print(f"\n🔍 Scanning: {args.file}")
    print("=" * 60)
    
    analyzer = ThreatAnalyzer()
    blockchain = Blockchain() if args.blockchain else None
    
    threats_found = []
    
    with open(args.file, 'r', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            event = LogParser.parse_line(line)
            if not event:
                continue
            
            threats = analyzer.process_event(event)
            
            if threats and args.verbose:
                for threat in threats:
                    print(f"  [{threat['severity']:>8}] Line {line_num}: {threat['type']}")
                    threats_found.append((line_num, threat))
            
            # Add to blockchain
            if blockchain and threats:
                for threat in threats:
                    data = json.dumps({
                        "line": line_num,
                        "type": threat["type"],
                        "severity": threat["severity"],
                        "timestamp": event.get("timestamp", "")
                    })
                    blockchain.add_block(data)
    
    # Print summary
    summary = analyzer.get_summary()
    
    print("\n" + "=" * 60)
    print("                    SCAN SUMMARY")
    print("=" * 60)
    print(f"  Events Processed:    {summary['events_processed']:>6}")
    print(f"  Threats Detected:    {summary['threats_detected']:>6}")
    print(f"  Unique Attackers:    {summary['unique_attackers']:>6}")
    print(f"  Risk Score:          {summary['risk_score']:>6}/100 ({summary['risk_level']})")
    
    if summary['severity_breakdown']:
        print("\n  Severity Breakdown:")
        for sev, count in sorted(summary['severity_breakdown'].items()):
            print(f"    {sev:>10}: {count}")
    
    if summary['threat_types']:
        print("\n  Threat Types:")
        for ttype, count in sorted(summary['threat_types'].items(), key=lambda x: -x[1]):
            print(f"    {ttype:<25}: {count}")
    
    if blockchain:
        print(f"\n  Blockchain: {len(blockchain.chain)} blocks")
    
    print("=" * 60 + "\n")
    
    # Output JSON if requested
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
    blockchain = Blockchain()
    
    if args.verify:
        valid, msg = blockchain.verify()
        if valid:
            print(f"\n✅ {msg}\n")
            return 0
        else:
            print(f"\n❌ Chain invalid: {msg}\n")
            return 1
    
    if args.show:
        if not blockchain.chain:
            print("\n⚠️  Blockchain is empty\n")
            return 0
        
        print(f"\n{'='*70}")
        print(f"{'BLOCKCHAIN STATUS':^70}")
        print(f"{'='*70}")
        print(f"  Blocks: {len(blockchain.chain)}")
        print(f"  Path: {blockchain.path}")
        print(f"{'='*70}")
        
        for i, block in enumerate(blockchain.chain[-10:]):  # Last 10 blocks
            print(f"\n  Block #{block.index}")
            print(f"    Hash:     {block.hash[:32]}...")
            print(f"    Previous: {block.previous_hash[:32]}...")
            print(f"    Nonce:    {block.nonce}")
            print(f"    Time:     {block.timestamp}")
            if block.data != "Genesis Block":
                try:
                    data = json.loads(block.data)
                    print(f"    Data:     {data.get('type', 'N/A')} @ line {data.get('line', 'N/A')}")
                except:
                    print(f"    Data:     {block.data[:50]}...")
        
        print(f"\n{'='*70}\n")
        return 0
    
    print("Use --verify to check integrity or --show to display blocks")
    return 1


def cmd_keygen(args):
    """Handle key generation command."""
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
    
    print("\n" + "=" * 70)
    print("                    NEW LICENSE KEY GENERATED")
    print("=" * 70)
    print(f"  Key:          {key}")
    print(f"  Organization: {args.org}")
    print(f"  Issued By:    {args.issuer}")
    print(f"  Valid For:    {args.hours} hours")
    print(f"  Expires:      {expires.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print("\n⚠️  Save this key! It can only be used ONCE on ONE device.\n")
    
    return 0


def cmd_audit(args):
    """Show audit trail."""
    conn = sqlite3.connect(str(Config.DB_PATH))
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, license_key, action, device_fingerprint, timestamp, status, error_message
        FROM auth_audit ORDER BY id DESC LIMIT ?
    """, (args.limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        print("\n⚠️  No audit entries found\n")
        return 0
    
    print("\n" + "=" * 90)
    print(f"{'AUTHENTICATION AUDIT TRAIL':^90}")
    print("=" * 90)
    print(f"{'ID':>4} | {'Action':<18} | {'Status':<8} | {'Device':<20} | {'Error'}")
    print("-" * 90)
    
    for row in rows:
        id, key, action, device, ts, status, err = row
        device = device[:20] if device else "N/A"
        print(f"{id:>4} | {action:<18} | {status:<8} | {device:<20} | {err or '-'}")
    
    print("=" * 90 + "\n")
    return 0


def cmd_fingerprint(args):
    """Show device fingerprint."""
    fp = DeviceFingerprint.generate()
    print(f"\n🔑 Device Fingerprint: {fp}\n")
    return 0


def cmd_version(args):
    """Show version."""
    print(f"\n{Config.APP_NAME} v{Config.VERSION}")
    print("Enterprise SIEM Platform - CLI Edition")
    print("(c) 2024 LogSentinel\n")
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
  logsentinel scan /var/log/auth.log         Scan log file for threats
  logsentinel scan /var/log/syslog -v -b     Scan with verbose + blockchain
  logsentinel keygen -o "Acme Corp" -h 720   Generate 30-day license key
  logsentinel blockchain --verify            Verify blockchain integrity
  logsentinel audit                          Show authentication audit trail
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
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Show each threat found")
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
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
