"""
Suspicious Event Detector
Rule-based + heuristic detection for identifying suspicious activity in parsed events.
Maps detections to MITRE ATT&CK tactics and techniques.

Pipelines:
  - Network Detection (C2 beacon, port scan, DNS tunnel, data exfiltration)
  - Auth Detection (brute force, impossible travel, new device, off-hours, priv esc)
  - System Detection (cron tampering, root cmd abuse, chmod 777, kernel panic, service crash)
  - App Detection (planned)
  - Cloud Detection (planned)
  - Container/DB Detection (planned)
"""
import re
import math
from typing import List, Dict, Tuple, Optional
from collections import defaultdict
from datetime import datetime, timedelta

# ── MITRE ATT&CK Mapping ────────────────────────────────────────────────────
MITRE_MAP = {
    "ssh_failed_login":       ("Initial Access",       "T1078 - Valid Accounts / Brute Force"),
    "ssh_invalid_user":       ("Initial Access",       "T1078.001 - Default Accounts"),
    "ssh_accepted_login":     ("Initial Access",       "T1078 - Valid Accounts"),
    "sudo_command":           ("Privilege Escalation",  "T1548.003 - Sudo and Sudo Caching"),
    "su_attempt":             ("Privilege Escalation",  "T1548 - Abuse Elevation Control"),
    "process_execution":      ("Execution",            "T1059 - Command and Scripting Interpreter"),
    "network_drop":           ("Discovery",            "T1046 - Network Service Discovery"),
    "network_accept":         ("Lateral Movement",     "T1021 - Remote Services"),
    "outbound_connection":    ("Exfiltration",         "T1041 - Exfiltration Over C2 Channel"),
    "windows_logon_failure":  ("Initial Access",       "T1078 - Valid Accounts / Brute Force"),
    "windows_logon_success":  ("Initial Access",       "T1078 - Valid Accounts"),
    "windows_privilege_assigned": ("Privilege Escalation", "T1134 - Access Token Manipulation"),
    "windows_process_created": ("Execution",           "T1059 - Command and Scripting Interpreter"),
    "windows_user_created":   ("Persistence",          "T1136 - Create Account"),
    "windows_group_member_added": ("Persistence",      "T1098 - Account Manipulation"),
    # ── Network pipeline MITRE mappings ──
    "c2_beacon":              ("Command and Control",  "T1071 - Application Layer Protocol"),
    "dns_tunnel":             ("Command and Control",  "T1071.004 - DNS"),
    "data_exfiltration":      ("Exfiltration",         "T1041 - Exfiltration Over C2 Channel"),
    "port_scan":              ("Discovery",            "T1046 - Network Service Discovery"),
    # ── Auth pipeline MITRE mappings ──
    "auth_brute_force":       ("Credential Access",    "T1110 - Brute Force"),
    "impossible_travel":      ("Initial Access",       "T1078 - Valid Accounts"),
    "new_device_login":       ("Initial Access",       "T1078 - Valid Accounts"),
    "off_hours_login":        ("Initial Access",       "T1078 - Valid Accounts"),
    "privilege_escalation":   ("Privilege Escalation", "T1548 - Abuse Elevation Control"),
    # ── System pipeline MITRE mappings ──
    "cron_tampering":         ("Execution",            "T1053 - Scheduled Task/Job"),
    "root_cmd_abuse":         ("Execution",            "T1059 - Command and Scripting Interpreter"),
    "file_permission_abuse":  ("Defense Evasion",      "T1222 - File and Directory Permissions Modification"),
    "kernel_panic":           ("Impact",               "N/A - Kernel Panic / System Instability"),
    "service_crash":          ("Impact",               "T1489 - Service Stop"),
}

# Suspicious processes and commands
SUSPICIOUS_PROCESSES = {
    "/bin/bash", "/bin/sh", "/usr/bin/python", "/usr/bin/perl",
    "/usr/bin/wget", "/usr/bin/curl", "/usr/bin/nc", "/usr/bin/ncat",
    "/usr/bin/nmap", "/usr/sbin/tcpdump", "/usr/bin/base64",
    "powershell.exe", "cmd.exe", "certutil.exe", "bitsadmin.exe",
    "whoami", "id", "cat /etc/shadow", "cat /etc/passwd",
}

SUSPICIOUS_COMMANDS = [
    "wget", "curl", "nc ", "ncat", "nmap", "tcpdump", "base64",
    "/etc/shadow", "/etc/passwd", "chmod 777", "chmod +s",
    "reverse", "shell", "bind", "payload", "exploit",
    "powershell -enc", "certutil -urlcache", "bitsadmin /transfer",
]

# Known bad / internal IP ranges for detection
INTERNAL_RANGES = ["10.", "172.16.", "172.17.", "172.18.", "192.168.", "127."]

# ── Network Detection Constants ─────────────────────────────────────────────
C2_BEACON_MIN_CONNECTIONS = 5
C2_BEACON_JITTER_THRESHOLD = 0.35
C2_BEACON_WINDOW_SECONDS = 3600
PORT_SCAN_THRESHOLD = 10
DNS_QUERY_LENGTH_THRESHOLD = 50
DNS_LABEL_COUNT_THRESHOLD = 5
DNS_HIGH_FREQ_THRESHOLD = 20
DNS_ENTROPY_THRESHOLD = 3.5
EXFIL_BYTES_THRESHOLD = 10_000_000
EXFIL_CONN_COUNT_THRESHOLD = 50

# ── Auth Detection Constants ────────────────────────────────────────────────
AUTH_BRUTE_FORCE_FAILURES = 5       # 5+ failures
AUTH_BRUTE_FORCE_WINDOW = 60        # in 60 seconds
AUTH_IMPOSSIBLE_SPEED_KMH = 800     # > 800 km/h is highly suspicious
AUTH_BUSINESS_START_HOUR = 8        # 08:00
AUTH_BUSINESS_END_HOUR = 18         # 18:00

# ── System Detection Constants ──────────────────────────────────────────────
CRON_TAMPERING_KEYWORDS = [
    "crontab", "/etc/cron", "/var/spool/cron", "at ", "atd", "anacron",
    "systemctl enable", "systemctl start", "/etc/cron.d", "/etc/cron.daily",
    "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly",
]
ROOT_DANGEROUS_COMMANDS = [
    "rm -rf /", "dd if=", "mkfs.", "> /dev/sd", "chmod -R 777 /",
    "iptables -F", "iptables --flush", "kill -9 1", "shutdown", "reboot",
    "init 0", "init 6", "halt", "poweroff", "passwd root",
    "userdel", "groupdel", "visudo", "chown root", "wget.*|.*sh",
    "curl.*|.*sh", "nc -e", "ncat -e", "bash -i >& /dev/tcp",
    "/dev/tcp/", "/dev/udp/", "python -c", "perl -e", "ruby -e",
]
FILE_PERM_PATTERNS = [
    r"chmod\s+777", r"chmod\s+666", r"chmod\s+\+s", r"chmod\s+u\+s",
    r"chmod\s+g\+s", r"chmod\s+o\+w", r"chmod\s+a\+w",
    r"chmod\s+-R\s+777", r"chmod\s+-R\s+666",
    r"chown\s+root:root", r"chattr\s+\-i",
]
KERNEL_PANIC_KEYWORDS = [
    "kernel panic", "kernel: BUG", "kernel: Oops", "Out of memory",
    "oom_kill_process", "oom-killer", "call trace", "segfault",
    "general protection fault", "unable to handle kernel",
    "soft lockup", "hard lockup", "RIP:", "kernel: NMI watchdog",
]
SERVICE_CRASH_RESTART_THRESHOLD = 3     # 3+ restarts
SERVICE_CRASH_WINDOW_SECONDS = 300      # within 5 minutes


def is_internal_ip(ip: str) -> bool:
    if not ip:
        return True
    return any(ip.startswith(prefix) for prefix in INTERNAL_RANGES)


def _calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: Dict[str, int] = defaultdict(int)
    for ch in data:
        freq[ch] += 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return entropy


def _haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great circle distance in kilometers between two points on the earth."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    c = 2 * math.asin(math.sqrt(a))
    return R * c


# ── Network Handlers ──
def _detect_c2_beacon(ip, timestamp, connection_tracker):
    if not ip or not timestamp: return None
    connection_tracker[ip].append(timestamp)
    timestamps = sorted(connection_tracker[ip])
    if len(timestamps) < C2_BEACON_MIN_CONNECTIONS: return None
    cutoff = timestamp - timedelta(seconds=C2_BEACON_WINDOW_SECONDS)
    recent = [t for t in timestamps if t >= cutoff]
    if len(recent) < C2_BEACON_MIN_CONNECTIONS: return None
    intervals = []
    for i in range(1, len(recent)):
        delta = (recent[i] - recent[i - 1]).total_seconds()
        if delta > 0: intervals.append(delta)
    if len(intervals) < 3: return None
    mean_interval = sum(intervals) / len(intervals)
    if mean_interval == 0: return None
    variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
    cv = math.sqrt(variance) / mean_interval
    if cv <= C2_BEACON_JITTER_THRESHOLD:
        return {"pipeline": "network", "detection": "c2_beacon", "mitre_id": "T1071", "severity": "critical", "confidence": round(max(0.5, 1.0 - cv), 2), "details": {"source_ip": ip, "cv": round(cv, 4)}}
    return None

def _detect_port_scan(ip, dst_port, port_tracker):
    if not ip or dst_port is None: return None
    port_tracker[ip].add(dst_port)
    unique_ports = len(port_tracker[ip])
    if unique_ports > PORT_SCAN_THRESHOLD:
        return {"pipeline": "network", "detection": "port_scan", "mitre_id": "T1046", "severity": "critical", "confidence": min(0.99, 0.7 + (unique_ports - PORT_SCAN_THRESHOLD) * 0.02), "details": {"source_ip": ip, "unique_ports": unique_ports}}
    return None

def _detect_dns_tunnel(query_name, src_ip, timestamp, dns_tracker):
    if not query_name or not src_ip: return None
    indicators, conf = [], 0.0
    if len(query_name) > DNS_QUERY_LENGTH_THRESHOLD: indicators.append("long_query"); conf += 0.25
    labels = query_name.split(".")
    if len(labels) > DNS_LABEL_COUNT_THRESHOLD: indicators.append("excess_labels"); conf += 0.2
    if len(labels) > 2 and _calculate_shannon_entropy(".".join(labels[:-2])) > DNS_ENTROPY_THRESHOLD: indicators.append("high_entropy"); conf += 0.3
    if timestamp:
        dns_tracker[src_ip].append(timestamp)
        if len([t for t in dns_tracker[src_ip] if t >= timestamp - timedelta(seconds=60)]) > DNS_HIGH_FREQ_THRESHOLD: indicators.append("high_freq"); conf += 0.25
    if len(indicators) >= 2 and conf >= 0.4:
        return {"pipeline": "network", "detection": "dns_tunnel", "mitre_id": "T1071.004", "severity": "critical" if conf >= 0.7 else "high", "confidence": round(min(0.99, conf), 2), "details": {"query_name": query_name}}
    return None

def _detect_data_exfiltration(src_ip, dst_ip, bytes_sent, timestamp, exfil_tracker):
    if not dst_ip or is_internal_ip(dst_ip) or bytes_sent <= 0: return None
    key = f"{src_ip}->{dst_ip}"
    if key not in exfil_tracker: exfil_tracker[key] = {"bytes": 0, "conn": 0}
    exfil_tracker[key]["bytes"] += bytes_sent
    exfil_tracker[key]["conn"] += 1
    b, c = exfil_tracker[key]["bytes"], exfil_tracker[key]["conn"]
    if b > EXFIL_BYTES_THRESHOLD or c > EXFIL_CONN_COUNT_THRESHOLD:
        return {"pipeline": "network", "detection": "data_exfiltration", "mitre_id": "T1041", "severity": "critical" if b > EXFIL_BYTES_THRESHOLD * 5 else "high", "confidence": min(0.99, 0.6 + (b / EXFIL_BYTES_THRESHOLD) * 0.1), "details": {"dst_ip": dst_ip, "bytes_sent": b}}
    return None


# ── Auth Handlers ──
def _detect_auth_brute_force(ip: str, timestamp: Optional[datetime], auth_fail_tracker: Dict[str, List[datetime]]) -> Optional[Dict]:
    if not ip or not timestamp: return None
    auth_fail_tracker[ip].append(timestamp)
    cutoff = timestamp - timedelta(seconds=AUTH_BRUTE_FORCE_WINDOW)
    recent = [t for t in auth_fail_tracker[ip] if t >= cutoff]
    if len(recent) >= AUTH_BRUTE_FORCE_FAILURES:
        return {"pipeline": "auth", "detection": "auth_brute_force", "mitre_id": "T1110", "severity": "critical", "confidence": 0.95, "details": {"ip": ip, "failures": len(recent)}}
    return None

def _detect_impossible_travel(user: str, ip: str, lat: float, lon: float, timestamp: datetime, user_geo_tracker: Dict[str, List[Dict]]) -> Optional[Dict]:
    if not user or not timestamp or lat is None or lon is None: return None
    history = user_geo_tracker.get(user, [])
    if history:
        last = history[-1]
        time_diff = (timestamp - last["timestamp"]).total_seconds() / 3600.0
        distance = _haversine_distance(last["lat"], last["lon"], lat, lon)
        if time_diff > 0 and distance > 0:
            speed = distance / time_diff
            if speed > AUTH_IMPOSSIBLE_SPEED_KMH:
                user_geo_tracker[user].append({"timestamp": timestamp, "lat": lat, "lon": lon, "ip": ip})
                return {"pipeline": "auth", "detection": "impossible_travel", "mitre_id": "T1078", "severity": "high", "confidence": 0.90, "details": {"user": user, "speed_kmh": round(speed, 2), "distance": round(distance, 2)}}
    user_geo_tracker.setdefault(user, []).append({"timestamp": timestamp, "lat": lat, "lon": lon, "ip": ip})
    return None

def _detect_new_device(user: str, device_id: str, user_device_tracker: Dict[str, set]) -> Optional[Dict]:
    if not user or not device_id: return None
    known = user_device_tracker.get(user, set())
    if known and device_id not in known:
        user_device_tracker[user].add(device_id)
        return {"pipeline": "auth", "detection": "new_device_login", "mitre_id": "T1078", "severity": "low", "confidence": 0.80, "details": {"user": user, "new_device": device_id}}
    user_device_tracker.setdefault(user, set()).add(device_id)
    return None

def _is_off_hours(timestamp: datetime) -> bool:
    if not timestamp: return False
    if timestamp.weekday() >= 5: return True
    if timestamp.hour < AUTH_BUSINESS_START_HOUR or timestamp.hour >= AUTH_BUSINESS_END_HOUR: return True
    return False


# ── System Handlers ──
def _detect_cron_tampering(event: Dict) -> Optional[Dict]:
    """Detect crontab modifications, at job scheduling, and cron directory changes (T1053)."""
    raw_log = event.get("raw_log", "").lower()
    action = event.get("action", "").lower()
    process = event.get("process", "").lower()
    combined = f"{raw_log} {action} {process}"

    matches = [kw for kw in CRON_TAMPERING_KEYWORDS if kw.lower() in combined]
    if not matches:
        return None

    # Higher confidence for direct crontab edits
    confidence = 0.75
    severity = "high"
    if "crontab" in combined and ("edit" in combined or "-e" in combined or "-r" in combined):
        confidence = 0.95
        severity = "critical"
    elif "/etc/cron" in combined:
        confidence = 0.90
        severity = "critical"

    return {
        "pipeline": "system",
        "detection": "cron_tampering",
        "mitre_id": "T1053",
        "severity": severity,
        "confidence": confidence,
        "detection_details": {
            "matched_keywords": matches,
            "user": event.get("user", "unknown"),
        },
    }


def _detect_root_cmd_abuse(event: Dict) -> Optional[Dict]:
    """Detect dangerous commands executed as root or via sudo (T1059)."""
    user = event.get("user", "").lower()
    raw_log = event.get("raw_log", "")
    process = event.get("process", "")
    action = event.get("action", "").lower()
    combined = f"{raw_log} {process}"

    is_root = user == "root" or "sudo" in action or "sudo" in raw_log.lower()
    if not is_root:
        return None

    matched = []
    for cmd in ROOT_DANGEROUS_COMMANDS:
        if cmd.lower() in combined.lower():
            matched.append(cmd)

    if not matched:
        return None

    # Severity escalation based on destructiveness
    severity = "high"
    confidence = 0.85
    critical_cmds = ["rm -rf /", "dd if=", "mkfs.", "kill -9 1", "> /dev/sd"]
    if any(c in combined.lower() for c in critical_cmds):
        severity = "critical"
        confidence = 0.95

    return {
        "pipeline": "system",
        "detection": "root_cmd_abuse",
        "mitre_id": "T1059",
        "severity": severity,
        "confidence": confidence,
        "detection_details": {
            "matched_commands": matched,
            "user": event.get("user", "unknown"),
            "raw_snippet": raw_log[:200],
        },
    }


def _detect_file_permission_abuse(event: Dict) -> Optional[Dict]:
    """Detect chmod 777, setuid/setgid changes, and broad permission modifications (T1222)."""
    raw_log = event.get("raw_log", "")
    process = event.get("process", "")
    combined = f"{raw_log} {process}"

    matched = []
    for pattern in FILE_PERM_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            matched.append(pattern)

    if not matched:
        return None

    severity = "high"
    confidence = 0.85
    # chmod 777 on sensitive paths is critical
    if re.search(r"chmod\s+(777|-R\s+777)", combined) and any(
        p in combined for p in ["/etc", "/usr", "/bin", "/sbin", "/root", "/var"]
    ):
        severity = "critical"
        confidence = 0.95
    # setuid bit is always critical
    if re.search(r"chmod\s+\+s|chmod\s+u\+s", combined):
        severity = "critical"
        confidence = 0.95

    return {
        "pipeline": "system",
        "detection": "file_permission_abuse",
        "mitre_id": "T1222",
        "severity": severity,
        "confidence": confidence,
        "detection_details": {
            "matched_patterns": matched,
            "user": event.get("user", "unknown"),
            "raw_snippet": raw_log[:200],
        },
    }


def _detect_kernel_panic(event: Dict) -> Optional[Dict]:
    """Detect kernel panics, OOM kills, BUGs, oops, and other critical kernel failures."""
    raw_log = event.get("raw_log", "").lower()
    action = event.get("action", "").lower()
    process = event.get("process", "").lower()
    combined = f"{raw_log} {action} {process}"

    matched = [kw for kw in KERNEL_PANIC_KEYWORDS if kw.lower() in combined]
    if not matched:
        return None

    severity = "critical"
    confidence = 0.90
    # Actual kernel panic is highest severity
    if "kernel panic" in combined:
        confidence = 0.99
    elif "oom" in combined or "out of memory" in combined:
        confidence = 0.92
    elif "segfault" in combined:
        severity = "high"
        confidence = 0.85

    return {
        "pipeline": "system",
        "detection": "kernel_panic",
        "mitre_id": "N/A",
        "severity": severity,
        "confidence": confidence,
        "detection_details": {
            "matched_keywords": matched,
            "raw_snippet": raw_log[:300],
        },
    }


def _detect_service_crash(service_name: str, timestamp: Optional[datetime],
                          service_tracker: Dict[str, List[datetime]]) -> Optional[Dict]:
    """Detect services crashing and restarting repeatedly within a short window (T1489)."""
    if not service_name or not timestamp:
        return None

    service_tracker.setdefault(service_name, []).append(timestamp)
    cutoff = timestamp - timedelta(seconds=SERVICE_CRASH_WINDOW_SECONDS)
    recent = [t for t in service_tracker[service_name] if t >= cutoff]
    service_tracker[service_name] = recent  # prune old entries

    if len(recent) >= SERVICE_CRASH_RESTART_THRESHOLD:
        confidence = min(0.99, 0.70 + (len(recent) - SERVICE_CRASH_RESTART_THRESHOLD) * 0.05)
        return {
            "pipeline": "system",
            "detection": "service_crash",
            "mitre_id": "T1489",
            "severity": "critical" if len(recent) >= SERVICE_CRASH_RESTART_THRESHOLD * 2 else "high",
            "confidence": round(confidence, 2),
            "detection_details": {
                "service": service_name,
                "restart_count": len(recent),
                "window_seconds": SERVICE_CRASH_WINDOW_SECONDS,
            },
        }
    return None


def detect_suspicious_events(events: List[Dict]) -> List[Dict]:
    """
    Analyze events and flag suspicious ones with severity ratings
    and MITRE ATT&CK mappings.

    Includes core rules + Network Pipeline + Auth Pipeline + System Pipeline.
    """
    failed_logins = defaultdict(list)
    login_sources = defaultdict(set)
    port_scans = defaultdict(list)

    c2_tracker = defaultdict(list)
    scan_tracker = defaultdict(set)
    dns_tracker = defaultdict(list)
    exfil_tracker = {}
    
    auth_fail_tracker = defaultdict(list)
    user_geo_tracker = {}
    user_device_tracker = {}

    service_restart_tracker: Dict[str, List[datetime]] = {}

    for event in events:
        action = event.get("action", "")
        ip = event.get("ip_address")
        user = event.get("user")
        process = event.get("process", "")
        timestamp = event.get("timestamp")
        raw_log = event.get("raw_log", "")

        event["is_suspicious"] = 0
        event["severity"] = "low"
        event["detection_rule"] = None
        event["mitre_tactic"] = None
        event["mitre_technique"] = None
        event.setdefault("pipeline", None)
        event.setdefault("confidence", None)
        event.setdefault("detection_details", None)

        if action in MITRE_MAP:
            event["mitre_tactic"], event["mitre_technique"] = MITRE_MAP[action]

        # ── Baseline Rules ──
        if action in ("ssh_failed_login", "ssh_invalid_user", "windows_logon_failure"):
            event["is_suspicious"] = 1
            event["severity"] = "medium"
            event["detection_rule"] = "failed_login"
            if ip: failed_logins[ip].append(timestamp)

        if ip and ip in failed_logins and timestamp:
            recent = [t for t in failed_logins[ip] if t and abs((timestamp - t).total_seconds()) < 300]
            if len(recent) >= 5:
                event["severity"] = "critical"
                event["detection_rule"] = "brute_force"
                event["mitre_technique"] = "T1110 - Brute Force"

        if action in ("ssh_accepted_login", "windows_logon_success") and ip:
            if not is_internal_ip(ip):
                event["is_suspicious"] = 1
                event["severity"] = "high"
                event["detection_rule"] = "external_login"
            if user: login_sources[user].add(ip)

        if user and len(login_sources.get(user, set())) > 2:
            event["is_suspicious"] = 1
            event["severity"] = "high"
            event["detection_rule"] = "multiple_login_sources"

        if action in ("sudo_command", "su_attempt", "windows_privilege_assigned"):
            event["is_suspicious"] = 1
            event["severity"] = "high"
            event["detection_rule"] = "privilege_escalation"

        if process:
            proc_lower = process.lower()
            if any(sp in proc_lower for sp in SUSPICIOUS_COMMANDS):
                event["is_suspicious"] = 1
                event["severity"] = "high"
                event["detection_rule"] = "suspicious_process"
            if process in SUSPICIOUS_PROCESSES:
                event["is_suspicious"] = 1
                event["severity"] = "medium"
                event["detection_rule"] = "known_suspicious_binary"

        # ── Pipeline: Network Detection ──
        if action in ("connection", "outbound_connection", "network_accept", "network_drop", "dns_query", "data_transfer"):
            dst_ip = event.get("dst_ip") or (re.search(r"DST=(\d+\.\d+\.\d+\.\d+)", raw_log).group(1) if re.search(r"DST=(\d+\.\d+\.\d+\.\d+)", raw_log) else None)
            src_ip = ip or event.get("src_ip", "unknown")
            
            if dst_ip and not is_internal_ip(dst_ip) and action in ("connection", "outbound_connection"):
                res = _detect_c2_beacon(dst_ip, timestamp, c2_tracker)
                if res: event.update({"is_suspicious": 1, **res})
            
            dst_port_raw = event.get("dst_port") or event.get("port") or (re.search(r"DPT=(\d+)", raw_log).group(1) if re.search(r"DPT=(\d+)", raw_log) else None)
            if dst_port_raw and src_ip:
                try:
                    res = _detect_port_scan(src_ip, int(dst_port_raw), scan_tracker)
                    if res: event.update({"is_suspicious": 1, **res})
                except ValueError: pass
                
            if "dns" in action:
                query_name = event.get("query_name") or (re.search(r"query:\s*(\S+)", raw_log, re.IGNORECASE).group(1) if re.search(r"query:\s*(\S+)", raw_log, re.IGNORECASE) else None)
                if query_name:
                    res = _detect_dns_tunnel(query_name, src_ip, timestamp, dns_tracker)
                    if res: event.update({"is_suspicious": 1, **res})
                    
            bytes_sent = event.get("bytes_sent") or event.get("bytes_out") or (re.search(r"LEN=(\d+)", raw_log).group(1) if re.search(r"LEN=(\d+)", raw_log) else 0)
            if dst_ip and bytes_sent:
                try:
                    res = _detect_data_exfiltration(src_ip, dst_ip, int(bytes_sent), timestamp, exfil_tracker)
                    if res: event.update({"is_suspicious": 1, **res})
                except ValueError: pass

        # ── Pipeline: Auth Detection ──
        is_auth_event = "login" in action or "logon" in action or action in ("auth_failed", "auth_success")
        is_fail = "fail" in action or "invalid" in action
        is_success = "success" in action or "accepted" in action
        
        if is_auth_event or action in ("sudo_command", "su_attempt", "role_change"):
            # 1. Priv Escalation Detection
            if action in ("sudo_command", "su_attempt", "role_change"):
                event.update({"is_suspicious": 1, "pipeline": "auth", "detection": "privilege_escalation", "mitre_id": "T1548", "severity": "high", "confidence": 0.90, "detection_details": {"user": user, "action": action}})

            # 2. Brute Force Detection
            if is_fail and ip:
                brute_res = _detect_auth_brute_force(ip, timestamp, auth_fail_tracker)
                if brute_res: event.update({"is_suspicious": 1, **brute_res})

            if is_success and user:
                # 3. Impossible Travel
                lat = event.get("lat") or event.get("geo", {}).get("lat")
                lon = event.get("lon") or event.get("geo", {}).get("lon")
                if lat is not None and lon is not None and timestamp:
                    travel_res = _detect_impossible_travel(user, ip, float(lat), float(lon), timestamp, user_geo_tracker)
                    if travel_res: event.update({"is_suspicious": 1, **travel_res})
                
                # 4. New Device Login
                device_id = event.get("device_id") or event.get("user_agent") or ip
                if device_id:
                    device_res = _detect_new_device(user, device_id, user_device_tracker)
                    if device_res and (event["severity"] == "low" or event["detection"] is None):
                        event.update({"is_suspicious": 1, **device_res})

                # 5. Off-Hours Access
                if timestamp and _is_off_hours(timestamp):
                    if event["severity"] == "low" or event["detection"] is None:
                        event.update({"is_suspicious": 1, "pipeline": "auth", "detection": "off_hours_login", "mitre_id": "T1078", "severity": "low", "confidence": 0.70, "detection_details": {"user": user}})

        # ── Pipeline: System Detection ──
        # Cron Tampering (T1053)
        cron_res = _detect_cron_tampering(event)
        if cron_res:
            event.update({"is_suspicious": 1, **cron_res})

        # Root Command Abuse (T1059)
        root_res = _detect_root_cmd_abuse(event)
        if root_res:
            event.update({"is_suspicious": 1, **root_res})

        # File Permission Abuse / chmod 777 (T1222)
        perm_res = _detect_file_permission_abuse(event)
        if perm_res:
            event.update({"is_suspicious": 1, **perm_res})

        # Kernel Panic
        kp_res = _detect_kernel_panic(event)
        if kp_res:
            event.update({"is_suspicious": 1, **kp_res})

        # Service Crash / Repeated Restart (T1489)
        service_name = event.get("service") or event.get("unit")
        if not service_name:
            # Try to extract service name from raw log
            svc_match = re.search(r"(?:systemd|init).*?:\s*(\S+)\.service", raw_log)
            if svc_match:
                service_name = svc_match.group(1)
        restart_keywords = ["restart", "started", "activating", "failed", "crash", "core dump", "exited"]
        if service_name and any(kw in raw_log.lower() or kw in action for kw in restart_keywords):
            svc_res = _detect_service_crash(service_name, timestamp, service_restart_tracker)
            if svc_res:
                event.update({"is_suspicious": 1, **svc_res})

    return events


def calculate_risk_score(events: List[Dict]) -> Tuple[float, str]:
    if not events: return 0.0, "low"

    severity_weights = {"low": 1, "medium": 3, "high": 7, "critical": 15}
    total_score = sum(severity_weights.get(e.get("severity", "low"), 1) for e in events if e.get("is_suspicious"))
    
    max_possible = len(events) * 15
    normalized = min(100, (total_score / max(max_possible, 1)) * 100 * 5)

    unique_rules = set(e.get("detection_rule") for e in events if e.get("detection_rule"))
    unique_pipelines = set(e.get("pipeline") for e in events if e.get("pipeline"))
    
    normalized += len(unique_rules) * 5
    normalized += len(unique_pipelines) * 10

    normalized = min(100, normalized)
    
    if normalized >= 75: level = "critical"
    elif normalized >= 50: level = "high"
    elif normalized >= 25: level = "medium"
    else: level = "low"

    return round(normalized, 1), level
