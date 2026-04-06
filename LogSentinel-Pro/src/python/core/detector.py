"""
Suspicious Event Detector
Rule-based + heuristic detection for identifying suspicious activity in parsed events.
Maps detections to MITRE ATT&CK tactics and techniques.

Pipelines:
  - Network Detection (C2 beacon, port scan, DNS tunnel, data exfiltration)
  - Auth Detection (planned)
  - System Detection (planned)
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
# C2 Beacon: periodic callback detection
C2_BEACON_MIN_CONNECTIONS = 5       # minimum connections to consider a beacon
C2_BEACON_JITTER_THRESHOLD = 0.35   # max coefficient of variation for interval regularity
C2_BEACON_WINDOW_SECONDS = 3600     # 1-hour sliding window

# Port Scan: multiple ports from same source IP
PORT_SCAN_THRESHOLD = 10            # unique ports contacted to flag as scan

# DNS Tunnel: long subdomain queries, high frequency
DNS_QUERY_LENGTH_THRESHOLD = 50     # query name length threshold
DNS_LABEL_COUNT_THRESHOLD = 5       # number of subdomain labels
DNS_HIGH_FREQ_THRESHOLD = 20        # queries in 60 seconds from same source
DNS_ENTROPY_THRESHOLD = 3.5         # Shannon entropy for subdomain randomness

# Data Exfiltration: large outbound transfers to external IPs
EXFIL_BYTES_THRESHOLD = 10_000_000  # 10 MB cumulative to same external IP
EXFIL_CONN_COUNT_THRESHOLD = 50     # many connections to same external host


def is_internal_ip(ip: str) -> bool:
    """Check if an IP is in internal/private range."""
    if not ip:
        return True
    return any(ip.startswith(prefix) for prefix in INTERNAL_RANGES)


def _calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string (useful for DNS tunnel detection)."""
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


def _detect_c2_beacon(
    ip: str,
    timestamp: Optional[datetime],
    connection_tracker: Dict[str, List[datetime]],
) -> Optional[Dict]:
    """
    Detect C2 beacon behavior by identifying periodic connection patterns.

    C2 beacons typically call home at regular intervals. We detect this by
    measuring the coefficient of variation (stddev/mean) of inter-connection
    intervals. A low CV indicates periodic behavior.

    Args:
        ip: Source IP address making connections.
        timestamp: Connection timestamp.
        connection_tracker: Dict tracking {ip: [timestamps]}.

    Returns:
        Detection result dict if beacon detected, None otherwise.
    """
    if not ip or not timestamp:
        return None

    connection_tracker[ip].append(timestamp)
    timestamps = sorted(connection_tracker[ip])

    # Only analyze if enough connections
    if len(timestamps) < C2_BEACON_MIN_CONNECTIONS:
        return None

    # Filter to recent window only
    cutoff = timestamp - timedelta(seconds=C2_BEACON_WINDOW_SECONDS)
    recent = [t for t in timestamps if t >= cutoff]
    if len(recent) < C2_BEACON_MIN_CONNECTIONS:
        return None

    # Calculate inter-arrival intervals
    intervals = []
    for i in range(1, len(recent)):
        delta = (recent[i] - recent[i - 1]).total_seconds()
        if delta > 0:
            intervals.append(delta)

    if len(intervals) < 3:
        return None

    # Calculate coefficient of variation
    mean_interval = sum(intervals) / len(intervals)
    if mean_interval == 0:
        return None

    variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
    stddev = math.sqrt(variance)
    cv = stddev / mean_interval

    if cv <= C2_BEACON_JITTER_THRESHOLD:
        return {
            "pipeline": "network",
            "detection": "c2_beacon",
            "mitre_id": "T1071",
            "severity": "critical",
            "confidence": round(max(0.5, 1.0 - cv), 2),
            "details": {
                "source_ip": ip,
                "connection_count": len(recent),
                "mean_interval_seconds": round(mean_interval, 2),
                "coefficient_of_variation": round(cv, 4),
                "window_seconds": C2_BEACON_WINDOW_SECONDS,
            },
        }
    return None


def _detect_port_scan(
    ip: str,
    dst_port: Optional[int],
    port_tracker: Dict[str, set],
) -> Optional[Dict]:
    """
    Detect port scanning behavior — multiple unique destination ports
    contacted from the same source IP.

    Args:
        ip: Source IP address.
        dst_port: Destination port number.
        port_tracker: Dict tracking {ip: {ports}}.

    Returns:
        Detection result dict if port scan detected, None otherwise.
    """
    if not ip or dst_port is None:
        return None

    port_tracker[ip].add(dst_port)
    unique_ports = len(port_tracker[ip])

    if unique_ports > PORT_SCAN_THRESHOLD:
        return {
            "pipeline": "network",
            "detection": "port_scan",
            "mitre_id": "T1046",
            "severity": "critical",
            "confidence": min(0.99, 0.7 + (unique_ports - PORT_SCAN_THRESHOLD) * 0.02),
            "details": {
                "source_ip": ip,
                "unique_ports_scanned": unique_ports,
                "threshold": PORT_SCAN_THRESHOLD,
                "sample_ports": sorted(list(port_tracker[ip]))[:20],
            },
        }
    return None


def _detect_dns_tunnel(
    query_name: str,
    src_ip: str,
    timestamp: Optional[datetime],
    dns_tracker: Dict[str, List[datetime]],
) -> Optional[Dict]:
    """
    Detect DNS tunneling by analyzing query characteristics:
    - Unusually long domain names (data encoded in subdomains)
    - High subdomain label count
    - High Shannon entropy in subdomain labels (random-looking strings)
    - High query frequency from same source

    Args:
        query_name: DNS query name (e.g., 'aGVsbG8.d2f9c.tunnel.evil.com').
        src_ip: Source IP making the query.
        timestamp: Query timestamp.
        dns_tracker: Dict tracking {ip: [timestamps]} for frequency analysis.

    Returns:
        Detection result dict if DNS tunnel detected, None otherwise.
    """
    if not query_name or not src_ip:
        return None

    indicators = []
    confidence = 0.0

    # Check query length
    if len(query_name) > DNS_QUERY_LENGTH_THRESHOLD:
        indicators.append("long_query")
        confidence += 0.25

    # Check label count (split by '.')
    labels = query_name.split(".")
    if len(labels) > DNS_LABEL_COUNT_THRESHOLD:
        indicators.append("excessive_labels")
        confidence += 0.2

    # Check entropy of subdomain portion (everything except last 2 labels = domain + TLD)
    if len(labels) > 2:
        subdomain = ".".join(labels[:-2])
        entropy = _calculate_shannon_entropy(subdomain)
        if entropy > DNS_ENTROPY_THRESHOLD:
            indicators.append("high_entropy_subdomain")
            confidence += 0.3

    # Check frequency
    if timestamp:
        dns_tracker[src_ip].append(timestamp)
        cutoff = timestamp - timedelta(seconds=60)
        recent_queries = [t for t in dns_tracker[src_ip] if t >= cutoff]
        if len(recent_queries) > DNS_HIGH_FREQ_THRESHOLD:
            indicators.append("high_frequency")
            confidence += 0.25

    if len(indicators) >= 2 and confidence >= 0.4:
        return {
            "pipeline": "network",
            "detection": "dns_tunnel",
            "mitre_id": "T1071.004",
            "severity": "critical" if confidence >= 0.7 else "high",
            "confidence": round(min(0.99, confidence), 2),
            "details": {
                "query_name": query_name,
                "source_ip": src_ip,
                "indicators": indicators,
                "query_length": len(query_name),
                "label_count": len(labels),
            },
        }
    return None


def _detect_data_exfiltration(
    src_ip: str,
    dst_ip: str,
    bytes_sent: int,
    timestamp: Optional[datetime],
    exfil_tracker: Dict[str, Dict],
) -> Optional[Dict]:
    """
    Detect potential data exfiltration by monitoring large outbound data
    transfers to external IP addresses.

    Tracks cumulative bytes sent per source→destination pair and flags
    when thresholds are exceeded.

    Args:
        src_ip: Source (internal) IP.
        dst_ip: Destination (external) IP.
        bytes_sent: Number of bytes in this transfer.
        timestamp: Event timestamp.
        exfil_tracker: Dict tracking {dst_ip: {"total_bytes": int, "conn_count": int}}.

    Returns:
        Detection result dict if exfiltration detected, None otherwise.
    """
    if not dst_ip or is_internal_ip(dst_ip) or bytes_sent <= 0:
        return None

    key = f"{src_ip}->{dst_ip}"
    if key not in exfil_tracker:
        exfil_tracker[key] = {"total_bytes": 0, "conn_count": 0, "first_seen": timestamp}

    exfil_tracker[key]["total_bytes"] += bytes_sent
    exfil_tracker[key]["conn_count"] += 1

    total_bytes = exfil_tracker[key]["total_bytes"]
    conn_count = exfil_tracker[key]["conn_count"]

    # Flag on bytes threshold OR excessive connection count
    if total_bytes > EXFIL_BYTES_THRESHOLD or conn_count > EXFIL_CONN_COUNT_THRESHOLD:
        severity = "critical" if total_bytes > EXFIL_BYTES_THRESHOLD * 5 else "high"
        confidence = min(0.99, 0.6 + (total_bytes / EXFIL_BYTES_THRESHOLD) * 0.1)

        return {
            "pipeline": "network",
            "detection": "data_exfiltration",
            "mitre_id": "T1041",
            "severity": severity,
            "confidence": round(confidence, 2),
            "details": {
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "total_bytes_sent": total_bytes,
                "total_bytes_sent_mb": round(total_bytes / (1024 * 1024), 2),
                "connection_count": conn_count,
                "bytes_threshold": EXFIL_BYTES_THRESHOLD,
            },
        }
    return None


def detect_suspicious_events(events: List[Dict]) -> List[Dict]:
    """
    Analyze events and flag suspicious ones with severity ratings
    and MITRE ATT&CK mappings.

    Includes all original 10 detection rules plus the Network Detection
    Pipeline (C2 beacon, port scan, DNS tunnel, data exfiltration).
    """
    # Track patterns for correlation
    failed_logins = defaultdict(list)  # ip -> [timestamps]
    login_sources = defaultdict(set)   # user -> {ips}
    port_scans = defaultdict(list)     # ip -> [ports]

    # ── Network pipeline trackers ──
    c2_connection_tracker: Dict[str, List[datetime]] = defaultdict(list)
    port_scan_tracker: Dict[str, set] = defaultdict(set)
    dns_query_tracker: Dict[str, List[datetime]] = defaultdict(list)
    exfil_tracker: Dict[str, Dict] = {}

    for event in events:
        action = event.get("action", "")
        ip = event.get("ip_address")
        user = event.get("user")
        process = event.get("process", "")
        timestamp = event.get("timestamp")
        raw_log = event.get("raw_log", "")

        # Default values
        event["is_suspicious"] = 0
        event["severity"] = "low"
        event["detection_rule"] = None
        event["mitre_tactic"] = None
        event["mitre_technique"] = None
        event.setdefault("pipeline", None)
        event.setdefault("confidence", None)

        # Apply MITRE mapping
        if action in MITRE_MAP:
            event["mitre_tactic"], event["mitre_technique"] = MITRE_MAP[action]

        # ── Rule 1: Failed login attempts ──
        if action in ("ssh_failed_login", "ssh_invalid_user", "windows_logon_failure"):
            event["is_suspicious"] = 1
            event["severity"] = "medium"
            event["detection_rule"] = "failed_login"
            if ip:
                failed_logins[ip].append(timestamp)

        # ── Rule 2: Brute force detection (5+ failures from same IP in 5 min) ──
        if ip and ip in failed_logins:
            recent = [t for t in failed_logins[ip]
                      if timestamp and t and abs((timestamp - t).total_seconds()) < 300]
            if len(recent) >= 5:
                event["severity"] = "critical"
                event["detection_rule"] = "brute_force"
                event["mitre_technique"] = "T1110 - Brute Force"

        # ── Rule 3: Login from unknown/external IP ──
        if action in ("ssh_accepted_login", "windows_logon_success") and ip:
            if not is_internal_ip(ip):
                event["is_suspicious"] = 1
                event["severity"] = "high"
                event["detection_rule"] = "external_login"
            if user:
                login_sources[user].add(ip)

        # ── Rule 4: Multiple login sources for same user ──
        if user and len(login_sources.get(user, set())) > 2:
            event["is_suspicious"] = 1
            event["severity"] = "high"
            event["detection_rule"] = "multiple_login_sources"

        # ── Rule 5: Privilege escalation ──
        if action in ("sudo_command", "su_attempt", "windows_privilege_assigned"):
            event["is_suspicious"] = 1
            event["severity"] = "high"
            event["detection_rule"] = "privilege_escalation"

        # ── Rule 6: Suspicious process execution ──
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

        # ── Rule 7: Port scanning behavior (original) ──
        if action in ("network_drop", "connection") and ip:
            dst_port = event.get("process", "").replace("port_", "")
            if dst_port.isdigit():
                port_scans[ip].append(int(dst_port))
                if len(set(port_scans[ip])) > 10:
                    event["is_suspicious"] = 1
                    event["severity"] = "critical"
                    event["detection_rule"] = "port_scan"
                    event["mitre_tactic"] = "Discovery"
                    event["mitre_technique"] = "T1046 - Network Service Discovery"

        # ── Rule 8: Outbound connections to external IPs ──
        if action in ("network_accept", "connection"):
            dst_ip = None
            dst_match = re.search(r"DST=(\d+\.\d+\.\d+\.\d+)", raw_log)
            if dst_match:
                dst_ip = dst_match.group(1)
            if dst_ip and not is_internal_ip(dst_ip):
                event["is_suspicious"] = 1
                event["severity"] = "high"
                event["detection_rule"] = "outbound_external"
                event["action"] = "outbound_connection"
                event["mitre_tactic"] = "Exfiltration"
                event["mitre_technique"] = "T1041 - Exfiltration Over C2 Channel"

        # ── Rule 9: Account creation / manipulation ──
        if action in ("windows_user_created", "windows_group_member_added"):
            event["is_suspicious"] = 1
            event["severity"] = "high"
            event["detection_rule"] = "account_manipulation"

        # ── Rule 10: Post-exploitation indicators ──
        if process and any(cmd in process.lower() for cmd in
                          ["shadow", "passwd", "whoami", " id", "ifconfig", "ipconfig"]):
            event["is_suspicious"] = 1
            event["severity"] = "critical"
            event["detection_rule"] = "post_exploitation_recon"
            event["mitre_tactic"] = "Discovery"
            event["mitre_technique"] = "T1087 - Account Discovery"

        # ════════════════════════════════════════════════════════════════════
        # ██  NETWORK DETECTION PIPELINE — C2, Port Scan, DNS Tunnel, Exfil
        # ════════════════════════════════════════════════════════════════════

        # ── Network Rule 1: C2 Beacon Detection ──
        # Periodic outbound connections to the same external IP indicate
        # a compromised host calling back to a C2 server.
        if action in ("connection", "outbound_connection", "network_accept"):
            dst_ip = event.get("dst_ip")
            if not dst_ip:
                dst_match = re.search(r"DST=(\d+\.\d+\.\d+\.\d+)", raw_log)
                if dst_match:
                    dst_ip = dst_match.group(1)

            if dst_ip and not is_internal_ip(dst_ip):
                beacon_result = _detect_c2_beacon(
                    ip=dst_ip,
                    timestamp=timestamp,
                    connection_tracker=c2_connection_tracker,
                )
                if beacon_result:
                    event["is_suspicious"] = 1
                    event["severity"] = beacon_result["severity"]
                    event["detection_rule"] = "c2_beacon"
                    event["pipeline"] = "network"
                    event["confidence"] = beacon_result["confidence"]
                    event["mitre_tactic"] = "Command and Control"
                    event["mitre_technique"] = "T1071 - Application Layer Protocol"
                    event["detection_details"] = beacon_result["details"]

        # ── Network Rule 2: Enhanced Port Scan Detection ──
        # Tracks unique destination ports per source IP using dedicated tracker
        if action in ("connection", "network_drop", "network_accept", "port_probe"):
            dst_port_raw = event.get("dst_port") or event.get("port")
            if dst_port_raw is None:
                port_match = re.search(r"DPT=(\d+)", raw_log)
                if port_match:
                    dst_port_raw = port_match.group(1)

            if dst_port_raw is not None:
                try:
                    dst_port_int = int(dst_port_raw)
                except (ValueError, TypeError):
                    dst_port_int = None

                if dst_port_int is not None and ip:
                    scan_result = _detect_port_scan(
                        ip=ip,
                        dst_port=dst_port_int,
                        port_tracker=port_scan_tracker,
                    )
                    if scan_result:
                        event["is_suspicious"] = 1
                        event["severity"] = scan_result["severity"]
                        event["detection_rule"] = "port_scan_advanced"
                        event["pipeline"] = "network"
                        event["confidence"] = scan_result["confidence"]
                        event["mitre_tactic"] = "Discovery"
                        event["mitre_technique"] = "T1046 - Network Service Discovery"
                        event["detection_details"] = scan_result["details"]

        # ── Network Rule 3: DNS Tunnel Detection ──
        # Long, high-entropy DNS queries with many subdomain labels indicate
        # data being smuggled through DNS (e.g., iodine, dnscat2).
        if action in ("dns_query", "dns", "dns_request"):
            query_name = event.get("query_name") or event.get("dns_query", "")
            if not query_name:
                dns_match = re.search(r"query:\s*(\S+)", raw_log, re.IGNORECASE)
                if dns_match:
                    query_name = dns_match.group(1)

            if query_name:
                src_ip = ip or event.get("src_ip", "")
                tunnel_result = _detect_dns_tunnel(
                    query_name=query_name,
                    src_ip=src_ip,
                    timestamp=timestamp,
                    dns_tracker=dns_query_tracker,
                )
                if tunnel_result:
                    event["is_suspicious"] = 1
                    event["severity"] = tunnel_result["severity"]
                    event["detection_rule"] = "dns_tunnel"
                    event["pipeline"] = "network"
                    event["confidence"] = tunnel_result["confidence"]
                    event["mitre_tactic"] = "Command and Control"
                    event["mitre_technique"] = "T1071.004 - DNS"
                    event["detection_details"] = tunnel_result["details"]

        # ── Network Rule 4: Data Exfiltration Detection ──
        # Large cumulative outbound transfers to external IPs indicate
        # data theft (staging + exfil over C2, HTTP, or custom protocol).
        if action in ("connection", "outbound_connection", "network_accept", "data_transfer"):
            bytes_sent = event.get("bytes_sent") or event.get("bytes_out", 0)
            if not bytes_sent:
                bytes_match = re.search(r"LEN=(\d+)", raw_log)
                if bytes_match:
                    bytes_sent = int(bytes_match.group(1))

            dst_ip = event.get("dst_ip")
            if not dst_ip:
                dst_match = re.search(r"DST=(\d+\.\d+\.\d+\.\d+)", raw_log)
                if dst_match:
                    dst_ip = dst_match.group(1)

            src_ip = ip or event.get("src_ip", "unknown")

            if dst_ip and bytes_sent:
                try:
                    bytes_val = int(bytes_sent)
                except (ValueError, TypeError):
                    bytes_val = 0

                if bytes_val > 0:
                    exfil_result = _detect_data_exfiltration(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        bytes_sent=bytes_val,
                        timestamp=timestamp,
                        exfil_tracker=exfil_tracker,
                    )
                    if exfil_result:
                        event["is_suspicious"] = 1
                        event["severity"] = exfil_result["severity"]
                        event["detection_rule"] = "data_exfiltration"
                        event["pipeline"] = "network"
                        event["confidence"] = exfil_result["confidence"]
                        event["mitre_tactic"] = "Exfiltration"
                        event["mitre_technique"] = "T1041 - Exfiltration Over C2 Channel"
                        event["detection_details"] = exfil_result["details"]

    return events


def calculate_risk_score(events: List[Dict]) -> Tuple[float, str]:
    """Calculate overall risk score (0-100) and risk level."""
    if not events:
        return 0.0, "low"

    severity_weights = {"low": 1, "medium": 3, "high": 7, "critical": 15}
    total_score = 0
    suspicious_count = 0

    for event in events:
        if event.get("is_suspicious"):
            suspicious_count += 1
            total_score += severity_weights.get(event.get("severity", "low"), 1)

    # Normalize: max reasonable score = 100
    max_possible = len(events) * 15
    normalized = min(100, (total_score / max(max_possible, 1)) * 100 * 5)

    # Boost score based on attack chain indicators
    unique_rules = set(e.get("detection_rule") for e in events if e.get("detection_rule"))
    chain_bonus = len(unique_rules) * 5
    normalized = min(100, normalized + chain_bonus)

    # Boost for network pipeline detections (high-value signals)
    network_detections = set(
        e.get("detection_rule") for e in events
        if e.get("pipeline") == "network" and e.get("detection_rule")
    )
    network_bonus = len(network_detections) * 8
    normalized = min(100, normalized + network_bonus)

    if normalized >= 75:
        level = "critical"
    elif normalized >= 50:
        level = "high"
    elif normalized >= 25:
        level = "medium"
    else:
        level = "low"

    return round(normalized, 1), level
