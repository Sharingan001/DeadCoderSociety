"""
Network Monitor Module
Provides real-time network connection tracking using psutil.
Includes SOAR auto-response engine (CP-003 compliant — every action is logged to blockchain).
"""
import psutil
import socket
import subprocess
from collections import Counter
from datetime import datetime, timezone
from typing import List, Dict, Optional


# ---------------------------------------------------------------------------
# Original Network Monitor functions
# ---------------------------------------------------------------------------

def get_active_connections() -> List[Dict]:
    """Get all active network connections with resolved process names."""
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            try:
                proc = psutil.Process(conn.pid) if conn.pid else None
                proc_name = proc.name() if proc else "unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = "unknown"

            local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
            remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"

            connections.append({
                "pid": conn.pid or 0,
                "process": proc_name,
                "local": local,
                "remote": remote,
                "status": conn.status,
                "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
            })
    except psutil.AccessDenied:
        pass
    return connections


def get_listening_ports() -> List[Dict]:
    """Get all listening ports."""
    listeners = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN':
                try:
                    proc = psutil.Process(conn.pid) if conn.pid else None
                    proc_name = proc.name() if proc else "unknown"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "unknown"

                listeners.append({
                    "port": conn.laddr.port,
                    "process": proc_name,
                    "pid": conn.pid or 0,
                    "address": conn.laddr.ip,
                })
    except psutil.AccessDenied:
        pass
    return listeners


def get_connection_summary() -> Dict:
    """Get summary statistics of network connections."""
    try:
        conns = psutil.net_connections(kind='inet')
        status_counts = Counter(c.status for c in conns)
        return {
            "total": len(conns),
            "established": status_counts.get("ESTABLISHED", 0),
            "listening": status_counts.get("LISTEN", 0),
            "time_wait": status_counts.get("TIME_WAIT", 0),
            "close_wait": status_counts.get("CLOSE_WAIT", 0),
        }
    except psutil.AccessDenied:
        return {"total": 0, "established": 0, "listening": 0, "time_wait": 0, "close_wait": 0}


def get_system_info() -> Dict:
    """Get comprehensive system information."""
    cpu_freq = psutil.cpu_freq()
    disk = psutil.disk_usage('/')
    net_io = psutil.net_io_counters()
    boot_time = psutil.boot_time()

    return {
        "cpu_count": psutil.cpu_count(),
        "cpu_freq_mhz": round(cpu_freq.current, 0) if cpu_freq else 0,
        "ram_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "ram_used_gb": round(psutil.virtual_memory().used / (1024**3), 2),
        "disk_total_gb": round(disk.total / (1024**3), 2),
        "disk_used_gb": round(disk.used / (1024**3), 2),
        "disk_percent": disk.percent,
        "net_sent_mb": round(net_io.bytes_sent / (1024**2), 2),
        "net_recv_mb": round(net_io.bytes_recv / (1024**2), 2),
        "boot_time": boot_time,
    }


# ---------------------------------------------------------------------------
# SOAR Auto-Response Engine
# Every action is logged to the blockchain BEFORE execution (audit-first).
# ---------------------------------------------------------------------------

class ResponseEngine:
    """SOAR auto-response engine.

    Triggered by Abhi's ML threat scores.  Every response action is
    recorded in the blockchain ledger before it is executed so the
    audit trail is always intact.

    Usage:
        from blockchain import Blockchain
        from network_monitor import ResponseEngine

        chain = Blockchain()
        engine = ResponseEngine(chain)
        engine.evaluate_threat(threat_data)
    """

    # Thresholds (matching README spec)
    THRESHOLD_BLOCK_IP = 0.9
    THRESHOLD_ISOLATE_HOST = 0.85

    def __init__(self, blockchain=None):
        """
        Args:
            blockchain: Blockchain instance for audit logging.
                        Can be set later via engine.blockchain = chain.
        """
        self.blockchain = blockchain

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate_threat(self, threat_data: Dict) -> Optional[Dict]:
        """Decide which SOAR action to take based on threat_data.

        Expected keys in threat_data:
            threat_score  (float 0-1) — from Abhi's ML ensemble
            technique     (str)       — MITRE ATT&CK ID, e.g. 'T1110'
            source_ip     (str)       — attacker IP / actor
            severity      (str)       — 'critical' | 'high' | 'medium' | 'low'
            source        (str)       — 'container_db' or other pipeline name
            session_id    (str, opt)  — session to kill on isolate
            container_id  (str, opt)  — container to quarantine
            namespace     (str, opt)  — k8s namespace for quarantine

        Returns:
            Result dict from the executed action, or None if below threshold.
        """
        score = float(threat_data.get("threat_score", 0))
        technique = threat_data.get("technique", "")
        severity = threat_data.get("severity", "").lower()
        source = threat_data.get("source", "")

        # Priority order: Block IP → Isolate Host → Quarantine Container
        if score >= self.THRESHOLD_BLOCK_IP and technique in ("T1110", "T1071"):
            return self.execute_response("block_ip", threat_data)

        if score >= self.THRESHOLD_ISOLATE_HOST and technique in ("T1078", "T1548"):
            return self.execute_response("isolate_host", threat_data)

        if severity == "critical" and source == "container_db":
            return self.execute_response("quarantine_container", threat_data)

        return None

    def execute_response(self, action: str, threat_data: Dict) -> Dict:
        """Execute a SOAR action.  Logs to blockchain FIRST, then acts.

        Args:
            action:      'block_ip' | 'isolate_host' | 'quarantine_container'
            threat_data: same dict as evaluate_threat()

        Returns:
            dict with keys: action, status, commands, blockchain_index
        """
        actor = threat_data.get("source_ip", "unknown")
        result = {"action": action, "actor": actor, "status": "pending", "commands": []}

        # 1. Record in blockchain BEFORE execution (audit-first)
        if self.blockchain is not None:
            blk = self.blockchain.add_event(
                actor=actor,
                action=f"soar_{action}",
                data={
                    "threat_score": threat_data.get("threat_score"),
                    "technique": threat_data.get("technique"),
                    "severity": threat_data.get("severity"),
                    "source": threat_data.get("source"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )
            result["blockchain_index"] = blk.index

        # 2. Execute the appropriate action
        if action == "block_ip":
            result.update(self._block_ip(actor, threat_data))
        elif action == "isolate_host":
            result.update(self._isolate_host(actor, threat_data))
        elif action == "quarantine_container":
            result.update(self._quarantine_container(threat_data))
        else:
            result["status"] = "unknown_action"

        return result

    # ------------------------------------------------------------------
    # Action 1 — Block IP / Revoke Token  (threat_score ≥ 0.9)
    # Techniques: T1110 (Brute Force), T1071 (Application Layer Protocol)
    # ------------------------------------------------------------------

    def _block_ip(self, ip: str, threat_data: Dict) -> Dict:
        """Generate iptables DROP rule and optionally revoke tokens."""
        commands = []

        # iptables rule (Linux) — generated but not auto-executed for safety
        iptables_cmd = f"iptables -I INPUT -s {ip} -j DROP"
        commands.append({"type": "iptables", "command": iptables_cmd, "executed": False})

        # Token revocation placeholder (integrate with auth service)
        token = threat_data.get("token")
        if token:
            commands.append({
                "type": "token_revoke",
                "command": f"auth-service revoke --token {token}",
                "executed": False,
            })

        print(f"[SOAR] Block IP triggered for {ip} | cmd: {iptables_cmd}")
        return {"status": "blocked", "commands": commands}

    # ------------------------------------------------------------------
    # Action 2 — Isolate Host / Kill Session  (threat_score ≥ 0.85)
    # Techniques: T1078 (Valid Accounts), T1548 (Abuse Elevation Control)
    # ------------------------------------------------------------------

    def _isolate_host(self, ip: str, threat_data: Dict) -> Dict:
        """Network isolation + session kill."""
        commands = []
        session_id = threat_data.get("session_id")

        # Block all inbound/outbound traffic except management interface
        commands.append({
            "type": "iptables_isolate",
            "command": f"iptables -I INPUT -s {ip} -j DROP && iptables -I OUTPUT -d {ip} -j DROP",
            "executed": False,
        })

        # Kill active session
        if session_id:
            commands.append({
                "type": "kill_session",
                "command": f"pkill -KILL -s {session_id}",
                "executed": False,
            })

        print(f"[SOAR] Isolate Host triggered for {ip} | session={session_id}")
        return {"status": "isolated", "commands": commands}

    # ------------------------------------------------------------------
    # Action 3 — Quarantine Container  (critical severity, container_db)
    # ------------------------------------------------------------------

    def _quarantine_container(self, threat_data: Dict) -> Dict:
        """Pause Docker container and apply K8s network policy."""
        commands = []
        container_id = threat_data.get("container_id", "unknown")
        namespace = threat_data.get("namespace", "default")

        # Docker pause
        commands.append({
            "type": "docker_pause",
            "command": f"docker pause {container_id}",
            "executed": False,
        })

        # Kubernetes network isolation via label
        commands.append({
            "type": "k8s_isolate",
            "command": (
                f"kubectl label pod {container_id} quarantine=true -n {namespace} "
                f"&& kubectl apply -f /etc/logsentinel/k8s/quarantine-netpol.yaml -n {namespace}"
            ),
            "executed": False,
        })

        print(f"[SOAR] Quarantine Container triggered | container={container_id} ns={namespace}")
        return {"status": "quarantined", "commands": commands}
