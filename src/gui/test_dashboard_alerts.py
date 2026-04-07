"""
Test Script - Send Demo Attacks to Premium Dashboard
"""

import requests
import json
import time
from datetime import datetime, timedelta

API_URL = "http://localhost:5000/api/alert/attack"

demo_attacks = [
    {
        "type": "BRUTE_FORCE",
        "severity": "CRITICAL",
        "source_ip": "192.0.2.100",
        "description": "SSH brute force attack - 25 failed attempts in 30 seconds",
        "port": 22,
        "attempts": 25,
        "protocol": "SSH"
    },
    {
        "type": "PORT_SCAN",
        "severity": "HIGH",
        "source_ip": "203.0.113.45",
        "description": "Network reconnaissance - 256 ports scanned",
        "scan_count": 256,
        "protocol": "TCP"
    },
    {
        "type": "SQL_INJECTION",
        "severity": "CRITICAL",
        "source_ip": "198.51.100.78",
        "description": "SQL injection attempt in login form - UNION-based detection",
        "port": 443,
        "payload": "admin' OR '1'='1",
        "endpoint": "/api/login"
    },
    {
        "type": "DDOS",
        "severity": "HIGH",
        "source_ip": "198.51.100.120",
        "description": "DDoS traffic spike - 10x normal rate detected",
        "packets_per_sec": 50000,
        "threshold_normal": 5000
    },
    {
        "type": "UNAUTHORIZED_ACCESS",
        "severity": "MEDIUM",
        "source_ip": "203.0.113.88",
        "description": "Privilege escalation attempt - sudo execution blocked",
        "user": "www-data",
        "command": "sudo whoami"
    },
    {
        "type": "MALWARE",
        "severity": "CRITICAL",
        "source_ip": "192.0.2.50",
        "description": "Suspicious executable detected - hash matches known malware",
        "file": "/tmp/suspicious.exe",
        "hash": "a1b2c3d4e5f6..."
    }
]


def send_attack(attack):
    """Send single attack to dashboard"""
    attack['timestamp'] = datetime.now().isoformat()
    
    try:
        response = requests.post(API_URL, json=attack, timeout=5)
        if response.status_code == 200:
            print(f"✅ {attack['type']:20} [{attack['severity']:8}] → {attack['source_ip']}")
            return True
        else:
            print(f"❌ {attack['type']:20} - Error: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"❌ Connection refused - Is dashboard server running? (python dashboard_server.py)")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def send_batch_attacks():
    """Send multiple attacks at once"""
    batch = {
        "attacks": [
            {**attack, "timestamp": datetime.now().isoformat()}
            for attack in demo_attacks[:3]
        ]
    }
    
    try:
        response = requests.post(
            "http://localhost:5000/api/alert/batch",
            json=batch,
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Batch sent: {data['processed']} attacks processed")
            return True
        else:
            print(f"❌ Batch failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Batch error: {e}")
        return False


def continuous_attacks(interval=3):
    """Send attacks continuously"""
    print("\n🚀 Starting continuous attack simulation...")
    print(f"   Sending attack every {interval} seconds")
    print("   Press Ctrl+C to stop\n")
    
    idx = 0
    try:
        while True:
            attack = demo_attacks[idx % len(demo_attacks)]
            send_attack(attack)
            idx += 1
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n\n⏹️  Attack simulation stopped")


if __name__ == "__main__":
    print("=" * 80)
    print("🎯 LogSentinel Pro - Dashboard Attack Simulator")
    print("=" * 80)
    print()
    
    # Test connection
    print("Testing connection to dashboard server...")
    print()
    
    # Send individual attacks
    print("📤 Sending individual attacks:")
    print()
    for attack in demo_attacks[:3]:
        send_attack(attack)
        time.sleep(1)
    
    print()
    print("=" * 80)
    print("\n💡 CLI Options:")
    print("   python test_dashboard_alerts.py              # Send 3 demo attacks")
    print("   python test_dashboard_alerts.py batch        # Send batch of 3 attacks")
    print("   python test_dashboard_alerts.py continuous   # Send attacks every 3 seconds")
    print("   python test_dashboard_alerts.py continuous 2 # Send attacks every 2 seconds")
    print()
    print("🎨 View Dashboard: http://localhost:5000")
    print("=" * 80)
