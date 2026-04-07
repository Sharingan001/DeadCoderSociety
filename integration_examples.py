#!/usr/bin/env python3
"""
Integration Examples - Using New Alert Systems with LogSentinel
Shows how to integrate SendGrid, SMTP Fallback, Telegram, and Live Analysis
"""

import os
import sys
from datetime import datetime
from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from engines.sendgrid_alerter import SendGridEmailAlerter, SendGridConfig, SMTPConfig
from engines.telegram_alerter import TelegramAlerter
from engines.live_log_analyzer import LiveLogAnalyzer
from engines.alert_manager import AlertManager


# Load env
load_dotenv()


# ============================================================================
# EXAMPLE 1: Integrate Live Analysis with Alert Manager
# ============================================================================

def example_live_analysis_integration():
    """
    Shows how to integrate the Live Log Analyzer with AlertManager
    to create an intelligent, adaptive alert system.
    """
    
    print("\n" + "=" * 80)
    print("EXAMPLE 1: Integrating Live Analysis with Alert Manager")
    print("=" * 80)
    
    # Initialize components
    alert_manager = AlertManager()
    live_analyzer = LiveLogAnalyzer()
    
    # Sample threat detections
    threats = [
        {
            'alert_id': 'ALERT_001',
            'threat_type': 'SQL_INJECTION',
            'severity': 'CRITICAL',
            'source_ip': '192.168.1.100',
            'timestamp': datetime.now().isoformat(),
            'description': 'SQL injection in login form'
        },
        {
            'alert_id': 'ALERT_002',
            'threat_type': 'BRUTE_FORCE',
            'severity': 'HIGH',
            'source_ip': '203.0.113.50',
            'timestamp': datetime.now().isoformat(),
            'description': 'Multiple failed SSH attempts'
        },
    ]
    
    print("\n[*] Processing threats through Alert Manager...")
    for threat in threats:
        # Alert Manager processes threat
        alert_manager.create_alert(threat)
        
        # Also ingest into Live Analyzer for real-time stats
        live_analyzer.ingest_log(threat)
        print(f"    ✓ Processed: {threat['threat_type']}")
    
    # Get statistics
    print("\n[*] Live Analysis Statistics:")
    stats = live_analyzer.get_live_stats()
    print(f"    Total Events: {stats['total_logs_processed']}")
    print(f"    Threat Patterns: {stats['threat_patterns']}")
    print(f"    Anomaly Score: {stats['anomaly_score']:.1f}/100")


# ============================================================================
# EXAMPLE 2: Multi-Channel Alert Dispatch (Email + Telegram)
# ============================================================================

def example_multi_channel_dispatch():
    """
    Shows how to send the same alert through multiple channels
    with automatic fallback and status tracking.
    """
    
    print("\n" + "=" * 80)
    print("EXAMPLE 2: Multi-Channel Alert Dispatch")
    print("=" * 80)
    
    # Initialize alerters
    sg_config = SendGridConfig(
        api_key=os.getenv('SENDGRID_API_KEY', ''),
        from_email=os.getenv('SENDGRID_FROM_EMAIL', 'noreply@logsentinel.com')
    )
    
    smtp_config = SMTPConfig(
        host=os.getenv('SMTP_HOST', 'smtp.gmail.com'),
        port=int(os.getenv('SMTP_PORT', '587')),
        user=os.getenv('SMTP_USER', ''),
        password=os.getenv('SMTP_PASSWORD', ''),
        from_email=os.getenv('SMTP_FROM_EMAIL', '')
    ) if os.getenv('SMTP_ENABLED', 'false').lower() == 'true' else None
    
    email_alerter = SendGridEmailAlerter(sg_config, smtp_config)
    
    telegram_token = os.getenv('TELEGRAM_BOT_TOKEN', '')
    telegram_chat = os.getenv('TELEGRAM_CHAT_ID', '')
    telegram_alerter = TelegramAlerter(telegram_token) if telegram_token else None
    
    # Critical event
    event = {
        'name': 'Unauthorized Database Access',
        'severity': 'CRITICAL',
        'description': 'Root user accessed from unknown IP',
        'source_ip': '192.0.2.200',
        'action': 'Database access blocked'
    }
    
    print(f"\n[*] Dispatching alert for: {event['name']}")
    
    # Channel 1: Email
    print("\n    📧 Email Channel:")
    security_email = os.getenv('SECURITY_ALERT_EMAIL', 'security@localhost')
    if security_email != 'security@localhost' and email_alerter:
        try:
            result = email_alerter.send_attack_alert(
                to_email=security_email,
                attack_name=event['name'],
                severity=event['severity'],
                description=event['description'],
                remediation=f"Action: {event['action']}. Investigate source IP immediately.",
                source_ip=event['source_ip'],
                log_sample=f"Unauthorized {event['name']} from {event['source_ip']}"
            )
            if result['success']:
                print(f"       ✅ Sent via {result.get('method', 'Email')}")
            else:
                print(f"       ❌ Failed: {result.get('error', 'Unknown error')}")
        except Exception as e:
            print(f"       ❌ Error: {e}")
    else:
        print("       ⚠️  Email not configured")
    
    # Channel 2: Telegram
    print("\n    📱 Telegram Channel:")
    if telegram_alerter and telegram_chat:
        try:
            message = f"""🚨 **{event['name'].upper()}**

**Severity:** {event['severity']}
**Source IP:** {event['source_ip']}
**Description:** {event['description']}
**Action:** {event['action']}

⚠️ Immediate investigation required!
"""
            result = telegram_alerter.send_alert(telegram_chat, message)
            print(f"       ✅ Sent to Telegram" if result else "       ❌ Failed")
        except Exception as e:
            print(f"       ❌ Error: {e}")
    else:
        print("       ⚠️  Telegram not configured")


# ============================================================================
# EXAMPLE 3: Threat Pattern Analysis & Correlation
# ============================================================================

def example_threat_correlation():
    """
    Shows advanced threat analysis by correlating multiple events
    within the Live Log Analyzer.
    """
    
    print("\n" + "=" * 80)
    print("EXAMPLE 3: Threat Pattern Analysis & Correlation")
    print("=" * 80)
    
    analyzer = LiveLogAnalyzer()
    
    # Simulate attack progression
    attack_sequence = [
        {'threat_type': 'RECONNAISSANCE', 'source_ip': '10.20.30.40', 'severity': 'LOW'},
        {'threat_type': 'EXPLOITATION', 'source_ip': '10.20.30.40', 'severity': 'HIGH'},
        {'threat_type': 'LATERAL_MOVEMENT', 'source_ip': '192.168.1.10', 'severity': 'HIGH'},
        {'threat_type': 'PRIVILEGE_ESCALATION', 'source_ip': '192.168.1.10', 'severity': 'CRITICAL'},
        {'threat_type': 'DATA_EXFILTRATION', 'source_ip': '192.168.1.10', 'severity': 'CRITICAL'},
    ]
    
    print("\n[*] Simulating attack progression...")
    for i, threat in enumerate(attack_sequence, 1):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            **threat,
            'destination_ip': '10.0.0.50',
            'port': 443
        }
        analyzer.ingest_log(log_entry)
        print(f"    [{i}] {threat['threat_type']} ({threat['severity']})")
    
    # Analyze patterns
    print("\n[*] Pattern Analysis:")
    
    threats = analyzer.get_threat_summary()
    print(f"    Total Events: {threats['total_events']}")
    print(f"    Critical Threats: {threats['critical_threats']}")
    
    anomalies = analyzer.detect_live_anomalies(sensitivity=0.8)
    print(f"\n[*] Detected Anomalies:")
    for anomaly in anomalies:
        print(f"    ⚠️  {anomaly['type']}: {anomaly}")
    
    # Export for investigation
    print("\n[*] Exporting correlated events...")
    export_path = analyzer.export_logs('logs/threat_correlation_analysis.json')
    print(f"    ✓ Saved to: {export_path}")


# ============================================================================
# EXAMPLE 4: Real-Time Log Streaming Integration
# ============================================================================

def example_log_streaming():
    """
    Shows how to stream logs from a file in real-time and trigger
    alerts based on threat level.
    """
    
    print("\n" + "=" * 80)
    print("EXAMPLE 4: Real-Time Log Streaming Integration")
    print("=" * 80)
    
    analyzer = LiveLogAnalyzer()
    
    # Register callback for critical threats
    def on_critical_threat(log_entry):
        print(f"\n🚨 CRITICAL THREAT DETECTED!")
        print(f"   Type: {log_entry.get('threat_type', 'Unknown')}")
        print(f"   Source: {log_entry.get('source_ip', 'Unknown')}")
        print(f"   Severity: {log_entry.get('severity', 'Unknown')}")
    
    analyzer.add_alert_callback(on_critical_threat)
    
    # Example: Start monitoring
    log_file = 'test_threats.log'
    if os.path.exists(log_file):
        print(f"\n[*] Starting live log monitoring: {log_file}")
        print("    (In production, this would run continuously)")
        
        # Simulate file monitoring
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()[:10]  # First 10 lines
                for line in lines:
                    try:
                        import json
                        log_entry = json.loads(line)
                        analyzer.ingest_log(log_entry)
                    except:
                        pass
            
            stats = analyzer.get_live_stats()
            print(f"\n[*] Processed {stats['total_logs_processed']} logs")
            print(f"    Anomaly Score: {stats['anomaly_score']:.1f}/100")
        except FileNotFoundError:
            print(f"    ⚠️  Log file not found: {log_file}")


# ============================================================================
# EXAMPLE 5: Custom Alert Rules and Thresholds
# ============================================================================

def example_custom_alert_rules():
    """
    Shows how to implement custom alert rules based on
    real-time analytics from Live Log Analyzer.
    """
    
    print("\n" + "=" * 80)
    print("EXAMPLE 5: Custom Alert Rules & Thresholds")
    print("=" * 80)
    
    analyzer = LiveLogAnalyzer()
    
    # Sample events
    events = [
        {'threat_type': 'SQL_INJECTION', 'severity': 'CRITICAL'} for _ in range(3),
        {'threat_type': 'BRUTE_FORCE', 'severity': 'HIGH'} for _ in range(2),
        {'threat_type': 'XSS', 'severity': 'MEDIUM'} for _ in range(5),
    ]
    
    for event in events:
        analyzer.ingest_log({
            'timestamp': datetime.now().isoformat(),
            **event,
            'source_ip': '192.168.1.50',
            'destination_ip': '10.0.0.50'
        })
    
    # Custom rules
    stats = analyzer.get_live_stats()
    
    print("\n[*] Evaluating Custom Alert Rules:")
    
    # Rule 1: Critical threat count
    critical_count = stats['severity_breakdown'].get('CRITICAL', 0)
    print(f"\n    Rule 1: Critical Threat Count")
    print(f"            Current: {critical_count} | Threshold: 2")
    if critical_count >= 2:
        print(f"            ✅ ALERT TRIGGERED")
    
    # Rule 2: Anomaly score
    anomaly_score = stats['anomaly_score']
    print(f"\n    Rule 2: Overall Anomaly Score")
    print(f"            Current: {anomaly_score:.1f}/100 | Threshold: 70")
    if anomaly_score > 70:
        print(f"            ✅ ALERT TRIGGERED")
    
    # Rule 3: Multiple threat types
    threat_types = len(stats['threat_patterns'])
    print(f"\n    Rule 3: Threat Type Diversity")
    print(f"            Current: {threat_types} types | Threshold: 2")
    if threat_types >= 2:
        print(f"            ✅ ALERT TRIGGERED (Diverse threats detected)")


# ============================================================================
# Main
# ============================================================================

def main():
    """Run all examples."""
    
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 78 + "║")
    print("║" + "LogSentinel Pro - Integration Examples".center(78) + "║")
    print("║" + "Showing real-world usage patterns".center(78) + "║")
    print("║" + " " * 78 + "║")
    print("╚" + "=" * 78 + "╝")
    
    try:
        example_live_analysis_integration()
        example_multi_channel_dispatch()
        example_threat_correlation()
        example_log_streaming()
        example_custom_alert_rules()
        
        print("\n" + "=" * 80)
        print("✅ All examples completed!")
        print("=" * 80 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
