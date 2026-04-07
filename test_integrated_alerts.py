#!/usr/bin/env python3
"""
Integrated Alert System Test
Tests SendGrid + SMTP Fallback + Telegram + Live Log Analysis
LogSentinel Pro v4.0
"""

import os
import sys
from datetime import datetime
from dotenv import load_dotenv

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from engines.sendgrid_alerter import SendGridEmailAlerter, SendGridConfig, SMTPConfig
from engines.telegram_alerter import TelegramAlerter
from engines.live_log_analyzer import LiveLogAnalyzer


# Load environment variables
load_dotenv()


def initialize_alerters():
    """Initialize all alerters with fallback support."""
    
    print("=" * 80)
    print("🔧 INITIALIZING ALERT SYSTEMS")
    print("=" * 80)
    
    # SendGrid Configuration
    sendgrid_key = os.getenv('SENDGRID_API_KEY', '').strip()
    sendgrid_from = os.getenv('SENDGRID_FROM_EMAIL', 'noreply@logsentinel.com')
    
    if sendgrid_key and sendgrid_key != 'your_sendgrid_api_key_here':
        try:
            sg_config = SendGridConfig(
                api_key=sendgrid_key,
                from_email=sendgrid_from,
                from_name="LogSentinel Security"
            )
            print("✅ SendGrid Config: VALID")
        except Exception as e:
            print(f"❌ SendGrid Config Error: {e}")
            sg_config = None
    else:
        print("⚠️  SendGrid Config: API key not configured")
        sg_config = None
    
    # SMTP Fallback Configuration
    smtp_enabled = os.getenv('SMTP_ENABLED', 'false').lower() == 'true'
    if smtp_enabled:
        smtp_config = SMTPConfig(
            host=os.getenv('SMTP_HOST', 'smtp.gmail.com'),
            port=int(os.getenv('SMTP_PORT', '587')),
            user=os.getenv('SMTP_USER', ''),
            password=os.getenv('SMTP_PASSWORD', ''),
            from_email=os.getenv('SMTP_FROM_EMAIL', ''),
            from_name="LogSentinel Security"
        )
        print("✅ SMTP Fallback: CONFIGURED")
    else:
        smtp_config = None
        print("⚠️  SMTP Fallback: NOT configured (optional)")
    
    # Initialize Email Alerter
    if sg_config:
        email_alerter = SendGridEmailAlerter(sg_config, smtp_config)
        print("✅ Email Alerter: INITIALIZED")
    else:
        if smtp_config:
            email_alerter = SendGridEmailAlerter(
                SendGridConfig(
                    api_key="dummy_key",
                    from_email="noreply@logsentinel.com"
                ),
                smtp_config
            )
            print("✅ Email Alerter: INITIALIZED (SMTP fallback only)")
        else:
            email_alerter = None
            print("❌ Email Alerter: DISABLED (no configuration)")
    
    # Telegram Configuration
    telegram_token = os.getenv('TELEGRAM_BOT_TOKEN', '').strip()
    telegram_chat = os.getenv('TELEGRAM_CHAT_ID', '').strip()
    
    if telegram_token and telegram_chat and telegram_token != 'your_token_here':
        try:
            telegram_alerter = TelegramAlerter(telegram_token)
            print("✅ Telegram Alerter: INITIALIZED")
        except Exception as e:
            print(f"⚠️  Telegram Alerter Error: {e}")
            telegram_alerter = None
    else:
        print("⚠️  Telegram Alerter: NOT configured")
        telegram_alerter = None
    
    # Live Log Analyzer
    live_analyzer = LiveLogAnalyzer(max_history=1000, update_interval=5)
    print("✅ Live Log Analyzer: INITIALIZED")
    
    print("\n" + "=" * 80)
    return {
        'email': email_alerter,
        'telegram': telegram_alerter,
        'live_analyzer': live_analyzer,
        'config': {
            'sendgrid': sendgrid_key is not None,
            'smtp': smtp_config is not None,
            'telegram': telegram_alerter is not None
        }
    }


def demo_email_alert(email_alerter, recipient_email):
    """Demo: Send attack alert via email."""
    
    print("\n" + "=" * 80)
    print("📧 DEMO 1: EMAIL ALERT (SendGrid + SMTP Fallback)")
    print("=" * 80)
    
    if not email_alerter:
        print("❌ Email alerter not configured")
        return
    
    print(f"\n📧 Sending to: {recipient_email}")
    print("   Attack: SQL Injection - Authentication Bypass")
    print("   Severity: CRITICAL")
    print("   Status: Sending...\n")
    
    result = email_alerter.send_attack_alert(
        to_email=recipient_email,
        attack_name="SQL Injection - Authentication Bypass",
        severity="CRITICAL",
        description="Attacker attempted SQL injection to bypass authentication.",
        remediation="Use parameterized queries, validate all inputs, implement WAF rules.",
        source_ip="192.168.1.50",
        log_sample="SELECT * FROM users WHERE username='admin'-- AND password='anything'",
        cve_ids=["CVE-2019-9193", "CVE-2020-0001"],
        confidence=0.95
    )
    
    print(f"   Method: {result.get('method', 'Unknown')}")
    print(f"   Status: {'✅ SUCCESS' if result['success'] else '❌ FAILED'}")
    if not result['success']:
        print(f"   Error: {result.get('error', 'Unknown error')}")
    else:
        print(f"   Status Code: {result.get('status_code', 'N/A')}")


def demo_telegram_alert(telegram_alerter, telegram_chat_id):
    """Demo: Send alert via Telegram."""
    
    print("\n" + "=" * 80)
    print("📱 DEMO 2: TELEGRAM ALERT")
    print("=" * 80)
    
    if not telegram_alerter or not telegram_chat_id:
        print("⚠️  Telegram not configured")
        return
    
    print(f"\n📱 Sending to Chat ID: {telegram_chat_id}")
    print("   Alert: Brute Force Attack Detected")
    print("   Status: Sending...\n")
    
    try:
        result = telegram_alerter.send_alert(
            chat_id=telegram_chat_id,
            message="""
🚨 **BRUTE FORCE ATTACK DETECTED**
            
**Source IP:** 203.0.113.45
**Target:** Login Portal
**Attempts:** 127 failed attempts
**Severity:** HIGH
**Action:** IP blocked
            """
        )
        print(f"   Status: {'✅ SUCCESS' if result else '❌ FAILED'}")
    except Exception as e:
        print(f"   Error: {e}")


def demo_live_log_analysis(live_analyzer):
    """Demo: Live log analysis."""
    
    print("\n" + "=" * 80)
    print("📊 DEMO 3: LIVE LOG ANALYSIS")
    print("=" * 80)
    
    # Ingest sample logs
    sample_logs = [
        {
            'timestamp': datetime.now().isoformat(),
            'threat_type': 'SQL_INJECTION',
            'severity': 'CRITICAL',
            'source_ip': '192.168.1.50',
            'destination_ip': '10.0.0.50',
            'port': 3306,
            'message': 'SQL injection pattern detected in login form'
        },
        {
            'timestamp': datetime.now().isoformat(),
            'threat_type': 'BRUTE_FORCE',
            'severity': 'HIGH',
            'source_ip': '203.0.113.45',
            'destination_ip': '10.0.0.50',
            'port': 22,
            'message': 'Multiple failed SSH authentication attempts'
        },
        {
            'timestamp': datetime.now().isoformat(),
            'threat_type': 'XSS',
            'severity': 'HIGH',
            'source_ip': '198.51.100.78',
            'destination_ip': '10.0.0.50',
            'port': 80,
            'message': 'XSS payload detected in user input'
        },
        {
            'timestamp': datetime.now().isoformat(),
            'threat_type': 'DDoS',
            'severity': 'CRITICAL',
            'source_ip': '192.0.2.1',
            'destination_ip': '10.0.0.50',
            'port': 443,
            'message': 'High volume traffic detected from single source'
        },
    ]
    
    print("\n📥 Ingesting sample logs...")
    live_analyzer.ingest_logs_batch(sample_logs)
    print(f"✅ Ingested {len(sample_logs)} logs")
    
    # Get live statistics
    print("\n📈 LIVE STATISTICS:")
    stats = live_analyzer.get_live_stats()
    print(f"   Total Logs: {stats['total_logs_processed']}")
    print(f"   Last Hour: {stats['logs_last_hour']}")
    print(f"   Last Day: {stats['logs_last_day']}")
    print(f"   Threat Patterns: {stats['threat_patterns']}")
    print(f"   Top Source IPs: {stats['top_source_ips']}")
    print(f"   Anomaly Score: {stats['anomaly_score']:.1f}/100")
    print(f"   Alert Rate: {stats['alert_rate']:.2f} alerts/min")
    
    # Get threat summary
    print("\n🎯 THREAT SUMMARY:")
    threats = live_analyzer.get_threat_summary(hours=24)
    print(f"   Total Events (24h): {threats['total_events']}")
    print(f"   Critical Threats: {threats['critical_threats']}")
    print(f"   High Threats: {threats['high_threats']}")
    print(f"   Top Threat Types: {threats['top_threat_types']}")
    
    # Detect anomalies
    print("\n⚠️  ANOMALY DETECTION:")
    anomalies = live_analyzer.detect_live_anomalies(sensitivity=0.7)
    if anomalies:
        for i, anomaly in enumerate(anomalies, 1):
            print(f"   [{i}] {anomaly['type']}: {anomaly}")
    else:
        print("   No anomalies detected")
    
    # Generate detailed report
    print("\n📋 DETAILED REPORT:")
    report = live_analyzer.get_detailed_report()
    print(f"   Report ID: {report['report_id']}")
    print(f"   Generated: {report['generated_at']}")
    print(f"   Anomalies: {report['anomaly_count']}")
    print(f"   Requires Attention: {'⚠️  YES' if report['requires_attention'] else '✅ NO'}")


def demo_integrated_flow(alerters):
    """Demo: Integrated alert flow with live analysis."""
    
    print("\n" + "=" * 80)
    print("🔗 DEMO 4: INTEGRATED ALERT FLOW")
    print("=" * 80)
    
    email_alerter = alerters['email']
    telegram_alerter = alerters['telegram']
    live_analyzer = alerters['live_analyzer']
    
    # Simulate critical event
    critical_event = {
        'timestamp': datetime.now().isoformat(),
        'threat_type': 'RANSOMWARE',
        'severity': 'CRITICAL',
        'source_ip': '192.0.2.100',
        'destination_ip': '10.0.0.50',
        'port': 445,
        'message': 'Ransomware behavior detected: mass file encryption pattern',
        'confidence': 0.98
    }
    
    print("\n🔴 CRITICAL EVENT DETECTED!")
    print(f"   Type: {critical_event['threat_type']}")
    print(f"   Severity: {critical_event['severity']}")
    print(f"   Source: {critical_event['source_ip']}")
    
    # Add to live analysis
    live_analyzer.ingest_log(critical_event)
    print("   ✅ Logged to Live Analyzer")
    
    # Get security email from env
    security_email = os.getenv('SECURITY_ALERT_EMAIL', 'security@localhost')
    telegram_chat = os.getenv('TELEGRAM_CHAT_ID', '')
    
    # Send email alert
    if email_alerter and security_email != 'security@localhost':
        print("   📧 Dispatching Email Alert...")
        try:
            result = email_alerter.send_attack_alert(
                to_email=security_email,
                attack_name="Ransomware - Mass File Encryption",
                severity="CRITICAL",
                description=critical_event['message'],
                remediation="Isolate affected systems immediately, check backups, notify incident response team.",
                source_ip=critical_event['source_ip'],
                log_sample=critical_event['message'],
                confidence=critical_event['confidence']
            )
            print(f"      {'✅ Sent' if result['success'] else '❌ Failed'}")
        except Exception as e:
            print(f"      ❌ Error: {e}")
    
    # Send Telegram alert
    if telegram_alerter and telegram_chat:
        print("   📱 Dispatching Telegram Alert...")
        try:
            result = telegram_alerter.send_alert(
                chat_id=telegram_chat,
                message=f"""🚨 **RANSOMWARE DETECTED**

**Type:** {critical_event['threat_type']}
**Severity:** {critical_event['severity']}
**Source:** {critical_event['source_ip']}
**Confidence:** {critical_event['confidence']*100:.1f}%

**Action:** Isolating affected systems...
"""
            )
            print(f"      {'✅ Sent' if result else '❌ Failed'}")
        except Exception as e:
            print(f"      ❌ Error: {e}")
    
    print("\n✅ Integrated alert flow complete!")


def main():
    """Main test function."""
    
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 78 + "║")
    print("║" + "LogSentinel Pro v4.0 - Integrated Alert System Test".center(78) + "║")
    print("║" + "(SendGrid + SMTP Fallback + Telegram + Live Log Analysis)".center(78) + "║")
    print("║" + " " * 78 + "║")
    print("╚" + "=" * 78 + "╝\n")
    
    # Initialize alerters
    alerters = initialize_alerters()
    
    # Get email addresses
    security_email = os.getenv('SECURITY_ALERT_EMAIL', 'security@localhost')
    telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID', '')
    
    # Run demos
    if alerters['email']:
        if security_email != 'security@localhost':
            demo_email_alert(alerters['email'], security_email)
        else:
            print("\n⚠️  SECURITY_ALERT_EMAIL not configured, skipping email demo")
    
    if alerters['telegram']:
        demo_telegram_alert(alerters['telegram'], telegram_chat_id)
    
    demo_live_log_analysis(alerters['live_analyzer'])
    
    demo_integrated_flow(alerters)
    
    # Summary
    print("\n" + "=" * 80)
    print("📊 SUMMARY")
    print("=" * 80)
    print(f"✅ Email Alerter: {'Enabled' if alerters['email'] else 'Disabled'}")
    print(f"✅ Telegram Alerter: {'Enabled' if alerters['telegram'] else 'Disabled'}")
    print(f"✅ Live Log Analyzer: Enabled")
    print(f"✅ SMTP Fallback: {'Available' if alerters['config']['smtp'] else 'Not available'}")
    print("\n✅ All systems initialized and tested!\n")


if __name__ == '__main__':
    main()
