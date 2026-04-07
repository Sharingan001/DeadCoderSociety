#!/usr/bin/env python3
"""
SendGrid Alerter - Test & Demo Script
Sends professional security alerts with reports
LogSentinel Pro v4.0
"""

import os
import json
from dotenv import load_dotenv
from src.engines.sendgrid_alerter import SendGridEmailAlerter, SendGridConfig

# Load environment variables
load_dotenv()


def test_sendgrid_setup():
    """Test SendGrid configuration."""
    
    print("=" * 80)
    print("🔍 SENDGRID CONFIGURATION TEST")
    print("=" * 80)
    
    # Check environment variables
    api_key = os.getenv('SENDGRID_API_KEY')
    from_email = os.getenv('SENDGRID_FROM_EMAIL', 'alerts@logsentinel.com')
    from_name = os.getenv('SENDGRID_FROM_NAME', 'LogSentinel Security')
    
    print(f"\n✅ Checking configuration...")
    print(f"   API Key: {'✓ Found' if api_key else '✗ Missing'}")
    print(f"   From Email: {from_email}")
    print(f"   From Name: {from_name}")
    
    if not api_key:
        print("\n❌ ERROR: SENDGRID_API_KEY not found in environment!")
        print("   Set it with: $env:SENDGRID_API_KEY = 'your_key_here'")
        return False
    
    print("\n✅ Configuration looks good!\n")
    return True


def demo_attack_alert(alerter, recipient_email):
    """Demo: Send attack alert with report."""
    
    print("=" * 80)
    print("🚨 DEMO 1: ATTACK ALERT WITH DETAILS")
    print("=" * 80)
    
    print(f"\n📧 Sending to: {recipient_email}")
    print("   Attack: SQL Injection - Authentication Bypass")
    print("   Severity: CRITICAL")
    print("   Source: 192.168.1.50")
    print("   Status: Sending...\n")
    
    result = alerter.send_attack_alert(
        to_email=recipient_email,
        attack_name="SQL Injection - Authentication Bypass",
        severity="CRITICAL",
        description="Attacker attempted to bypass authentication using SQL injection. The attack pattern indicates malicious user input with SQL syntax to manipulate the database query.",
        remediation="Use parameterized queries/prepared statements, validate all user input, implement WAF rules, monitor for SQL injection patterns",
        source_ip="192.168.1.50",
        log_sample="SELECT * FROM users WHERE username='admin'-- AND password='anything'",
        cve_ids=["CVE-2019-9193", "CVE-2020-0001"],
        confidence=0.95
    )
    
    if result['success']:
        print(f"   ✅ Email sent successfully!")
        print(f"   Status Code: {result['status_code']}")
        return True
    else:
        print(f"   ❌ Failed to send email")
        print(f"   Error: {result['error']}")
        return False


def demo_anomaly_alert(alerter, recipient_email):
    """Demo: Send anomaly detection alert."""
    
    print("\n" + "=" * 80)
    print("⚠️  DEMO 2: ANOMALY DETECTION ALERT")
    print("=" * 80)
    
    print(f"\n📧 Sending to: {recipient_email}")
    print("   Metric: Login Attempts")
    print("   Current: 150 attempts")
    print("   Baseline: 10 attempts")
    print("   Severity: HIGH")
    print("   Status: Sending...\n")
    
    result = alerter.send_anomaly_alert(
        to_email=recipient_email,
        metric_name="Login_Attempts",
        current_value=150,
        baseline_value=10,
        anomaly_score=87.5,
        severity="HIGH",
        explanation="Detected 150 login attempts in the last 5 minutes, which is 1400% higher than the 10-attempt baseline. This indicates a possible brute force attack. Multiple failed authentications detected from source IP 203.0.113.42. Recommend immediate investigation and IP blocking."
    )
    
    if result['success']:
        print(f"   ✅ Email sent successfully!")
        print(f"   Status Code: {result['status_code']}")
        return True
    else:
        print(f"   ❌ Failed to send email")
        print(f"   Error: {result['error']}")
        return False


def demo_security_report(alerter, recipient_email):
    """Demo: Send comprehensive security report."""
    
    print("\n" + "=" * 80)
    print("📊 DEMO 3: SECURITY REPORT WITH STATISTICS")
    print("=" * 80)
    
    print(f"\n📧 Sending to: {recipient_email}")
    print("   Report Type: Daily Security Summary")
    print("   Period: Today")
    print("   Total Logs: 125,000")
    print("   Status: Sending...\n")
    
    result = alerter.send_security_report(
        to_email=recipient_email,
        report_type="daily",
        total_logs=125000,
        total_alerts=47,
        critical_count=3,
        high_count=12,
        report_data={
            'period': 'Daily',
            'date': '2026-04-06',
            'top_threats': ['SQL Injection', 'Brute Force', 'XSS'],
            'detection_rate': 0.0376
        }
    )
    
    if result['success']:
        print(f"   ✅ Email sent successfully!")
        print(f"   Status Code: {result['status_code']}")
        return True
    else:
        print(f"   ❌ Failed to send email")
        print(f"   Error: {result['error']}")
        return False


def demo_login_alert(alerter, recipient_email):
    """Demo: Send login notification."""
    
    print("\n" + "=" * 80)
    print("✅ DEMO 4: LOGIN NOTIFICATION")
    print("=" * 80)
    
    print(f"\n📧 Sending to: {recipient_email}")
    print("   User: john_doe")
    print("   Form: Admin Portal")
    print("   IP: 192.168.1.100")
    print("   Status: Sending...\n")
    
    result = alerter.send_login_alert(
        to_email=recipient_email,
        username="john_doe",
        form_name="Admin Portal",
        ip_address="192.168.1.100",
        location="New York, USA",
        device="Chrome on Windows 10"
    )
    
    if result['success']:
        print(f"   ✅ Email sent successfully!")
        print(f"   Status Code: {result['status_code']}")
        return True
    else:
        print(f"   ❌ Failed to send email")
        print(f"   Error: {result['error']}")
        return False


def show_alert_history(alerter):
    """Show all sent alerts."""
    
    print("\n" + "=" * 80)
    print("📋 EMAIL SEND HISTORY")
    print("=" * 80)
    
    history = alerter.get_history()
    
    if not history:
        print("\nNo emails sent yet.")
        return
    
    print(f"\nTotal Emails Sent: {len(history)}\n")
    
    for i, alert in enumerate(history, 1):
        status = "✅ SUCCESS" if alert['success'] else "❌ FAILED"
        print(f"{i}. {status}")
        print(f"   To: {alert['to_email']}")
        print(f"   Time: {alert['timestamp']}")
        if alert.get('status_code'):
            print(f"   Status Code: {alert['status_code']}")
        if alert.get('error'):
            print(f"   Error: {alert['error']}")
        print()


def main():
    """Run all tests."""
    
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 78 + "║")
    print("║" + "  🚀 SENDGRID EMAIL ALERTER - TEST & DEMO".center(78) + "║")
    print("║" + "  LogSentinel Pro v4.0".center(78) + "║")
    print("║" + " " * 78 + "║")
    print("╚" + "=" * 78 + "╝")
    
    # Step 1: Test configuration
    if not test_sendgrid_setup():
        print("\n❌ Configuration test failed. Please setup environment variables first.")
        print("\nQuick Setup:")
        print("  1. Set API Key: $env:SENDGRID_API_KEY = 'your_key_here'")
        print("  2. Run this script again")
        return
    
    # Step 2: Initialize alerter
    try:
        config = SendGridConfig(
            api_key=os.getenv('SENDGRID_API_KEY'),
            from_email=os.getenv('SENDGRID_FROM_EMAIL', 'alerts@logsentinel.com'),
            from_name=os.getenv('SENDGRID_FROM_NAME', 'LogSentinel Security')
        )
        alerter = SendGridEmailAlerter(config)
        print("   ✅ Alerter initialized successfully!")
    except Exception as e:
        print(f"   ❌ Failed to initialize alerter: {e}")
        return
    
    # Step 3: Run demos
    recipient = "tuskydv@gmail.com"  # Your recipient email
    
    results = {
        'attack_alert': demo_attack_alert(alerter, recipient),
        'anomaly_alert': demo_anomaly_alert(alerter, recipient),
        'security_report': demo_security_report(alerter, recipient),
        'login_alert': demo_login_alert(alerter, recipient)
    }
    
    # Step 4: Show history
    show_alert_history(alerter)
    
    # Step 5: Final summary
    print("=" * 80)
    print("📊 TEST SUMMARY")
    print("=" * 80)
    
    total = len(results)
    successful = sum(1 for v in results.values() if v)
    
    print(f"\nTotal Demos Run: {total}")
    print(f"Successful: {successful}")
    print(f"Failed: {total - successful}")
    
    if successful == total:
        print("\n✅ ALL TESTS PASSED!")
        print("\n🎉 SendGrid alerting is working perfectly!")
        print("\nNext Steps:")
        print("1. Check your email inbox at tuskydv@gmail.com")
        print("2. You should receive 4 different alert types")
        print("3. Review the professional formatting")
        print("4. Integrate into your LogSentinel system")
    else:
        print(f"\n⚠️  Some tests failed. Check errors above.")
    
    print("\n" + "=" * 80)
    print("Documentation: See SENDGRID_ALERTER_SETUP.md for details")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
