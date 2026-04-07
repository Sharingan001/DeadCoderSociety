#!/usr/bin/env python3
"""
Global Attack Recognition - Integration & Demo
Shows how to use the worldwide attack recognizer with email alerts
LogSentinel Pro v4.0
"""

from src.engines.global_attack_recognizer import GlobalAttackRecognitionEngine, identify_attack
from src.engines.simple_email_alerter import SimpleEmailAlerter, EmailConfig
from src.engines.log_classifier import LogClassifier
from datetime import datetime
import json


def demo_attack_recognition():
    """Demo: Recognize real-world attacks."""
    
    print("=" * 80)
    print("🌍 GLOBAL ATTACK RECOGNITION ENGINE - DEMONSTRATION")
    print("=" * 80)
    
    # Initialize systems
    recognizer = GlobalAttackRecognitionEngine()
    classifier = LogClassifier()
    alerter = SimpleEmailAlerter(EmailConfig(
        email="security@company.com",
        password="app_password"
    ))
    
    # Real-world log examples
    test_logs = [
        {
            'entry': "SELECT * FROM users WHERE username='admin'--",
            'source': '192.168.1.50',
            'user': 'unknown',
            'timestamp': datetime.now().isoformat()
        },
        {
            'entry': '<script>alert("XSS Vulnerability")</script>',
            'source': '203.0.113.42',
            'user': 'attacker',
            'timestamp': datetime.now().isoformat()
        },
        {
            'entry': 'Failed password for root from 10.0.0.100 port 22 ssh',
            'source': '10.0.0.100',
            'user': 'root',
            'timestamp': datetime.now().isoformat()
        },
        {
            'entry': 'rm -rf /; chmod 777 /etc/passwd',
            'source': '172.16.0.50',
            'user': 'www-data',
            'timestamp': datetime.now().isoformat()
        },
        {
            'entry': 'UNION SELECT password, credit_card FROM payment_table',
            'source': '192.0.2.10',
            'user': 'unknown',
            'timestamp': datetime.now().isoformat()
        },
    ]
    
    print(f"\n📊 Processing {len(test_logs)} log entries...\n")
    
    for i, log in enumerate(test_logs, 1):
        print(f"\n{'─' * 80}")
        print(f"📝 Log #{i}: {log['entry'][:60]}...")
        print(f"   Source IP: {log['source']} | User: {log['user']}")
        
        # Classify log
        classification = classifier.classify_log(log['entry'])
        print(f"   Classification: {classification['log_type']} (Risk: {classification['risk_level']})")
        
        # Recognize attack
        attacks = recognizer.recognize_attack(log['entry'], context={
            'ip': log['source'],
            'user': log['user'],
            'timestamp': log['timestamp']
        })
        
        if attacks:
            print(f"\n   🚨 ATTACK DETECTED!")
            for attack in attacks:
                print(f"\n      Attack ID: {attack['attack_id']}")
                print(f"      Name: {attack['attack_name']}")
                print(f"      Category: {attack['category']}")
                print(f"      Severity: {attack['severity']}")
                print(f"      Confidence: {attack['confidence']*100:.0f}%")
                
                if attack['cve_ids']:
                    print(f"      CVE IDs: {', '.join(attack['cve_ids'])}")
                
                if attack['mitre_techniques']:
                    print(f"      MITRE: {', '.join(attack['mitre_techniques'])}")
                
                print(f"      Description: {attack['description']}")
                print(f"      Remediation: {attack['remediation']}")
        else:
            print("   ✅ No attack detected")
    
    print(f"\n\n{'=' * 80}")
    print("📊 ATTACK STATISTICS")
    print("=" * 80)
    stats = recognizer.get_statistics()
    print(f"Total Detections: {stats['total_detections']}")
    print(f"By Category: {stats['by_category']}")
    print(f"By Severity: {stats['by_severity']}")
    print(f"Database Size: {stats['total_signatures']} signatures")


def demo_intelligence_report():
    """Demo: Generate threat intelligence report."""
    
    print("\n\n" + "=" * 80)
    print("🔍 THREAT INTELLIGENCE REPORT")
    print("=" * 80)
    
    recognizer = GlobalAttackRecognitionEngine()
    report = recognizer.get_attack_intelligence_report()
    
    print(f"\nReport Generated: {report['timestamp']}")
    print(f"Total Signatures: {report['total_attack_signatures']}")
    print(f"\nAttack Categories Covered:")
    for cat in report['attack_categories']:
        print(f"  • {cat}")
    
    print(f"\nCritical Severity Attacks:")
    for attack in report['critical_attacks']:
        print(f"  🔴 {attack}")
    
    print(f"\nCoverage:")
    for key, value in report['coverage'].items():
        print(f"  • {key.replace('_', ' ').title()}: {value}")


def demo_simple_one_liner():
    """Demo: One-liner attack detection."""
    
    print("\n\n" + "=" * 80)
    print("⚡ ONE-LINER ATTACK DETECTION")
    print("=" * 80)
    
    test_cases = [
        "SELECT * FROM users",
        "'; DROP TABLE users;--",
        "<script>alert('xss')</script>",
        "Normal system event",
        "user root logged in",
    ]
    
    for log_entry in test_cases:
        is_attack, details = identify_attack(log_entry)
        status = "🚨 ATTACK" if is_attack else "✅ SAFE"
        print(f"\n{status}: {log_entry[:50]}")
        if is_attack:
            print(f"   → {details[0]['attack_name']} ({details[0]['severity']})")


def demo_email_alerting():
    """Demo: Email alerts on attack detection."""
    
    print("\n\n" + "=" * 80)
    print("📧 EMAIL ALERTING INTEGRATION")
    print("=" * 80)
    
    # Setup
    recognizer = GlobalAttackRecognitionEngine()
    alerter = SimpleEmailAlerter(EmailConfig(
        email="security@company.com",
        password="app_password"
    ))
    
    suspicious_log = "SELECT * FROM users WHERE id=1 UNION SELECT username,password FROM admin"
    
    # Detect attack
    attacks = recognizer.recognize_attack(suspicious_log)
    
    if attacks:
        attack = attacks[0]
        
        print(f"\n🚨 Attack Detected: {attack['attack_name']}")
        print(f"Severity: {attack['severity']}")
        
        # In real system, this would send email:
        # alerter.send_admin_alert(
        #     recipient="security@company.com",
        #     title=attack['attack_name'],
        #     attack_type=attack['category'],
        #     severity=attack['severity'],
        #     details=json.dumps(attack, indent=2)
        # )
        
        print("\n✉️  Email would be sent with:")
        print(f"   To: security@company.com")
        print(f"   Subject: 🚨 CRITICAL: {attack['attack_name']}")
        print(f"   Body: {attack['description']}")
        print(f"   Actions: {attack['remediation']}")


def demo_cve_lookup():
    """Demo: Look up attacks by CVE ID."""
    
    print("\n\n" + "=" * 80)
    print("🔐 CVE LOOKUP")
    print("=" * 80)
    
    recognizer = GlobalAttackRecognitionEngine()
    
    cve_ids = [
        'CVE-2017-0144',  # EternalBlue
        'CVE-2014-6271',  # Shellshock
        'CVE-2021-3156',  # Sudo SameEdit
    ]
    
    for cve in cve_ids:
        attack = recognizer.get_attack_by_cve(cve)
        if attack:
            print(f"\n{cve}:")
            print(f"  Name: {attack['attack_name']}")
            print(f"  Severity: {attack['severity']}")
            print(f"  Description: {attack['description']}")
            print(f"  Remediation: {attack['remediation']}")


def demo_mitre_lookup():
    """Demo: Look up attacks by MITRE technique."""
    
    print("\n\n" + "=" * 80)
    print("🎯 MITRE ATT&CK LOOKUP")
    print("=" * 80)
    
    recognizer = GlobalAttackRecognitionEngine()
    
    techniques = ['T1110', 'T1190', 'T1486']  # Brute Force, Exploit, Encryption
    
    for tech in techniques:
        attacks = recognizer.get_attack_by_mitre(tech)
        print(f"\nTechnique {tech}:")
        for attack in attacks:
            print(f"  • {attack['attack_name']} ({attack['severity']})")


def complete_workflow_example():
    """Demo: Complete log processing workflow."""
    
    print("\n\n" + "=" * 80)
    print("🔄 COMPLETE WORKFLOW: LOG PROCESSING → ATTACK RECOGNITION → ALERTING")
    print("=" * 80)
    
    # Initialize all systems
    recognizer = GlobalAttackRecognitionEngine()
    classifier = LogClassifier()
    alerter = SimpleEmailAlerter(EmailConfig(
        email="security@company.com",
        password="app_password"
    ))
    
    # Sample attack log
    suspicious_log = "SQL Error: SELECT * FROM users WHERE id='1' OR '1'='1'; //allowed"
    source_ip = "203.0.113.100"
    source_user = "web_app"
    
    print(f"\n📥 Incoming Log:")
    print(f"   Content: {suspicious_log[:70]}...")
    print(f"   Source: {source_ip}")
    print(f"   User: {source_user}\n")
    
    # Step 1: Classify
    print("Step 1️⃣  Classify Log")
    classification = classifier.classify_log(suspicious_log)
    print(f"   Type: {classification['log_type']}")
    print(f"   Risk: {classification['risk_level']}")
    
    # Step 2: Recognize Attack
    print("\nStep 2️⃣  Recognize Attack Pattern")
    attacks = recognizer.recognize_attack(suspicious_log, context={
        'ip': source_ip,
        'user': source_user
    })
    
    if attacks:
        attack = attacks[0]
        print(f"   Found: {attack['attack_name']}")
        print(f"   Severity: {attack['severity']}")
        
        # Step 3: Alert
        print("\nStep 3️⃣  Send Alert")
        print(f"   ✉️  Would email to: security@company.com")
        print(f"   Subject: 🚨 {attack['severity']}: {attack['attack_name']}")
        print(f"   Recommended: {attack['remediation']}")
    
    print("\n✅ Workflow Complete\n")


if __name__ == "__main__":
    # Run all demos
    demo_attack_recognition()
    demo_intelligence_report()
    demo_simple_one_liner()
    demo_email_alerting()
    demo_cve_lookup()
    demo_mitre_lookup()
    complete_workflow_example()
    
    print("\n" + "=" * 80)
    print("✨ All demos complete!")
    print("=" * 80)
