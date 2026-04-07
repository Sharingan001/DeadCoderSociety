#!/usr/bin/env python3
"""
Integrated Attack Alert System
Sends instant Telegram alerts + Email with PDF report attachments
"""

import os
import sys
import json
import threading
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

sys.path.insert(0, 'src')

from engines.telegram_alerter import TelegramAlerter
from engines.sendgrid_alerter import EmailAlerter, SMTPConfig
from engines.pdf_reporter import PDFReporter
from dotenv import load_dotenv


class IntegratedAttackAlerter:
    """Sends alerts via multiple channels with report attachments"""
    
    def __init__(self):
        """Initialize all alert channels"""
        load_dotenv()
        
        # Telegram
        self.telegram_token = os.getenv('TELEGRAM_BOT_TOKEN', '')
        self.telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID', '')
        self.telegram_alerter = None
        
        # Email
        self.email_alerter = None
        self.alert_email = os.getenv('SECURITY_ALERT_EMAIL', 'security@localhost')
        
        # Initialize alerters
        self._init_telegram()
        self._init_email()
        
        self.pdf_reporter = PDFReporter()
        self.alert_history = []
        
    def _init_telegram(self):
        """Initialize Telegram alerter"""
        if self.telegram_token and self.telegram_chat_id:
            try:
                self.telegram_alerter = TelegramAlerter()
                print("[✅] Telegram alerter initialized")
            except Exception as e:
                print(f"[⚠️] Telegram error: {e}")
    
    def _init_email(self):
        """Initialize Email alerter"""
        try:
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
                self.email_alerter = EmailAlerter(smtp_config)
                print("[✅] Email alerter initialized")
        except Exception as e:
            print(f"[⚠️] Email error: {e}")
    
    def send_attack_alert(self, attack_data: Dict) -> Dict:
        """Send attack alert via all channels"""
        
        alert_result = {
            'timestamp': datetime.now().isoformat(),
            'attack_type': attack_data.get('type', 'UNKNOWN'),
            'telegram': False,
            'email': False,
            'report_generated': False
        }
        
        # 1. TELEGRAM - Instant Alert
        if self.telegram_alerter and self.telegram_chat_id:
            try:
                telegram_message = self._format_telegram_message(attack_data)
                result = self.telegram_alerter.send_alert(self.telegram_chat_id, telegram_message)
                alert_result['telegram'] = result
                print(f"[📱] Telegram alert sent: {result}")
            except Exception as e:
                print(f"[❌] Telegram failed: {e}")
        
        # 2. Generate PDF Report
        report_path = None
        try:
            report_data = self._format_report_data(attack_data)
            report_path = self.pdf_reporter.generate_attack_report(report_data)
            alert_result['report_generated'] = True
            print(f"[📄] Report generated: {report_path}")
        except Exception as e:
            print(f"[⚠️] Report generation failed: {e}")
        
        # 3. EMAIL - With Attachment
        if self.email_alerter and self.alert_email != 'security@localhost':
            try:
                email_result = self.email_alerter.send_attack_alert(
                    to_email=self.alert_email,
                    attack_name=attack_data.get('type', 'UNKNOWN ATTACK'),
                    severity=attack_data.get('severity', 'HIGH'),
                    description=self._format_email_description(attack_data),
                    remediation=self._get_remediation(attack_data.get('type')),
                    source_ip=attack_data.get('source_ip', 'N/A'),
                    log_sample=self._format_log_sample(attack_data),
                    confidence=attack_data.get('confidence', 0.9)
                )
                alert_result['email'] = email_result.get('success', False)
                print(f"[📧] Email sent: {alert_result['email']}")
            except Exception as e:
                print(f"[❌] Email failed: {e}")
        
        self.alert_history.append(alert_result)
        return alert_result
    
    def _format_telegram_message(self, attack_data: Dict) -> str:
        """Format attack data for Telegram"""
        
        severity_emoji = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MEDIUM': '⚡',
            'LOW': 'ℹ️'
        }
        
        emoji = severity_emoji.get(attack_data.get('severity', 'HIGH'), '⚠️')
        
        message = f"""{emoji} **ATTACK DETECTED**

**Type:** {attack_data.get('type', 'Unknown')}
**Severity:** {attack_data.get('severity', 'HIGH')}
**Source IP:** {attack_data.get('source_ip', 'N/A')}
**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

**Details:**
{attack_data.get('description', 'No details')}

**Action:** Automated response activated
**Status:** Under investigation

🔗 Check dashboard for full report
"""
        return message
    
    def _format_email_description(self, attack_data: Dict) -> str:
        """Format detailed description for email"""
        details = []
        
        for key, value in attack_data.items():
            if key not in ['type', 'severity', 'source_ip']:
                details.append(f"• {key}: {value}")
        
        return "\n".join(details) if details else attack_data.get('description', 'Attack detected')
    
    def _format_log_sample(self, attack_data: Dict) -> str:
        """Format log sample for email"""
        
        log_sample = attack_data.get('log_sample', attack_data.get('description', ''))
        
        if isinstance(log_sample, dict):
            return json.dumps(log_sample, indent=2)[:500]
        
        return str(log_sample)[:500]
    
    def _format_report_data(self, attack_data: Dict) -> Dict:
        """Format data for PDF report"""
        return {
            'attack_type': attack_data.get('type', 'UNKNOWN'),
            'severity': attack_data.get('severity', 'HIGH'),
            'timestamp': datetime.now().isoformat(),
            'source_ip': attack_data.get('source_ip', 'N/A'),
            'target_ip': attack_data.get('target_ip', 'N/A'),
            'description': attack_data.get('description', 'No description'),
            'details': attack_data,
            'recommendations': self._get_recommendations(attack_data.get('type')),
        }
    
    def _get_remediation(self, attack_type: str) -> str:
        """Get remediation steps for attack type"""
        
        remediations = {
            'PORT_SCAN': 'Enable firewall rules to block port scanning. Update IDS/IPS signatures.',
            'BRUTE_FORCE': 'Implement account lockout policy. Enable MFA. Review access logs.',
            'SQL_INJECTION': 'Use parameterized queries. Validate all user inputs. Update WAF rules.',
            'DDOS': 'Activate DDoS mitigation. Route traffic through CDN. Contact ISP.',
            'MALWARE': 'Isolate affected system. Run full antivirus scan. Restore from backup.',
            'UNAUTHORIZED_ACCESS': 'Revoke compromised credentials. Reset passwords. Audit logs.',
            'PRIVILEGE_ESCALATION': 'Apply security patches. Review user permissions. Monitor logs.',
            'DATA_EXFILTRATION': 'Block external IPs. Revoke access tokens. Monitor outbound traffic.',
        }
        
        return remediations.get(attack_type, 'Immediate investigation and containment recommended.')
    
    def _get_recommendations(self, attack_type: str) -> List[str]:
        """Get recommendations for attack type"""
        
        recommendations = {
            'PORT_SCAN': [
                'Review firewall logs for other scan attempts',
                'Update network segmentation',
                'Enable port knocking if available',
                'Monitor for follow-up attacks',
            ],
            'BRUTE_FORCE': [
                'Block source IP temporarily',
                'Enable account lockout after 5 failures',
                'Implement CAPTCHA',
                'Monitor for credential stuffing',
            ],
            'SQL_INJECTION': [
                'Review recent database queries',
                'Check for unauthorized data access',
                'Update injection detection signatures',
                'Audit database permissions',
            ],
            'DDOS': [
                'Analyze traffic patterns',
                'Configure rate limiting',
                'Activate geo-blocking if needed',
                'Scale infrastructure',
            ],
        }
        
        return recommendations.get(attack_type, [
            'Continue monitoring',
            'Document incident',
            'Review security controls',
            'Prepare incident response'
        ])


def demo_attack_alerts():
    """Demo various attack scenarios"""
    
    alerter = IntegratedAttackAlerter()
    
    print("\n" + "="*80)
    print("🚨 ATTACK ALERT SYSTEM DEMONSTRATION")
    print("="*80)
    
    # Demo attacks
    attacks = [
        {
            'type': 'BRUTE_FORCE',
            'severity': 'CRITICAL',
            'source_ip': '192.0.2.100',
            'target_ip': '10.0.0.50',
            'description': 'SSH brute force attack detected',
            'failed_attempts': 127,
            'port': 22,
            'log_sample': '[WARN] 127 failed SSH login attempts from 192.0.2.100 in 2 minutes',
            'confidence': 0.98
        },
        {
            'type': 'SQL_INJECTION',
            'severity': 'CRITICAL',
            'source_ip': '203.0.113.45',
            'target_ip': '10.0.0.50',
            'description': 'SQL injection in login form',
            'payload': "username' OR '1'='1",
            'log_sample': "SELECT * FROM users WHERE username='' OR '1'='1' AND password=''",
            'confidence': 0.95
        },
        {
            'type': 'PORT_SCAN',
            'severity': 'HIGH',
            'source_ip': '198.51.100.78',
            'target_ip': '10.0.0.50',
            'description': 'Network port scanning detected',
            'ports_scanned': 256,
            'log_sample': 'Connection attempts on ports 1-256 from single source',
            'confidence': 0.92
        },
    ]
    
    for i, attack in enumerate(attacks, 1):
        print(f"\n[{i}] Sending alert for {attack['type']}...")
        result = alerter.send_attack_alert(attack)
        
        print(f"    Telegram: {'✅' if result.get('telegram') else '❌'}")
        print(f"    Email: {'✅' if result.get('email') else '❌'}")
        print(f"    Report: {'✅' if result.get('report_generated') else '❌'}")
        
        # Small delay between alerts
        import time
        time.sleep(1)
    
    print("\n" + "="*80)
    print("📊 Alert Summary")
    print("="*80)
    print(f"Total alerts sent: {len(alerter.alert_history)}")
    
    successful = sum(1 for a in alerter.alert_history if a['telegram'] or a['email'])
    print(f"Successful deliveries: {successful}")
    
    print("\n✅ Attack alert system working!\n")


if __name__ == '__main__':
    demo_attack_alerts()
