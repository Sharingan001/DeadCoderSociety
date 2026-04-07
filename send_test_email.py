#!/usr/bin/env python
"""
Send Test Email via SendGrid or SMTP
Tests whichever method is configured and working
"""

import os
import sys
from datetime import datetime
from dotenv import load_dotenv

sys.path.insert(0, 'src')

from engines.sendgrid_alerter import SendGridEmailAlerter, SendGridConfig, SMTPConfig

# Load configuration
load_dotenv()

# Target email
TARGET_EMAIL = "tuskydv@gmail.com"

print("\n" + "="*80)
print("📧 TEST EMAIL SENDER - SendGrid + SMTP Fallback")
print("="*80)

print(f"\n📬 Target Email: {TARGET_EMAIL}")
print(f"⏰ Timestamp: {datetime.now().isoformat()}")

# Get configuration
sendgrid_key = os.getenv('SENDGRID_API_KEY', '').strip()
sendgrid_from = os.getenv('SENDGRID_FROM_EMAIL', 'noreply@logsentinel.com')

smtp_enabled = os.getenv('SMTP_ENABLED', 'false').lower() == 'true'

print("\n" + "─"*80)
print("🔧 Configuration Check:")
print("─"*80)

# Check SendGrid
if sendgrid_key and sendgrid_key != 'your_sendgrid_api_key_here':
    print(f"✅ SendGrid API Key: CONFIGURED")
    sg_config = SendGridConfig(
        api_key=sendgrid_key,
        from_email=sendgrid_from,
        from_name="LogSentinel Security"
    )
else:
    print(f"⚠️  SendGrid API Key: NOT CONFIGURED (will use SMTP)")
    sg_config = SendGridConfig(
        api_key="dummy_key",
        from_email="noreply@logsentinel.com"
    )

# Check SMTP
if smtp_enabled:
    smtp_host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
    smtp_port = int(os.getenv('SMTP_PORT', '587'))
    smtp_user = os.getenv('SMTP_USER', '')
    smtp_pass = os.getenv('SMTP_PASSWORD', '')
    
    if smtp_user and smtp_pass:
        print(f"✅ SMTP Configuration: CONFIGURED")
        print(f"   Host: {smtp_host}:{smtp_port}")
        print(f"   User: {smtp_user[:20]}...")
        smtp_config = SMTPConfig(
            host=smtp_host,
            port=smtp_port,
            user=smtp_user,
            password=smtp_pass,
            from_email=os.getenv('SMTP_FROM_EMAIL', smtp_user)
        )
    else:
        print(f"⚠️  SMTP Configuration: INCOMPLETE (missing credentials)")
        smtp_config = None
else:
    print(f"⚠️  SMTP: NOT ENABLED in .env")
    smtp_config = None

print("\n" + "─"*80)
print("📤 Sending Test Email...")
print("─"*80)

# Create alerter
alerter = SendGridEmailAlerter(sg_config, smtp_config)

# Send test email
result = alerter.send_attack_alert(
    to_email=TARGET_EMAIL,
    attack_name="Test Alert - System Verification",
    severity="INFO",
    description="This is a test email to verify the alert system is working correctly.",
    remediation="No action needed - this is just a test email.",
    source_ip="127.0.0.1",
    log_sample="[TEST] Alert system test email",
    confidence=1.0
)

print("\n" + "─"*80)
print("📊 Results:")
print("─"*80)

if result['success']:
    print(f"✅ SUCCESS!")
    print(f"   Method: {result.get('method', 'Unknown')}")
    print(f"   To: {result.get('to_email')}")
    print(f"   Status Code: {result.get('status_code', 'N/A')}")
    print(f"   Timestamp: {result.get('timestamp')}")
    print(f"\n✅ Email should arrive at {TARGET_EMAIL} shortly!")
else:
    print(f"❌ FAILED!")
    print(f"   Error: {result.get('error')}")
    print(f"   Timestamp: {result.get('timestamp')}")
    print(f"\n❌ Email could not be sent. Check configuration.")

print("\n" + "="*80)
