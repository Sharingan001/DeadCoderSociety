#!/usr/bin/env python
"""
Test Both Email (SMTP) and Telegram Alerts
Comprehensive verification of all alert channels
"""

import os
import sys
from datetime import datetime
from dotenv import load_dotenv

sys.path.insert(0, 'src')

from engines.sendgrid_alerter import SendGridEmailAlerter, SMTPConfig
from engines.telegram_alerter import TelegramAlerter

# Load configuration
load_dotenv()

print("\n" + "="*80)
print("🔍 ALERT SYSTEM VERIFICATION - Email + Telegram")
print("="*80)

print(f"\n⏰ Test Time: {datetime.now().isoformat()}\n")

# ============================================================================
# 1. TEST EMAIL (SMTP)
# ============================================================================

print("─"*80)
print("📧 TEST 1: EMAIL ALERT (SMTP)")
print("─"*80)

target_email = "tuskydv@gmail.com"

# Get SMTP config
smtp_enabled = os.getenv('SMTP_ENABLED', 'false').lower() == 'true'
smtp_host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
smtp_port = int(os.getenv('SMTP_PORT', '587'))
smtp_user = os.getenv('SMTP_USER', '')
smtp_pass = os.getenv('SMTP_PASSWORD', '')

print(f"\nTarget Email: {target_email}")

if smtp_enabled and smtp_user and smtp_pass:
    print(f"✅ SMTP Configured")
    print(f"   Host: {smtp_host}:{smtp_port}")
    print(f"   User: {smtp_user}")
    
    smtp_config = SMTPConfig(
        host=smtp_host,
        port=smtp_port,
        user=smtp_user,
        password=smtp_pass,
        from_email=os.getenv('SMTP_FROM_EMAIL', smtp_user)
    )
    
    alerter = SendGridEmailAlerter(smtp_config=smtp_config)
    
    print("\n▶️  Sending test email...")
    
    email_result = alerter.send_attack_alert(
        to_email=target_email,
        attack_name="System Alert Test",
        severity="HIGH",
        description="This is a test email from LogSentinel Pro alert system verification.",
        remediation="No action needed - this is only a test.",
        source_ip="127.0.0.1",
        log_sample="[TEST] Alert system email test",
        confidence=1.0
    )
    
    print("\n📊 Email Result:")
    if email_result['success']:
        print(f"   ✅ SUCCESS - Email sent via {email_result.get('method')}")
        print(f"   To: {email_result.get('to_email')}")
        print(f"   Time: {email_result.get('timestamp')}")
        email_status = "✅ WORKING"
    else:
        print(f"   ❌ FAILED")
        print(f"   Error: {email_result.get('error')}")
        email_status = "❌ FAILED"
else:
    print(f"❌ SMTP NOT CONFIGURED")
    email_status = "❌ NOT CONFIGURED"

# ============================================================================
# 2. TEST TELEGRAM
# ============================================================================

print("\n" + "─"*80)
print("📱 TEST 2: TELEGRAM ALERT")
print("─"*80)

telegram_token = os.getenv('TELEGRAM_BOT_TOKEN', '').strip()
telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID', '').strip()

print(f"\nTelegram Bot Token: {'✅ Configured' if telegram_token else '❌ NOT CONFIGURED'}")
print(f"Telegram Chat ID: {'✅ Configured' if telegram_chat_id else '❌ NOT CONFIGURED'}")

if telegram_token and telegram_chat_id and telegram_token != 'your_token_here':
    print("\n▶️  Sending test telegram message...")
    
    try:
        telegram_alerter = TelegramAlerter()
        
        message = """🔍 **System Alert Test**

**Type:** Verification Test
**Status:** LogSentinel Pro Alert System Working
**Timestamp:** """ + datetime.now().isoformat() + """

✅ This message confirms Telegram alerts are functioning correctly.

No action required - this is a system test."""
        
        telegram_result = telegram_alerter.send_alert(telegram_chat_id, message)
        
        print("\n📊 Telegram Result:")
        if telegram_result:
            print(f"   ✅ SUCCESS - Message sent to Chat ID: {telegram_chat_id}")
            print(f"   Time: {datetime.now().isoformat()}")
            telegram_status = "✅ WORKING"
        else:
            print(f"   ❌ FAILED - No confirmation from Telegram API")
            telegram_status = "❌ FAILED"
    
    except Exception as e:
        print(f"\n   ❌ ERROR: {str(e)}")
        telegram_status = "❌ ERROR"
else:
    print(f"❌ TELEGRAM NOT CONFIGURED")
    telegram_status = "❌ NOT CONFIGURED"

# ============================================================================
# 3. SUMMARY
# ============================================================================

print("\n" + "="*80)
print("📋 FINAL STATUS SUMMARY")
print("="*80)

print(f"\n📧 EMAIL (SMTP): {email_status}")
print(f"📱 TELEGRAM:     {telegram_status}")

print("\n" + "─"*80)

if "✅ WORKING" in email_status and "✅ WORKING" in telegram_status:
    print("\n🎉 ALL SYSTEMS WORKING!")
    print("   ✅ Email alerts ready")
    print("   ✅ Telegram alerts ready")
    print("   ✅ Dual-channel alert system operational")
elif "✅ WORKING" in email_status or "✅ WORKING" in telegram_status:
    print("\n⚠️  PARTIAL SUCCESS")
    working = []
    if "✅ WORKING" in email_status:
        working.append("Email")
    if "✅ WORKING" in telegram_status:
        working.append("Telegram")
    print(f"   Working: {', '.join(working)}")
    print("   Not working: See above")
else:
    print("\n❌ NO SYSTEMS WORKING")
    print("   Please check configuration in .env file")

print("\n" + "="*80)

print(f"\n📬 Check Email: {target_email}")
if telegram_chat_id:
    print(f"📱 Check Telegram: Chat ID {telegram_chat_id}")

print("\nTest completed!\n")
