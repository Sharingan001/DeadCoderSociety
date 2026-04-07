# SendGrid Email Alerter Setup Guide

**LogSentinel Pro v4.0** - Professional Email Alerting

## 🎯 Quick Setup (5 minutes)

### Step 1: Install SendGrid Python Library

```powershell
pip install sendgrid
pip install python-dotenv
```

### Step 2: Set Environment Variables

#### Option A: PowerShell (Temporary - Current Session Only)
```powershell
$env:SENDGRID_API_KEY = "SG.your_api_key_here"
$env:SENDGRID_FROM_EMAIL = "alerts@logsentinel.com"
$env:SENDGRID_FROM_NAME = "LogSentinel Security"
```

#### Option B: PowerShell (Permanent)
```powershell
[Environment]::SetEnvironmentVariable("SENDGRID_API_KEY", "SG.your_api_key_here", "User")
[Environment]::SetEnvironmentVariable("SENDGRID_FROM_EMAIL", "alerts@logsentinel.com", "User")

# Restart PowerShell after setting
```

#### Option C: .env File (Recommended for Development)
```bash
# Create file: .env
SENDGRID_API_KEY=SG.your_api_key_here
SENDGRID_FROM_EMAIL=alerts@logsentinel.com
SENDGRID_FROM_NAME=LogSentinel Security
SECURITY_ALERT_EMAIL=security@company.com
ADMIN_EMAIL=admin@company.com
COMPLIANCE_EMAIL=compliance@company.com
```

**Important:** Add `.env` to your `.gitignore` to prevent accidental exposure:
```bash
echo ".env" >> .gitignore
```

### Step 3: Verify Setup

```powershell
# Check if environment variable is set
$env:SENDGRID_API_KEY
# Should output your API key
```

### Step 4: Test the System

```powershell
# Run demo test
python test_sendgrid_alerter.py
```

---

## 📋 Complete Setup Walkthrough

### 1. Create SendGrid Account

1. Go to [SendGrid.com](https://sendgrid.com)
2. Sign up for free account
3. Verify email address
4. Go to Settings → API Keys → Create API Key
5. Select "Full Access" 
6. Copy the key (you'll only see it once!)

### 2. Create Sender Email Address

1. In SendGrid dashboard → Settings → Sender Authentication
2. Select "Single Sender Verification"
3. Add sender email: `alerts@logsentinel.com`
4. Verify the email address
5. Wait for confirmation

### 3. Update Your Code

#### Using .env File (Recommended)
```python
from dotenv import load_dotenv
import os
from src.engines.sendgrid_alerter import SendGridEmailAlerter, SendGridConfig

# Load environment variables
load_dotenv()

# Initialize alerter
config = SendGridConfig(
    api_key=os.getenv('SENDGRID_API_KEY'),
    from_email=os.getenv('SENDGRID_FROM_EMAIL'),
    from_name=os.getenv('SENDGRID_FROM_NAME')
)

alerter = SendGridEmailAlerter(config)
```

#### Using Environment Variables Directly
```python
import os
from src.engines.sendgrid_alerter import SendGridEmailAlerter, SendGridConfig

config = SendGridConfig(
    api_key=os.environ.get('SENDGRID_API_KEY'),
    from_email=os.environ.get('SENDGRID_FROM_EMAIL', 'alerts@logsentinel.com'),
    from_name=os.environ.get('SENDGRID_FROM_NAME', 'LogSentinel Security')
)

alerter = SendGridEmailAlerter(config)
```

### 4. Send Your First Alert

```python
# Send attack alert
result = alerter.send_attack_alert(
    to_email="security@company.com",
    attack_name="SQL Injection Detected",
    severity="CRITICAL",
    description="SQL injection attempt detected in login form",
    remediation="Update WAF rules, review access logs",
    source_ip="192.168.1.50",
    log_sample="SELECT * FROM users WHERE id='1' OR '1'='1'",
    cve_ids=["CVE-2019-9193"]
)

if result['success']:
    print(f"✅ Email sent! Status: {result['status_code']}")
else:
    print(f"❌ Error: {result['error']}")
```

---

## 🚀 Alert Types Available

### 1. Attack Alerts
```python
alerter.send_attack_alert(
    to_email="security@company.com",
    attack_name="SQL Injection - Authentication Bypass",
    severity="CRITICAL",  # CRITICAL, HIGH, MEDIUM, LOW
    description="...",
    remediation="...",
    source_ip="192.168.1.50",
    log_sample="...",
    cve_ids=["CVE-2019-9193"]
)
```

### 2. Anomaly Alerts
```python
alerter.send_anomaly_alert(
    to_email="security@company.com",
    metric_name="Login_Attempts",
    current_value=150,
    baseline_value=10,
    anomaly_score=87.5,
    severity="HIGH",
    explanation="..."
)
```

### 3. Security Reports
```python
alerter.send_security_report(
    to_email="security@company.com",
    report_type="daily",  # daily, weekly, monthly
    total_logs=125000,
    total_alerts=47,
    critical_count=3,
    high_count=12
)
```

### 4. Login Notifications
```python
alerter.send_login_alert(
    to_email="user@company.com",
    username="john_doe",
    form_name="Admin Portal",
    ip_address="192.168.1.100",
    location="New York, USA",
    device="Chrome on Windows"
)
```

---

## 📧 Email Features

✅ **Professional HTML Templates**
- Color-coded severity levels (CRITICAL=Red, HIGH=Orange, MEDIUM=Yellow, LOW=Green)
- Clean, modern design
- Mobile-responsive
- Dark/Light theme compatible

✅ **Real-time Data**
- Live timestamp
- Actual metrics and values
- Source IP and location
- CVE references
- MITRE ATT&CK mappings

✅ **Action-Oriented**
- Clear descriptions of threats
- Specific remediation steps
- Next steps guidance
- Contact information

✅ **Professional Branding**
- Customizable sender name
- Your company logo (in HTML)
- Custom colors
- Professional footer

---

## 🧪 Testing Workflow

### Run Complete Demo
```powershell
python test_sendgrid_alerter.py
```

This will:
1. ✅ Verify SendGrid configuration
2. ✅ Send 4 different alert types
3. ✅ Display send history
4. ✅ Show success/failure status

### Send Custom Test
```python
from src.engines.sendgrid_alerter import SendGridEmailAlerter, SendGridConfig
import os
from dotenv import load_dotenv

load_dotenv()

config = SendGridConfig(
    api_key=os.getenv('SENDGRID_API_KEY'),
    from_email=os.getenv('SENDGRID_FROM_EMAIL')
)

alerter = SendGridEmailAlerter(config)

# Your custom alert
result = alerter.send_attack_alert(
    to_email="your-test-email@gmail.com",
    attack_name="Test Attack",
    severity="HIGH",
    description="This is a test attack",
    remediation="No action needed, this is a test",
    source_ip="0.0.0.0",
    log_sample="test log entry"
)

print(f"Status: {result}")
```

---

## 🔒 Security Best Practices

### ✅ DO:
- Use environment variables for API keys
- Rotate API keys regularly
- Use `.env` files only for development
- Add `.env` to `.gitignore`
- Set file permissions on `.env` to 600 (read-only for owner)
- Use dedicated sender email for alerts
- Verify sender email in SendGrid
- Use HTTPS for all communications
- Monitor email delivery metrics

### ❌ DON'T:
- Paste API keys in code
- Commit `.env` files to git
- Share API keys in messages/chat
- Use production keys in development
- Leave hardcoded credentials
- Use weak/shared API keys
- Send large attachments via email
- Spam users with alerts (use suppression)

---

## 🐛 Troubleshooting

### Issue: "API Key not found"
```python
# Check if set
import os
print(os.getenv('SENDGRID_API_KEY'))  # Should print your key

# If empty, set it:
$env:SENDGRID_API_KEY = "your_key"
```

### Issue: "Invalid API Key"
- Verify key starts with `SG.`
- Check for extra spaces/newlines
- Generate new key in SendGrid dashboard
- Ensure API key has "Full Access" permissions

### Issue: "Sender email not verified"
- Go to SendGrid Dashboard → Settings → Sender Authentication
- Click "Verify" for your sender email
- Check email inbox for verification link
- Verify the email address
- Wait 5-10 minutes for activation

### Issue: "Email not delivering"
- Check spam/junk folder
- Verify recipient email is correct
- Enable SendGrid webhook tracking:
  - Settings → Mail Send → Track opens/clicks
- Check SendGrid activity dashboard for delivery status

### Issue: "Connection timeout"
- Check internet connection
- Verify firewall allows outbound SMTP
- Try from different network
- Check SendGrid status page for incidents

---

## 📊 Monitoring & Logging

### View Send History
```python
alerter = SendGridEmailAlerter(config)
# ... send alerts ...
history = alerter.get_history()

for alert in history:
    print(f"Email to: {alert['to_email']}")
    print(f"Status: {'Success' if alert['success'] else 'Failed'}")
    print(f"Time: {alert['timestamp']}")
```

### Enable SendGrid Webhooks
1. SendGrid Dashboard → Settings → Mail Send
2. Enable: Open Tracking, Click Tracking, Bounce Processing
3. Add webhook URL to your server
4. Receive delivery status notifications

---

## 🚀 Integration with LogSentinel

### In Global Attack Recognizer
```python
from src.engines.global_attack_recognizer import GlobalAttackRecognitionEngine
from src.engines.sendgrid_alerter import SendGridEmailAlerter, SendGridConfig

recognizer = GlobalAttackRecognitionEngine()
alerter = SendGridEmailAlerter(config)

# Detect attacks and alert
attacks = recognizer.recognize_attack(log_entry)
if attacks:
    for attack in attacks:
        alerter.send_attack_alert(
            to_email="security@company.com",
            attack_name=attack['attack_name'],
            severity=attack['severity'],
            description=attack['description'],
            remediation=attack['remediation'],
            source_ip=context.get('ip'),
            log_sample=log_entry[:100]
        )
```

### In Anomaly Detection
```python
from src.engines.anomaly_detection_ml import AdvancedAnomalyDetectionEngine
from src.engines.sendgrid_alerter import SendGridEmailAlerter

anomaly_engine = AdvancedAnomalyDetectionEngine()
alerter = SendGridEmailAlerter(config)

result = anomaly_engine.detect_anomaly(...)
if result.is_anomaly:
    alerter.send_anomaly_alert(
        to_email="security@company.com",
        metric_name=result.metric_name,
        current_value=result.value,
        baseline_value=result.baseline,
        anomaly_score=result.anomaly_score,
        severity=result.severity,
        explanation=result.explanation
    )
```

---

## ✅ Verification Checklist

Before going to production:

- [ ] SendGrid account created and verified
- [ ] API key generated with Full Access
- [ ] Sender email verified in SendGrid
- [ ] Environment variables set correctly
- [ ] Test script runs successfully
- [ ] Received 4 test emails
- [ ] Emails display correctly (HTML rendering)
- [ ] Recipient email configured
- [ ] .env file ignored in git
- [ ] Error handling tested
- [ ] Rate limiting understood (SendGrid limits)
- [ ] Monitoring/logging in place

---

## 📞 Support Links

- **SendGrid Docs**: https://docs.sendgrid.com
- **Python SDK**: https://github.com/sendgrid/sendgrid-python
- **Email Best Practices**: https://docs.sendgrid.com/ui/sending-email/sender-verification
- **API Status**: https://status.sendgrid.com

---

## 📝 Quick Commands

```powershell
# Set API key (temporary)
$env:SENDGRID_API_KEY = "your_key_here"

# Verify it's set
$env:SENDGRID_API_KEY

# Run tests
python test_sendgrid_alerter.py

# Check if module installed
pip list | findstr sendgrid

# Install dependencies
pip install sendgrid python-dotenv
```

---

**Status: ✅ READY FOR PRODUCTION**

Your SendGrid email alerting is now configured and tested. You're ready to integrate it with LogSentinel Pro!
