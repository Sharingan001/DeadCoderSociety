# LogSentinel Pro v4.0 - Integrated Alert System Setup

## Overview
This document guides you through setting up the complete integrated alert system with three channels:
1. **Email Alerts** (SendGrid + SMTP Fallback)
2. **Telegram Alerts** (Real-time mobile notifications)
3. **Live Log Analysis** (Real-time threat detection and streaming)

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install sendgrid python-dotenv python-telegram-bot
```

### 2. Configure .env File

Create a `.env` file in the project root with your credentials:

```env
# SendGrid Configuration
SENDGRID_API_KEY=your_sendgrid_api_key_here
SENDGRID_FROM_EMAIL=noreply@logsentinel.com
SENDGRID_FROM_NAME=LogSentinel Security Alerts

# SMTP Fallback (for when SendGrid fails)
SMTP_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_gmail@gmail.com
SMTP_PASSWORD=your_app_password

# Telegram Configuration
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Alert Recipients
SECURITY_ALERT_EMAIL=security@company.com
ADMIN_EMAIL=admin@company.com
COMPLIANCE_EMAIL=compliance@company.com

# Live Log Analysis Settings
LIVE_LOG_ENABLED=true
LIVE_LOG_UPDATE_INTERVAL=5
LIVE_LOG_HISTORY_SIZE=1000
LIVE_LOG_ALERT_THRESHOLD=0.7
```

---

## 📧 Email Setup (SendGrid + SMTP)

### Getting SendGrid API Key

1. Go to https://app.sendgrid.com
2. Sign up or log in
3. Navigate to **Settings → API Keys**
4. Click **Create API Key**
5. Give it a name (e.g., "LogSentinel Pro")
6. Select **Full Access**
7. Copy the key and paste in `.env`

### SMTP Fallback (Gmail Example)

1. Go to https://myaccount.google.com/apppasswords
2. Select "Mail" and "Windows Computer"
3. Generate app password
4. Use the 16-character password in `.env`
5. Set `SMTP_ENABLED=true`

### Testing Email Alerts

```bash
python test_sendgrid_alerter.py
```

---

## 📱 Telegram Setup

### Creating Telegram Bot

1. Open Telegram and search for **@BotFather**
2. Type `/start` then `/newbot`
3. Follow the prompts to create your bot
4. BotFather will give you a token
5. Copy this token to `TELEGRAM_BOT_TOKEN` in `.env`

### Getting Chat ID

1. Create a Telegram group or use your private chat
2. Add your bot to the group or start a private chat
3. Send any message
4. Go to: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
5. Find `"chat":{"id":YOUR_CHAT_ID`
6. Add this ID to `TELEGRAM_CHAT_ID` in `.env`

### Testing Telegram

```bash
python test_telegram_alerter.py
```

---

## 📊 Live Log Analysis Features

### Real-Time Statistics
- Log ingestion and processing
- Threat pattern detection
- Source/destination IP tracking
- Port activity monitoring
- Severity breakdown

### Anomaly Detection
- Threat spike detection
- Port scanning patterns
- DDoS-like behavioral patterns
- Configurable sensitivity levels

### Live Monitoring
Monitor log files in real-time:

```python
from src.engines.live_log_analyzer import LiveLogAnalyzer

analyzer = LiveLogAnalyzer()
analyzer.start_live_monitoring('/path/to/logfile.log')

# Or ingest logs programmatically
analyzer.ingest_log({
    'timestamp': datetime.now().isoformat(),
    'threat_type': 'SQL_INJECTION',
    'severity': 'CRITICAL',
    'source_ip': '192.168.1.50'
})

# Get real-time stats
stats = analyzer.get_live_stats()
print(stats)
```

---

## 🔧 Running Integrated Tests

### Test All Systems

```bash
python test_integrated_alerts.py
```

This will:
- ✅ Initialize all three alert systems
- ✅ Show configuration status
- ✅ Demonstrate email alerting (with fallback)
- ✅ Demonstrate Telegram alerting
- ✅ Show live log analysis in action
- ✅ Simulate integrated alert flow

### Output Example

```
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║               LogSentinel Pro v4.0 - Integrated Alert System Test         ║
║          (SendGrid + SMTP Fallback + Telegram + Live Log Analysis)        ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝

================================================================================
🔧 INITIALIZING ALERT SYSTEMS
================================================================================
✅ SendGrid Config: VALID
✅ SMTP Fallback: CONFIGURED
✅ Email Alerter: INITIALIZED
✅ Telegram Alerter: INITIALIZED
✅ Live Log Analyzer: INITIALIZED
```

---

## 🔄 Error Handling & Fallback

### Email Fallback Chain

1. **Primary**: SendGrid API
   - Fastest, most reliable
   - Handles attachments, templates
   
2. **Fallback**: SMTP (Gmail, Office365, etc.)
   - Automatic activation if SendGrid fails
   - HTTP 403, timeout, or API errors trigger fallback
   
3. **Disabled**: If neither configured, emails won't send

### Common Issues & Solutions

#### SendGrid 403 Error
**Cause**: Invalid API key or insufficient permissions
**Solution**: 
- Verify API key is correct
- Ensure "Full Access" permissions
- Check key hasn't been revoked

#### SMTP Authentication Failed
**Cause**: Wrong password or app-specific password not used
**Solution**:
- For Gmail: Use app-specific password
- For Office365: Use your email password
- Ensure 2FA is properly configured

#### Telegram Not Sending
**Cause**: Invalid bot token or chat ID
**Solution**:
- Verify bot token format (starts with number)
- Check Chat ID is correct number
- Ensure bot is member of group

---

## 📈 Production Deployment

### Scaling Live Log Analysis

```python
# High-throughput configuration
analyzer = LiveLogAnalyzer(
    max_history=10000,  # Keep more history
    update_interval=1   # Check more frequently
)
```

### Setting Up Callbacks

```python
def on_critical_threat(log_entry):
    print(f"Critical threat detected: {log_entry}")
    # Send immediate notification
    # Page on-call engineer
    # Create incident

analyzer.add_alert_callback(on_critical_threat)
analyzer.start_live_monitoring('/var/log/auth.log')
```

### Exporting Logs

```python
# Export live logs and statistics
analyzer.export_logs('logs/export_2026-04-07.json')
```

---

## 🔐 Security Best Practices

1. **Never commit .env** - Add to .gitignore
2. **Rotate API keys regularly** - Update SENDGRID_API_KEY monthly
3. **Use app passwords** - Don't use main account password
4. **Limit bot permissions** - Telegram bot should have minimal permissions
5. **Encrypt backup logs** - Store exported logs securely
6. **Use HTTPS only** - For any remote log ingestion

---

## 📞 Support

### Files to Check
- `test_integrated_alerts.py` - Full integration test
- `src/engines/sendgrid_alerter.py` - Email alerting engine
- `src/engines/telegram_alerter.py` - Telegram integration
- `src/engines/live_log_analyzer.py` - Real-time log analysis

### Debug Mode

```bash
# Enable verbose output
DEBUG=true python test_integrated_alerts.py
```

---

## ✅ Verification Checklist

- [ ] `.env` file created with all credentials
- [ ] SendGrid API key tested
- [ ] SMTP credentials verified (if using fallback)
- [ ] Telegram bot created and added to group
- [ ] `test_integrated_alerts.py` runs without errors
- [ ] Email test sent successfully
- [ ] Telegram message received
- [ ] Live analyzer ingests sample logs
- [ ] Anomalies detected correctly

---

## 🚀 Next Steps

1. **Integrate with your application**
   ```python
   from src.engines.sendgrid_alerter import SendGridEmailAlerter, SendGridConfig
   from src.engines.telegram_alerter import TelegramAlerter
   from src.engines.live_log_analyzer import LiveLogAnalyzer
   
   # Your alert handlers can now use these
   ```

2. **Set up log streaming** to the live analyzer
3. **Configure automated incident response** based on threat levels
4. **Monitor anomaly scores** in real-time dashboards
5. **Schedule daily/weekly reports** via email

---

**Version**: 4.0  
**Last Updated**: 2026-04-07  
**Maintained By**: LogSentinel Security Team
