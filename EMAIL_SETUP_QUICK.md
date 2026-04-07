# Quick Email Setup for tuskydv@gmail.com

## Option 1: Setup SMTP (Easiest - Using Gmail)

### Step 1: Get Gmail App Password
1. Go to: https://myaccount.google.com/apppasswords
2. Select "Mail" and "Windows Computer"
3. Google will generate a 16-character password
4. Copy this password

### Step 2: Create `.env` file
In your project root, create a file named `.env` with:

```env
SMTP_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=tuskydv@gmail.com
SMTP_PASSWORD=your_16_char_password_here
SMTP_FROM_EMAIL=tuskydv@gmail.com
SECURITY_ALERT_EMAIL=tuskydv@gmail.com
```

### Step 3: Test It
```bash
py send_test_email.py
```

---

## Option 2: Setup SendGrid (Alternative)

### Step 1: Get SendGrid API Key
1. Go to: https://app.sendgrid.com
2. Click "Settings" → "API Keys"
3. Click "Create API Key"
4. Select "Full Access"
5. Copy the key

### Step 2: Create `.env` file
```env
SENDGRID_API_KEY=SG.your_long_api_key_here
SENDGRID_FROM_EMAIL=noreply@logsentinel.com
SECURITY_ALERT_EMAIL=tuskydv@gmail.com
```

### Step 3: Test It
```bash
py send_test_email.py
```

---

## Which One?

**SMTP (Recommended for quick setup):**
- ✅ Free (uses your Gmail account)
- ✅ No additional services
- ✅ Works immediately
- ⏱️ Takes 2 minutes

**SendGrid (More professional):**
- ✅ Industry standard
- ✅ Better for production
- ✅ Free tier available
- ⏱️ Takes 5 minutes (need to create account)

---

**Choose one method above and let me know when your `.env` is ready!** 

Then I'll run the test email to tuskydv@gmail.com ✉️
