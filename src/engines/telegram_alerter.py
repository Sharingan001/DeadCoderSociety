#!/usr/bin/env python3
import os
import time
import requests
from dotenv import load_dotenv

dotenv_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'clone_layout', '.env')

class TelegramAlerter:
    def __init__(self):
        load_dotenv(dotenv_path)
        self.bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
        self.chat_id = os.environ.get("TELEGRAM_CHAT_ID")
        self.api_url = f"https://api.telegram.org/bot{self.bot_token}"
        
        if self.bot_token and not self.chat_id:
            print("[Telegram] No CHAT_ID found. Auto-discovering from bot messages...")
            self.auto_discover_chat_id()

    def auto_discover_chat_id(self):
        """Polls telegram limits to find the user chat id from the latest incoming message."""
        try:
            response = requests.get(f"{self.api_url}/getUpdates", timeout=5)
            data = response.json()
            if data.get("ok") and data["result"]:
                # Get the chat id of the last message sent to the bot
                last_update = data["result"][-1]
                if "message" in last_update:
                    chat_id = str(last_update["message"]["chat"]["id"])
                    self.chat_id = chat_id
                    
                    # Save back to .env
                    self.save_chat_id(chat_id)
                    print(f"[*] Telegram Auto-Discovery successful! Bound to Chat ID: {chat_id}")
                    
                    self.send_alert("✅ LogSentinel Pro Enterprise is now securely bound to this chat. You will receive active threat intelligence alerts here.", "Security Orchestrator Online")
                    return
            print("[-] Telegram Auto-Discovery failed. Send a message to your bot and restart!")
        except Exception as e:
            print(f"[-] Telegram Auto-Discovery Error: {e}")

    def save_chat_id(self, chat_id):
        # Update .env
        try:
            if not os.path.exists(dotenv_path):
                return
            with open(dotenv_path, "r") as f:
                lines = f.readlines()
            
            with open(dotenv_path, "w") as f:
                for line in lines:
                    if line.startswith("TELEGRAM_CHAT_ID="):
                        f.write(f"TELEGRAM_CHAT_ID={chat_id}\n")
                    else:
                        f.write(line)
        except Exception:
            pass

    def send_alert(self, message: str, title: str = "🚨 LOGSENTINEL ALERT"):
        """Sends a markdown formatted alert to the telegram admin."""
        if not self.bot_token or not self.chat_id:
            return False
            
        text = f"*{title}*\n\n{message}"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown"
        }
        try:
            requests.post(f"{self.api_url}/sendMessage", json=payload, timeout=5)
            return True
        except Exception:
            return False

    def send_report(self, report_type: str, total_logs: int, total_alerts: int, critical_count: int, high_count: int):
        """Sends a structured daily/weekly report to Telegram."""
        if not self.bot_token or not self.chat_id:
            return False
            
        text = (
            f"📊 *SECURITY REPORT: {report_type.upper()}*\n"
            f"━━━━━━━━━━━━━━━━━━━\n"
            f"📥 *Logs Processed*: `{total_logs:,}`\n"
            f"⚠️ *Total Alerts*: `{total_alerts}`\n"
            f"🛑 *CRITICAL Events*: `{critical_count}`\n"
            f"🔥 *HIGH Events*: `{high_count}`\n\n"
            f"💡 *Summary*: {(total_alerts/max(total_logs, 1))*100:.2f}% of processed traffic engaged the anomaly detection and threat isolation layers. Action required on {critical_count} critical nodes."
        )
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown"
        }
        try:
            requests.post(f"{self.api_url}/sendMessage", json=payload, timeout=5)
            return True
        except Exception:
            return False

# Easy-to-use singleton
telegram = TelegramAlerter()
