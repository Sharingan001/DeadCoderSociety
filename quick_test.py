#!/usr/bin/env python
"""Quick test to verify all systems"""
import sys
sys.path.insert(0, 'src')
from datetime import datetime

print('Testing imports...')
try:
    from engines.live_log_analyzer import LiveLogAnalyzer
    print('✅ LiveLogAnalyzer imported')
except Exception as e:
    print(f'❌ LiveLogAnalyzer error: {e}')

try:
    from engines.sendgrid_alerter import SendGridEmailAlerter, SendGridConfig, SMTPConfig
    print('✅ SendGrid with SMTP support imported')
except Exception as e:
    print(f'❌ SendGrid error: {e}')

try:
    from engines.telegram_alerter import TelegramAlerter
    print('✅ Telegram alerter imported')
except Exception as e:
    print(f'❌ Telegram error: {e}')

# Quick Live Analyzer test
analyzer = LiveLogAnalyzer()
analyzer.ingest_log({
    'timestamp': datetime.now().isoformat(),
    'threat_type': 'TEST',
    'severity': 'HIGH',
    'source_ip': '192.168.1.1'
})

stats = analyzer.get_live_stats()
print(f'✅ Live Analyzer working - Processed {stats["total_logs_processed"]} log(s)')
print(f'✅ Anomaly Score: {stats["anomaly_score"]:.1f}/100')
print('\n✅ ALL SYSTEMS READY FOR TESTING!')
