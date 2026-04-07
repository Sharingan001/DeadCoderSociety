import json
import os
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

# Add core paths to parse logs
current_dir = Path(__file__).parent
project_root = current_dir.parent.parent
sys.path.insert(0, str(project_root / "src" / "cli"))
sys.path.insert(0, str(project_root / "src" / "engines"))

# Import from the plain CLI to use its parser locally
try:
    from logsentinel_cli_plain import LogParser, ThreatAnalyzer
except ImportError:
    pass

PORT = 8080

class LogSentinelGUIHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Serve files from the GUI directory
        super().__init__(*args, directory=str(current_dir), **kwargs)

    def do_GET(self):
        if self.path == '/api/logs':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            # Read real logs
            try:
                target_log = project_root / "test_threats.log"
                if not target_log.exists():
                    target_log = project_root / "sample.log"
                
                real_logs = []
                analyzer = ThreatAnalyzer()
                
                with open(str(target_log), 'r') as f:
                    for i, line in enumerate(f):
                        # Use the real LogSentinel parser
                        event = LogParser.parse_line(line)
                        if event:
                            threats = analyzer.process_event(event)
                            
                            # Determine risk based on threats detected by the real engine
                            status = "INFO"
                            cve = None
                            if threats:
                                highest_sev = "LOW"
                                for t in threats:
                                    if t['severity'] == 'CRITICAL': highest_sev = 'CRITICAL'
                                    elif t['severity'] == 'HIGH' and highest_sev != 'CRITICAL': highest_sev = 'ERROR'
                                    elif t['severity'] == 'MEDIUM' and highest_sev not in ['CRITICAL', 'ERROR']: highest_sev = 'WARN'
                                    if "CVE-" in t.get("message", "") or "CVE-" in t.get("type", ""):
                                        cve = t.get("type")
                                status = highest_sev
                                
                            real_logs.append({
                                "id": f"real-log-{i}",
                                "timestamp": event.get("timestamp", ""),
                                "status": status,
                                "thread": f"pid-{event.get('pid', 'sys')}",
                                "message": event.get("message", ""),
                                "ip": event.get("hostname", "local"),
                                "cve": cve if cve else ("DETECTED" if threats else None),
                                "process": event.get("process", ""),
                                "raw": event.get("raw", "")
                            })
                
                self.wfile.write(json.dumps(real_logs).encode())
            except Exception as e:
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return
            
        return super().do_GET()

def run_server():
    print(f"\n[+] Starting LogSentinel Pro Web GUI Server on http://localhost:{PORT}")
    print(f"[+] Serving directory: {current_dir}")
    print("[+] Press Ctrl+C to stop...")
    httpd = HTTPServer(('', PORT), LogSentinelGUIHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[-] Shutting down server.")
        httpd.server_close()

if __name__ == '__main__':
    run_server()
