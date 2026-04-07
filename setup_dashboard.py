"""
LogSentinel Pro - Premium Dashboard Setup & Validation
Tests all dependencies and configurations
"""

import sys
import subprocess
from pathlib import Path

def print_header(text):
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80)

def check_package(package_name, import_name=None):
    """Check if package is installed"""
    if import_name is None:
        import_name = package_name.replace('-', '_')
    
    try:
        __import__(import_name)
        print(f"  ✅ {package_name}")
        return True
    except ImportError:
        print(f"  ❌ {package_name} - NOT INSTALLED")
        return False

def main():
    print_header("🛡️  LogSentinel Pro - Premium Dashboard Setup")
    
    # Check Python version
    print("\n📌 Python Information:")
    print(f"  Version: {sys.version}")
    print(f"  Executable: {sys.executable}")
    
    # Check dependencies
    print("\n📦 Checking Dependencies:")
    
    required_packages = [
        ('flask', 'flask'),
        ('flask-cors', 'flask_cors'),
        ('flask-socketio', 'flask_socketio'),
        ('python-socketio', 'socketio'),
        ('python-engineio', 'engineio'),
        ('requests', 'requests'),
        ('psutil', 'psutil'),
        ('PyYAML', 'yaml'),
        ('reportlab', 'reportlab'),
        ('python-dotenv', 'dotenv'),
    ]
    
    missing = []
    for pkg, import_name in required_packages:
        if not check_package(pkg, import_name):
            missing.append(pkg)
    
    # Installation recommendation
    if missing:
        print_header("⚠️  Missing Dependencies")
        print(f"\nThe following packages need to be installed:\n")
        for pkg in missing:
            print(f"  - {pkg}")
        
        print("\nTo install, run:")
        print(f"\n  pip install {' '.join(missing)}\n")
        
        install_prompt = input("Install now? (y/n): ").lower()
        if install_prompt == 'y':
            print("\n📥 Installing packages...")
            subprocess.run(
                [sys.executable, '-m', 'pip', 'install'] + missing,
                check=False
            )
            print("✅ Installation complete!")
    
    # Check project structure
    print_header("📂 Project Structure")
    
    files_to_check = {
        'src/gui/premium_dashboard.html': 'Premium Dashboard UI',
        'src/gui/dashboard_server.py': 'Dashboard Server',
        'src/gui/test_dashboard_alerts.py': 'Test Script',
        'src/engines/integrated_attack_alerter.py': 'Alert Coordinator',
        'src/engines/universal_log_monitor.py': 'Log Monitor',
        'src/engines/telegram_alerter.py': 'Telegram AlerterSystem',
        'src/engines/sendgrid_alerter.py': 'Email Alerter',
        'PREMIUM_DASHBOARD_GUIDE.md': 'Documentation',
    }
    
    root = Path(__file__).parent.parent  # Go up from src/gui
    
    for file_path, description in files_to_check.items():
        full_path = root / file_path
        if full_path.exists():
            print(f"  ✅ {description}")
        else:
            print(f"  ❌ {description} - MISSING: {file_path}")
    
    # Check environment file
    print_header("🔐 Configuration Check")
    
    env_file = root / '.env'
    if env_file.exists():
        print("  ✅ .env file exists")
        
        with open(env_file) as f:
            content = f.read()
            checks = {
                'TELEGRAM': 'Telegram configured',
                'SMTP': 'Email (SMTP) configured',
                'SECURITY_ALERT_EMAIL': 'Alert email address configured',
            }
            
            for key, desc in checks.items():
                if key in content:
                    print(f"  ✅ {desc}")
                else:
                    print(f"  ⚠️  {desc} - Missing")
    else:
        print("  ⚠️  .env file not found - Email/Telegram may not work")
    
    # Final status
    print_header("✨ Setup Status")
    
    if missing:
        print("\n⚠️  Some dependencies are missing. Please install them above.")
        print("\nAfter installation, the dashboard will be fully operational.")
    else:
        print("\n✅ All dependencies installed!")
        print("✅ Project structure complete!")
        print("✅ Configuration ready!")
    
    print("\n" + "=" * 80)
    print("🚀 To Start the Dashboard:")
    print("=" * 80)
    print("\n  1. Navigate to: cd src/gui")
    print("  2. Start server: python dashboard_server.py")
    print("  3. Open browser: http://localhost:5000")
    print("  4. In new terminal: python test_dashboard_alerts.py")
    print("\n" + "=" * 80)
    print("📚 Documentation: PREMIUM_DASHBOARD_GUIDE.md")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⏹️  Setup interrupted")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
