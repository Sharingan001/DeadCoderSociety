@echo off
REM ============================================================================
REM LogSentinel Pro - Premium Dashboard Server Startup
REM ============================================================================

echo.
echo =============================================================
echo 🛡️  LogSentinel Pro - Premium Dashboard
echo =============================================================
echo.

REM Install required dependencies
echo Installing dependencies...
pip install flask flask-cors flask-socketio python-socketio python-engineio -q

echo.
echo ✅ Starting Premium Dashboard Server...
echo.
echo 🌐 Dashboard URL: http://localhost:5000
echo 📊 WebSocket: ws://localhost:5000/socket.io
echo.
echo 💡 To test attacks, open another terminal and run:
echo    cd src\gui
echo    python test_dashboard_alerts.py
echo.
echo =============================================================
echo.

REM Start the server
python dashboard_server.py

pause
