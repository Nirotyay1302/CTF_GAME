#!/usr/bin/env python3
"""
HUNTING-CTF Application Entry Point
Clean, modern CTF application with all features integrated
"""

import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=== HUNTING-CTF STARTING ===")
print(f"Python version: {sys.version}")
print(f"Working directory: {os.getcwd()}")

# Import the main application
try:
    from main import app, socketio
    print("✅ Main CTF application loaded successfully!")

    # Check if SocketIO is available
    if socketio:
        print("✅ SocketIO support enabled")
    else:
        print("⚠️ SocketIO not available, using standard Flask")

except Exception as e:
    print(f"❌ Failed to load main application: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("✅ HUNTING-CTF ready to serve!")

if __name__ == '__main__':
    # Run the application
    port = int(os.environ.get('PORT', 5000))
    debug = not os.environ.get('DATABASE_URL')  # Debug mode only in development

    if socketio:
        socketio.run(app, host='0.0.0.0', port=port, debug=debug)
    else:
        app.run(host='0.0.0.0', port=port, debug=debug)
