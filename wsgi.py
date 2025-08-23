#!/usr/bin/env python3
"""
Simple WSGI entry point for CTF Game application
This version uses threading mode instead of async workers for better compatibility
"""

import os
import sys
import traceback

try:
    from CTF_GAME import app, db, socketio
    print("Successfully imported CTF_GAME components")
except Exception as e:
    print(f"Error importing CTF_GAME: {e}")
    traceback.print_exc()
    sys.exit(1)

# Create database tables if they don't exist
def create_tables():
    """Create database tables if they don't exist"""
    try:
        with app.app_context():
            print("Creating database tables...")
            db.create_all()
            print("Database tables created successfully")
            return True
    except Exception as e:
        print(f"Error creating database tables: {e}")
        traceback.print_exc()
        return False

# Initialize database on startup
print("Initializing database...")
if not create_tables():
    print("Warning: Database initialization failed, but continuing...")

# Configure Flask app for production
app.config['DEBUG'] = False
app.config['TESTING'] = False

# Add a simple health check route
@app.route('/health')
def health_check():
    return {'status': 'healthy', 'message': 'CTF Game is running'}, 200

# This is what gunicorn will use
application = app

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    print(f"Starting application on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
