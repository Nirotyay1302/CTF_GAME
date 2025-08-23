#!/usr/bin/env python3
"""
Simple WSGI entry point for CTF Game application
This version uses threading mode instead of async workers for better compatibility
"""

import os
from CTF_GAME import app, db, socketio

# Create database tables if they don't exist
def create_tables():
    """Create database tables if they don't exist"""
    try:
        with app.app_context():
            print("Creating database tables...")
            db.create_all()
            print("Database tables created successfully")
    except Exception as e:
        print(f"Error creating database tables: {e}")

# Initialize database on startup
create_tables()

# Configure SocketIO for threading mode (more compatible)
socketio.init_app(app, 
                  cors_allowed_origins="*", 
                  async_mode='threading',
                  logger=True, 
                  engineio_logger=True)

# This is what gunicorn will use
application = app

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
