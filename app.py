#!/usr/bin/env python3
"""
WSGI entry point for CTF Game application
This file is used by gunicorn and other WSGI servers
"""

import os
from CTF_GAME import app, db

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

# This is what gunicorn will use
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
