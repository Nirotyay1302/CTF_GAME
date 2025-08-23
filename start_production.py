#!/usr/bin/env python3
"""
Production startup script for CTF Game application
Optimized for cloud hosting platforms like Render
"""

import os
import sys
from CTF_GAME import app, db, socketio

def create_tables():
    """Create database tables if they don't exist"""
    try:
        with app.app_context():
            print("Creating database tables...")
            db.create_all()
            print("Database tables created successfully")
    except Exception as e:
        print(f"Error creating database tables: {e}")
        sys.exit(1)

def main():
    """Main entry point for production deployment"""
    try:
        print("Starting CTF Game application in production mode...")
        
        # Create database tables
        create_tables()
        
        # Get port from environment (Render sets this automatically)
        port = int(os.environ.get('PORT', 10000))
        
        print(f"Starting server on port {port}...")
        
        # Use socketio.run for production with proper configuration
        socketio.run(
            app,
            host='0.0.0.0',
            port=port,
            debug=False,
            use_reloader=False,
            log_output=True
        )
        
    except Exception as e:
        print(f"Error starting application: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
