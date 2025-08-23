#!/usr/bin/env python3
"""
WSGI entry point for CTF Game application - Render auto-detection version
"""

import os
import sys
import traceback

print("=== APP.PY STARTING ===")
print(f"Python version: {sys.version}")
print(f"Working directory: {os.getcwd()}")

# Check DATABASE_URL
database_url = os.environ.get('DATABASE_URL')
print(f"DATABASE_URL set: {bool(database_url)}")
if database_url:
    print(f"DATABASE_URL preview: {database_url[:50]}...")
else:
    print("WARNING: DATABASE_URL not set - will use SQLite fallback")

try:
    print("Importing CTF_GAME...")
    from CTF_GAME import app, db
    print("Successfully imported CTF_GAME components")

    # Create database tables if they don't exist
    def create_tables():
        """Create database tables if they don't exist"""
        try:
            with app.app_context():
                print("Creating database tables...")
                print(f"Database URI: {app.config.get('SQLALCHEMY_DATABASE_URI', 'Not set')[:100]}...")

                # Import models to ensure they're registered
                from models import User, Challenge, Solve, Team, Tournament

                # Test database connection first
                try:
                    result = db.session.execute(db.text('SELECT 1'))
                    result.close()
                    print("Database connection successful")
                except Exception as conn_error:
                    print(f"Database connection failed: {conn_error}")
                    return False

                db.create_all()
                print("Database tables created successfully")
                return True
        except Exception as e:
            print(f"Error creating database tables: {e}")
            traceback.print_exc()
            return False

    # Initialize database on startup
    print("Initializing database...")
    db_success = create_tables()
    if not db_success:
        print("WARNING: Database initialization failed - app may not work correctly")

    # Configure Flask app for production
    app.config['DEBUG'] = False
    app.config['TESTING'] = False

    # Override any problematic configurations
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for now

    print("CTF_GAME loaded successfully")

    # Add a route to show database status
    @app.route('/database-status')
    def database_status():
        from flask import jsonify
        return jsonify({
            'database_url_set': bool(os.environ.get('DATABASE_URL')),
            'database_url_preview': os.environ.get('DATABASE_URL', 'Not set')[:50] + '...' if os.environ.get('DATABASE_URL') else 'Not set',
            'database_uri': app.config.get('SQLALCHEMY_DATABASE_URI', 'Not set')[:100] + '...',
            'database_initialized': db_success,
            'instructions': 'If DATABASE_URL is not set, you need to manually configure the database in Render dashboard'
        })

except Exception as e:
    print(f"Failed to load CTF_GAME: {e}")
    traceback.print_exc()
    # Create a fallback app
    from flask import Flask, jsonify
    app = Flask(__name__)

    @app.route('/')
    def fallback():
        return f"""
        <h1>CTF Game - Database Configuration Issue</h1>
        <p><strong>Error:</strong> {str(e)}</p>
        <p><strong>DATABASE_URL set:</strong> {bool(os.environ.get('DATABASE_URL'))}</p>

        <h2>To Fix This Issue:</h2>
        <ol>
            <li>Go to your Render dashboard</li>
            <li>Navigate to your ctf-game service</li>
            <li>Go to Environment tab</li>
            <li>Manually add DATABASE_URL environment variable</li>
            <li>Get the connection string from your PostgreSQL database</li>
        </ol>

        <p><a href="/database-status">Check Database Status</a></p>
        """

    @app.route('/database-status')
    def fallback_status():
        return jsonify({
            'error': 'Main app failed to load',
            'database_url_set': bool(os.environ.get('DATABASE_URL')),
            'message': str(e)
        })

# This is what gunicorn will use
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
