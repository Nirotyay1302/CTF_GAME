#!/usr/bin/env python3
"""
WSGI entry point for CTF Game application with robust error handling
"""

import os
import sys
import traceback
from flask import Flask, jsonify

# Create a fallback app in case main app fails
fallback_app = Flask(__name__)

@fallback_app.route('/')
def fallback_home():
    return """
    <h1>CTF Game Debug Mode</h1>
    <p>Main app failed to load. Check these endpoints:</p>
    <ul>
        <li><a href="/health">/health</a> - Health check</li>
        <li><a href="/debug">/debug</a> - Debug information</li>
        <li><a href="/test-db">/test-db</a> - Test database</li>
    </ul>
    """

@fallback_app.route('/health')
def fallback_health():
    return jsonify({'status': 'fallback', 'message': 'Main app failed to load'}), 500

@fallback_app.route('/debug')
def fallback_debug():
    return jsonify({
        'python_version': sys.version,
        'environment': dict(os.environ),
        'sys_path': sys.path[:5],  # First 5 entries
        'working_directory': os.getcwd()
    })

@fallback_app.route('/test-db')
def fallback_test_db():
    try:
        database_url = os.environ.get('DATABASE_URL', 'Not set')
        return jsonify({
            'database_url_set': bool(database_url),
            'database_url_preview': database_url[:50] + '...' if database_url else 'None'
        })
    except Exception as e:
        return jsonify({'error': str(e), 'traceback': traceback.format_exc()})

try:
    print("=== STARTING CTF_GAME IMPORT ===")
    print(f"Python version: {sys.version}")
    print(f"Working directory: {os.getcwd()}")
    print(f"DATABASE_URL set: {bool(os.environ.get('DATABASE_URL'))}")

    print("Importing CTF_GAME...")
    from CTF_GAME import app, db
    print("Successfully imported CTF_GAME components")

    # Create database tables if they don't exist
    def create_tables():
        """Create database tables if they don't exist"""
        try:
            with app.app_context():
                print("Creating database tables...")
                # Import models to ensure they're registered
                from models import User, Challenge, Solve, Team, Tournament
                db.create_all()
                print("Database tables created successfully")
                return True
        except Exception as e:
            print(f"Error creating database tables: {e}")
            traceback.print_exc()
            return False

    # Initialize database on startup
    print("Initializing database...")
    create_tables()

    # Configure Flask app for production
    app.config['DEBUG'] = False
    app.config['TESTING'] = False

    # Override any problematic configurations
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for now

    # Add error handlers
    @app.errorhandler(500)
    def handle_500(e):
        print(f"500 Error: {e}")
        traceback.print_exc()
        return "Internal Server Error - Check logs for details", 500

    @app.errorhandler(Exception)
    def handle_exception(e):
        print(f"Unhandled Exception: {e}")
        traceback.print_exc()
        return "An error occurred - Check logs for details", 500

    # Add a health check route
    @app.route('/health')
    def health_check():
        try:
            # Test database connection
            with app.app_context():
                result = db.session.execute(db.text('SELECT 1'))
                result.close()
            return jsonify({'status': 'healthy', 'message': 'CTF Game is running', 'database': 'connected'}), 200
        except Exception as e:
            return jsonify({'status': 'unhealthy', 'message': str(e), 'database': 'disconnected', 'traceback': traceback.format_exc()}), 500

    @app.route('/debug')
    def debug_info():
        return jsonify({
            'status': 'main_app_loaded',
            'database_url_set': bool(os.environ.get('DATABASE_URL')),
            'secret_key_set': bool(app.config.get('SECRET_KEY')),
            'config_debug': app.config.get('DEBUG'),
            'python_version': sys.version
        })

    print("CTF_GAME loaded successfully")
    application = app

except Exception as e:
    print(f"Failed to load CTF_GAME: {e}")
    traceback.print_exc()
    print("Using fallback application")
    application = fallback_app

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    print(f"Starting application on port {port}")
    application.run(host='0.0.0.0', port=port, debug=False)
