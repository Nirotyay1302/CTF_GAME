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

    # Test PostgreSQL drivers before importing
    database_url = os.environ.get('DATABASE_URL', '')
    if 'postgresql' in database_url:
        print("Testing PostgreSQL drivers...")
        try:
            import psycopg
            print("psycopg (v3) available")
        except ImportError:
            print("psycopg (v3) not available")

        try:
            import psycopg2
            print("psycopg2 available")
        except ImportError:
            print("psycopg2 not available")

    print("🚀 Loading working CTF application...")

    # Use minimal app as the working base
    try:
        from minimal_app import app
        print("✅ Minimal app loaded successfully")

        # Add the enhanced challenges route directly
        from flask import render_template, request, jsonify

        # Override the existing challenges route with enhanced version
        @app.route('/challenges/enhanced')
        def challenges_enhanced():
            return render_template('challenges.html',
                                 challenges=[],
                                 solved_ids=set(),
                                 categories=['web', 'crypto', 'pwn', 'reverse', 'forensics', 'misc'],
                                 difficulties=['easy', 'medium', 'hard', 'expert'],
                                 category_info={},
                                 difficulty_info={},
                                 category_filter='',
                                 difficulty_filter='',
                                 search_query='',
                                 solved_filter='',
                                 total_challenges=0,
                                 solved_count=0,
                                 total_points=0)

        @app.route('/dashboard/modern')
        def dashboard_modern():
            return render_template('dashboard_modern.html')

        @app.route('/api/dashboard/stats')
        def api_dashboard_stats():
            return jsonify({
                'success': True,
                'username': 'Demo User',
                'user_score': 1337,
                'challenges_solved': 15,
                'total_challenges': 50,
                'total_users': 100,
                'user_rank': 5
            })

        @app.route('/api/challenges/categories')
        def api_challenge_categories():
            return jsonify({
                'success': True,
                'categories': {
                    'web': {'name': 'Web Security', 'icon': 'fas fa-globe', 'color': '#3b82f6'},
                    'crypto': {'name': 'Cryptography', 'icon': 'fas fa-lock', 'color': '#8b5cf6'},
                    'pwn': {'name': 'Binary Exploitation', 'icon': 'fas fa-bug', 'color': '#ef4444'},
                    'reverse': {'name': 'Reverse Engineering', 'icon': 'fas fa-undo', 'color': '#f59e0b'},
                    'forensics': {'name': 'Digital Forensics', 'icon': 'fas fa-search', 'color': '#10b981'},
                    'misc': {'name': 'Miscellaneous', 'icon': 'fas fa-puzzle-piece', 'color': '#06b6d4'}
                },
                'difficulties': {
                    'easy': {'name': 'Easy', 'icon': 'fas fa-star', 'color': '#22c55e'},
                    'medium': {'name': 'Medium', 'icon': 'fas fa-star-half-alt', 'color': '#f59e0b'},
                    'hard': {'name': 'Hard', 'icon': 'fas fa-fire', 'color': '#ef4444'},
                    'expert': {'name': 'Expert', 'icon': 'fas fa-crown', 'color': '#8b5cf6'}
                }
            })

        print("✅ Enhanced routes added successfully")
        db = None  # No database needed for demo

    except Exception as e:
        print(f"❌ Failed to load enhanced app: {e}")
        import traceback
        traceback.print_exc()

        # Emergency fallback
        from flask import Flask
        app = Flask(__name__)

        @app.route('/')
        def emergency():
            return f"""
            <h1>🚨 CTF Game - Emergency Mode</h1>
            <p>Error: {str(e)}</p>
            <p>The application is in emergency mode but the enhanced features are ready to deploy.</p>
            """

        db = None

    print("Successfully loaded application components")

    # Demo mode - no database setup needed

    # For demo mode, we don't need database initialization
    print("✅ Running in demo mode - no database setup needed")

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
        error_msg = str(e) if 'e' in locals() else 'Unknown error during CTF_GAME import'
        return f"""
        <h1>CTF Game - Import Error</h1>
        <p><strong>Error:</strong> {error_msg}</p>
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
        error_msg = str(e) if 'e' in locals() else 'Unknown error during CTF_GAME import'
        return jsonify({
            'error': 'Main app failed to load',
            'database_url_set': bool(os.environ.get('DATABASE_URL')),
            'message': error_msg
        })

# This is what gunicorn will use
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
