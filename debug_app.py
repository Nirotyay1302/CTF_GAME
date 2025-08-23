#!/usr/bin/env python3
"""
Debug version of the CTF app to isolate issues
"""

import os
import sys
import traceback
from flask import Flask, jsonify

# Create a minimal Flask app first
debug_app = Flask(__name__)

@debug_app.route('/')
def home():
    return jsonify({
        'status': 'Flask is working',
        'python_version': sys.version,
        'environment_vars': {
            'DATABASE_URL': 'SET' if os.environ.get('DATABASE_URL') else 'NOT SET',
            'SECRET_KEY': 'SET' if os.environ.get('SECRET_KEY') else 'NOT SET',
            'PORT': os.environ.get('PORT', 'NOT SET')
        }
    })

@debug_app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'message': 'Debug app is running'})

@debug_app.route('/test-imports')
def test_imports():
    results = {}
    
    # Test basic imports
    try:
        import flask
        results['flask'] = f'OK - {flask.__version__}'
    except Exception as e:
        results['flask'] = f'ERROR - {str(e)}'
    
    try:
        import flask_sqlalchemy
        results['flask_sqlalchemy'] = f'OK - {flask_sqlalchemy.__version__}'
    except Exception as e:
        results['flask_sqlalchemy'] = f'ERROR - {str(e)}'
    
    try:
        import flask_socketio
        results['flask_socketio'] = f'OK - {flask_socketio.__version__}'
    except Exception as e:
        results['flask_socketio'] = f'ERROR - {str(e)}'
    
    # Test database drivers
    try:
        import psycopg2
        results['psycopg2'] = f'OK - {psycopg2.__version__}'
    except Exception as e:
        results['psycopg2'] = f'ERROR - {str(e)}'
    
    try:
        import pymysql
        results['pymysql'] = f'OK - {pymysql.__version__}'
    except Exception as e:
        results['pymysql'] = f'ERROR - {str(e)}'
    
    return jsonify(results)

@debug_app.route('/test-config')
def test_config():
    try:
        from config import Config
        return jsonify({
            'config_import': 'OK',
            'database_url': Config.DATABASE_URL[:50] + '...' if Config.DATABASE_URL else 'None',
            'secret_key_set': bool(Config.SECRET_KEY),
            'debug_mode': Config.DEBUG
        })
    except Exception as e:
        return jsonify({
            'config_import': f'ERROR - {str(e)}',
            'traceback': traceback.format_exc()
        })

@debug_app.route('/test-models')
def test_models():
    try:
        from models import db, User, Challenge
        return jsonify({
            'models_import': 'OK',
            'db_object': str(type(db)),
            'user_model': str(User),
            'challenge_model': str(Challenge)
        })
    except Exception as e:
        return jsonify({
            'models_import': f'ERROR - {str(e)}',
            'traceback': traceback.format_exc()
        })

@debug_app.route('/test-main-app')
def test_main_app():
    try:
        from CTF_GAME import app
        return jsonify({
            'main_app_import': 'OK',
            'app_name': app.name,
            'app_config': dict(app.config)
        })
    except Exception as e:
        return jsonify({
            'main_app_import': f'ERROR - {str(e)}',
            'traceback': traceback.format_exc()
        })

# This is what gunicorn will use
application = debug_app

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    debug_app.run(host='0.0.0.0', port=port, debug=True)
