#!/usr/bin/env python3
"""
Ultra-simple diagnostic app to identify deployment issues
"""

import os
import sys
import traceback
from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route('/')
def home():
    return f"""
    <h1>CTF Game Diagnostic</h1>
    <p><strong>Status:</strong> Flask is working!</p>
    <p><strong>Python:</strong> {sys.version}</p>
    <p><strong>Working Dir:</strong> {os.getcwd()}</p>
    
    <h2>Test Endpoints:</h2>
    <ul>
        <li><a href="/env">Environment Variables</a></li>
        <li><a href="/files">File System</a></li>
        <li><a href="/imports">Test Imports</a></li>
        <li><a href="/database">Database Test</a></li>
        <li><a href="/error-test">Trigger Error</a></li>
    </ul>
    """

@app.route('/env')
def show_env():
    env_vars = {}
    for key, value in os.environ.items():
        if 'SECRET' in key or 'PASSWORD' in key or 'KEY' in key:
            env_vars[key] = '[HIDDEN]'
        elif 'DATABASE_URL' in key:
            env_vars[key] = value[:50] + '...' if len(value) > 50 else value
        else:
            env_vars[key] = value
    
    return jsonify({
        'environment_variables': env_vars,
        'total_vars': len(os.environ)
    })

@app.route('/files')
def show_files():
    try:
        files = []
        for item in os.listdir('.'):
            if os.path.isfile(item):
                files.append(f"FILE: {item}")
            else:
                files.append(f"DIR: {item}")
        
        return jsonify({
            'current_directory': os.getcwd(),
            'contents': files[:20],  # First 20 items
            'total_items': len(files)
        })
    except Exception as e:
        return jsonify({'error': str(e), 'traceback': traceback.format_exc()})

@app.route('/imports')
def test_imports():
    results = {}
    
    # Test basic imports
    imports_to_test = [
        'flask',
        'flask_sqlalchemy', 
        'flask_socketio',
        'psycopg2',
        'pymysql',
        'cryptography',
        'gunicorn'
    ]
    
    for module_name in imports_to_test:
        try:
            module = __import__(module_name)
            results[module_name] = f"OK - {getattr(module, '__version__', 'version unknown')}"
        except ImportError as e:
            results[module_name] = f"IMPORT ERROR - {str(e)}"
        except Exception as e:
            results[module_name] = f"OTHER ERROR - {str(e)}"
    
    # Test our app imports
    try:
        import config
        results['config.py'] = "OK"
    except Exception as e:
        results['config.py'] = f"ERROR - {str(e)}"
    
    try:
        import models
        results['models.py'] = "OK"
    except Exception as e:
        results['models.py'] = f"ERROR - {str(e)}"
    
    try:
        import CTF_GAME
        results['CTF_GAME.py'] = "OK"
    except Exception as e:
        results['CTF_GAME.py'] = f"ERROR - {str(e)}"
    
    return jsonify(results)

@app.route('/database')
def test_database():
    try:
        database_url = os.environ.get('DATABASE_URL')
        
        if not database_url:
            return jsonify({
                'status': 'ERROR',
                'message': 'DATABASE_URL not set',
                'database_url': None
            })
        
        # Test basic connection
        if database_url.startswith('postgres'):
            try:
                import psycopg2
                # Parse URL manually for testing
                return jsonify({
                    'status': 'DATABASE_URL_SET',
                    'database_type': 'PostgreSQL',
                    'url_preview': database_url[:50] + '...',
                    'psycopg2_available': True
                })
            except ImportError:
                return jsonify({
                    'status': 'ERROR',
                    'message': 'psycopg2 not available',
                    'database_type': 'PostgreSQL',
                    'url_preview': database_url[:50] + '...'
                })
        else:
            return jsonify({
                'status': 'UNKNOWN_DB_TYPE',
                'database_url': database_url[:50] + '...'
            })
            
    except Exception as e:
        return jsonify({
            'status': 'ERROR',
            'error': str(e),
            'traceback': traceback.format_exc()
        })

@app.route('/error-test')
def error_test():
    # Intentionally trigger an error to test error handling
    raise Exception("This is a test error to verify error handling works")

@app.errorhandler(500)
def handle_500(e):
    return jsonify({
        'error': 'Internal Server Error',
        'message': str(e),
        'traceback': traceback.format_exc()
    }), 500

@app.errorhandler(Exception)
def handle_exception(e):
    return jsonify({
        'error': 'Unhandled Exception',
        'message': str(e),
        'traceback': traceback.format_exc()
    }), 500

# This is what gunicorn will use
application = app

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=True)
