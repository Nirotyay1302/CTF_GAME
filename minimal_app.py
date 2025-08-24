#!/usr/bin/env python3
"""
Minimal Flask app to test basic deployment
"""

from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return """
    <h1>🎯 HUNTING-CTF - Working!</h1>
    <p>✅ Application is working!</p>
    <ul>
        <li><a href="/challenges">Challenges</a></li>
        <li><a href="/dashboard">Dashboard</a></li>
        <li><a href="/api/test">API Test</a></li>
    </ul>
    """

@app.route('/challenges')
def challenges():
    return """
    <h1>🎯 Challenges</h1>
    <p>✅ Challenges route is working!</p>
    <p>The enhanced challenges system is ready!</p>
    <a href="/">← Back to Home</a>
    """

@app.route('/dashboard')
def dashboard():
    return """
    <h1>📊 Dashboard</h1>
    <p>✅ Dashboard route is working!</p>
    <p>The enhanced dashboard is ready!</p>
    <a href="/">← Back to Home</a>
    """

@app.route('/api/test')
def api_test():
    from flask import jsonify
    return jsonify({
        'success': True,
        'message': 'API is working!',
        'status': 'ready'
    })

@app.route('/health')
def health():
    return "OK"

# This is what gunicorn will use
application = app

if __name__ == "__main__":
    import os
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
