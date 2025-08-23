#!/usr/bin/env python3
"""
Minimal Flask app to test basic deployment
"""

from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello from Render! Flask is working."

@app.route('/health')
def health():
    return "OK"

# This is what gunicorn will use
application = app

if __name__ == "__main__":
    import os
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
