#!/usr/bin/env python3
"""
Render.com specific configuration for CTF application
Optimized for Render's infrastructure and requirements
"""

import os
import secrets
from datetime import timedelta

class RenderConfig:
    """Configuration optimized for Render.com deployment"""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    DEBUG = False
    TESTING = False
    
    # Server Configuration
    PORT = int(os.environ.get('PORT', '10000'))
    HOST = '0.0.0.0'
    
    # Security Configuration
    WTF_CSRF_ENABLED = os.environ.get('WTF_CSRF_ENABLED', '1').lower() in ('1', 'true', 'yes')
    WTF_CSRF_TIME_LIMIT = int(os.environ.get('WTF_CSRF_TIME_LIMIT', '3600'))
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', '1').lower() in ('1', 'true', 'yes')
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=int(os.environ.get('SESSION_LIFETIME', '86400')))
    
    # Database Configuration for Render PostgreSQL
    DATABASE_URL = os.environ.get('DATABASE_URL')
    if DATABASE_URL:
        # Render provides PostgreSQL URLs that need to be converted for SQLAlchemy
        if DATABASE_URL.startswith('postgres://'):
            DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql+psycopg://', 1)
        elif DATABASE_URL.startswith('postgresql://'):
            DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgresql+psycopg://', 1)
    else:
        # Fallback for local development
        DATABASE_URL = 'sqlite:///instance/ctf.sqlite'
    
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = False
    
    # Render-optimized database engine options
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,           # Reduced for Render's connection limits
        'pool_recycle': 300,       # 5 minutes
        'pool_pre_ping': True,
        'max_overflow': 20,        # Reduced overflow
        'pool_timeout': 10,
        'echo': False,
        'connect_args': {
            'connect_timeout': 10,
            'application_name': 'ctf_app_render'
        }
    }
    
    # Email Configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', '1').lower() in ('1', 'true', 'yes')
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or os.environ.get('MAIL_USERNAME')
    MAIL_SUPPRESS_SEND = os.environ.get('MAIL_SUPPRESS_SEND', '0').lower() in ('1', 'true', 'yes')
    
    # File Upload Configuration (Render disk storage)
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_UPLOAD_MB', '16')) * 1024 * 1024
    UPLOAD_FOLDER = '/app/uploads'  # Render disk mount path
    
    # Logging Configuration for Render
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    
    # Performance Configuration for Render
    COMPRESS_MIMETYPES = [
        'text/html', 'text/css', 'text/xml', 'text/javascript',
        'application/json', 'application/javascript', 'application/xml+rss',
        'application/atom+xml', 'image/svg+xml'
    ]
    COMPRESS_LEVEL = int(os.environ.get('COMPRESS_LEVEL', '6'))
    COMPRESS_MIN_SIZE = int(os.environ.get('COMPRESS_MIN_SIZE', '500'))
    
    # Admin Configuration
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL')
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
    
    # Backup Configuration
    BACKUP_ENABLED = os.environ.get('BACKUP_ENABLED', '1').lower() in ('1', 'true', 'yes')
    
    # Render-specific optimizations
    RENDER_EXTERNAL_HOSTNAME = os.environ.get('RENDER_EXTERNAL_HOSTNAME')
    RENDER_SERVICE_NAME = os.environ.get('RENDER_SERVICE_NAME')
    RENDER_GIT_COMMIT = os.environ.get('RENDER_GIT_COMMIT')
    
    @staticmethod
    def validate_render_config():
        """Validate Render-specific configuration"""
        required_vars = ['DATABASE_URL']
        
        missing_vars = []
        for var in required_vars:
            if not os.environ.get(var):
                missing_vars.append(var)
        
        if missing_vars:
            print(f"⚠️ Missing environment variables: {', '.join(missing_vars)}")
            return False
        
        return True
    
    @staticmethod
    def get_render_info():
        """Get Render deployment information"""
        return {
            'service_name': os.environ.get('RENDER_SERVICE_NAME', 'Unknown'),
            'external_hostname': os.environ.get('RENDER_EXTERNAL_HOSTNAME', 'Unknown'),
            'git_commit': os.environ.get('RENDER_GIT_COMMIT', 'Unknown'),
            'region': 'oregon',  # Default region
            'plan': 'starter'    # Default plan
        }

def setup_render_logging(app):
    """Setup logging optimized for Render.com"""
    import logging
    
    # Render captures stdout/stderr automatically
    logging.basicConfig(
        level=getattr(logging, app.config.get('LOG_LEVEL', 'INFO')),
        format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]',
        handlers=[logging.StreamHandler()]
    )
    
    app.logger.setLevel(getattr(logging, app.config.get('LOG_LEVEL', 'INFO')))
    app.logger.info('CTF Application starting on Render.com')
    
    # Log Render deployment info
    render_info = RenderConfig.get_render_info()
    app.logger.info(f"Render Service: {render_info['service_name']}")
    app.logger.info(f"Hostname: {render_info['external_hostname']}")
    app.logger.info(f"Git Commit: {render_info['git_commit']}")

def setup_render_health_checks(app):
    """Setup health checks optimized for Render"""
    from flask import jsonify
    from datetime import datetime
    
    @app.route('/health')
    def render_health_check():
        """Render-optimized health check endpoint"""
        try:
            from CTF_GAME import db
            
            # Test database connection
            db.session.execute(db.text('SELECT 1'))
            
            render_info = RenderConfig.get_render_info()
            
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'version': '1.0.0',
                'database': 'connected',
                'render_service': render_info['service_name'],
                'hostname': render_info['external_hostname'],
                'git_commit': render_info['git_commit'][:8] if render_info['git_commit'] != 'Unknown' else 'Unknown'
            }), 200
            
        except Exception as e:
            app.logger.error(f'Health check failed: {e}')
            return jsonify({
                'status': 'unhealthy',
                'timestamp': datetime.utcnow().isoformat(),
                'error': str(e),
                'render_service': render_info.get('service_name', 'Unknown')
            }), 503
    
    @app.route('/render-info')
    def render_info_endpoint():
        """Render deployment information endpoint"""
        return jsonify(RenderConfig.get_render_info())

def optimize_for_render(app):
    """Apply Render-specific optimizations"""
    
    # Setup logging
    setup_render_logging(app)
    
    # Setup health checks
    setup_render_health_checks(app)
    
    # Optimize for Render's infrastructure
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 31536000  # 1 year for static files
    
    # Add Render-specific headers
    @app.after_request
    def add_render_headers(response):
        response.headers['X-Render-Service'] = os.environ.get('RENDER_SERVICE_NAME', 'ctf-game')
        response.headers['X-Git-Commit'] = os.environ.get('RENDER_GIT_COMMIT', 'unknown')[:8]
        return response
    
    app.logger.info('Render.com optimizations applied')

# Export the configuration
Config = RenderConfig
