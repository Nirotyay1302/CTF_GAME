#!/usr/bin/env python3
"""
Production configuration for CTF application
"""

import os
import secrets
from datetime import timedelta

class ProductionConfig:
    """Production configuration class"""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    DEBUG = False
    TESTING = False
    
    # Server Configuration
    PORT = int(os.environ.get('PORT', '8000'))
    HOST = os.environ.get('HOST', '0.0.0.0')
    
    # Security Configuration
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # Database Configuration
    DATABASE_URL = os.environ.get('DATABASE_URL')
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable is required for production")
    
    # Handle different database URL formats
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql+psycopg://', 1)
    elif DATABASE_URL.startswith('postgresql://'):
        DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgresql+psycopg://', 1)
    
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 20,
        'pool_recycle': 300,
        'pool_pre_ping': True,
        'max_overflow': 30,
        'pool_timeout': 10,
        'echo': False
    }
    
    # Email Configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or os.environ.get('MAIL_USERNAME')
    MAIL_SUPPRESS_SEND = False
    MAIL_MAX_EMAILS = None
    
    # File Upload Configuration
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/app/uploads')
    
    # Redis Configuration (for caching and sessions)
    REDIS_URL = os.environ.get('REDIS_URL')
    if REDIS_URL:
        SESSION_TYPE = 'redis'
        SESSION_REDIS = REDIS_URL
        SESSION_PERMANENT = False
        SESSION_USE_SIGNER = True
        SESSION_KEY_PREFIX = 'ctf:'
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', '/app/logs/ctf.log')
    
    # Performance Configuration
    COMPRESS_MIMETYPES = [
        'text/html', 'text/css', 'text/xml', 'text/javascript',
        'application/json', 'application/javascript', 'application/xml+rss',
        'application/atom+xml', 'image/svg+xml'
    ]
    COMPRESS_LEVEL = 6
    COMPRESS_MIN_SIZE = 500
    
    # Security Headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
    }
    
    # Rate Limiting Configuration
    RATELIMIT_STORAGE_URL = REDIS_URL or 'memory://'
    RATELIMIT_DEFAULT = "100 per hour"
    RATELIMIT_HEADERS_ENABLED = True
    
    # Admin Configuration
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL')
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    
    # Monitoring Configuration
    SENTRY_DSN = os.environ.get('SENTRY_DSN')
    
    # Backup Configuration
    BACKUP_ENABLED = os.environ.get('BACKUP_ENABLED', '1').lower() in ('1', 'true', 'yes')
    BACKUP_SCHEDULE = os.environ.get('BACKUP_SCHEDULE', '0 2 * * *')  # Daily at 2 AM
    BACKUP_RETENTION_DAYS = int(os.environ.get('BACKUP_RETENTION_DAYS', '30'))
    
    @staticmethod
    def validate_config():
        """Validate production configuration"""
        required_vars = [
            'SECRET_KEY',
            'DATABASE_URL',
            'MAIL_USERNAME',
            'MAIL_PASSWORD'
        ]
        
        missing_vars = []
        for var in required_vars:
            if not os.environ.get(var):
                missing_vars.append(var)
        
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
        
        return True

class DevelopmentConfig:
    """Development configuration class"""
    
    # Flask Configuration
    SECRET_KEY = 'dev-secret-key-change-in-production'
    DEBUG = True
    TESTING = False
    
    # Server Configuration
    PORT = int(os.environ.get('PORT', '5000'))
    HOST = '127.0.0.1'
    
    # Security Configuration (relaxed for development)
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Database Configuration
    DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///instance/ctf_dev.sqlite')
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True  # Enable SQL logging in development
    
    # Email Configuration (disabled in development)
    MAIL_SUPPRESS_SEND = True
    MAIL_SERVER = 'localhost'
    MAIL_PORT = 25
    MAIL_USE_TLS = False
    MAIL_USE_SSL = False
    
    # File Upload Configuration
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    UPLOAD_FOLDER = 'instance/uploads'
    
    # Logging Configuration
    LOG_LEVEL = 'DEBUG'
    
    # Performance Configuration (disabled for development)
    COMPRESS_MIMETYPES = []

class TestingConfig:
    """Testing configuration class"""
    
    # Flask Configuration
    SECRET_KEY = 'test-secret-key'
    DEBUG = False
    TESTING = True
    
    # Database Configuration (in-memory SQLite)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security Configuration (disabled for testing)
    WTF_CSRF_ENABLED = False
    
    # Email Configuration (disabled for testing)
    MAIL_SUPPRESS_SEND = True
    
    # Disable rate limiting for testing
    RATELIMIT_ENABLED = False

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])

def setup_logging(app):
    """Setup logging for the application"""
    import logging
    from logging.handlers import RotatingFileHandler
    
    if not app.debug:
        # Create logs directory if it doesn't exist
        log_dir = os.path.dirname(app.config.get('LOG_FILE', 'logs/ctf.log'))
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Setup file handler
        file_handler = RotatingFileHandler(
            app.config.get('LOG_FILE', 'logs/ctf.log'),
            maxBytes=10240000,  # 10MB
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        
        app.logger.setLevel(logging.INFO)
        app.logger.info('CTF Application startup')

def setup_monitoring(app):
    """Setup monitoring and error tracking"""
    sentry_dsn = app.config.get('SENTRY_DSN')
    if sentry_dsn:
        try:
            import sentry_sdk
            from sentry_sdk.integrations.flask import FlaskIntegration
            from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
            
            sentry_sdk.init(
                dsn=sentry_dsn,
                integrations=[
                    FlaskIntegration(),
                    SqlalchemyIntegration()
                ],
                traces_sample_rate=0.1,
                environment=os.environ.get('FLASK_ENV', 'production')
            )
            app.logger.info('Sentry monitoring initialized')
        except ImportError:
            app.logger.warning('Sentry SDK not installed - monitoring disabled')
