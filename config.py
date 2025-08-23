import os
import secrets
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    DEBUG = os.environ.get('FLASK_DEBUG', '0').lower() in ('1', 'true', 'yes')
    PORT = int(os.environ.get('PORT', os.environ.get('FLASK_RUN_PORT', '5000')))

    # Security Configuration
    WTF_CSRF_ENABLED = os.environ.get('WTF_CSRF_ENABLED', '1').lower() in ('1', 'true', 'yes')
    WTF_CSRF_TIME_LIMIT = int(os.environ.get('WTF_CSRF_TIME_LIMIT', '3600'))
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', '0').lower() in ('1', 'true', 'yes')
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = int(os.environ.get('SESSION_LIFETIME', '86400'))  # 24 hours
    
    # Database Configuration
    # Build database URI
    DATABASE_URL = os.environ.get('DATABASE_URL')
    if not DATABASE_URL:
        # Check if MySQL environment variables are set
        mysql_user = os.environ.get('MYSQL_USER')
        mysql_password = os.environ.get('MYSQL_PASSWORD')
        mysql_host = os.environ.get('MYSQL_HOST')
        mysql_db = os.environ.get('MYSQL_DB')

        if all([mysql_user, mysql_password, mysql_host, mysql_db]):
            # Use MySQL if all credentials are provided
            DATABASE_URL = f'mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}/{mysql_db}'
        else:
            # Use SQLite for local development
            DATABASE_URL = 'sqlite:///instance/ctf.sqlite'
    else:
        # Handle PostgreSQL URL from Render and configure for psycopg3
        if DATABASE_URL.startswith('postgres://'):
            DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql+psycopg://', 1)
        elif DATABASE_URL.startswith('postgresql://'):
            DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgresql+psycopg://', 1)

    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {'pool_pre_ping': True}
    
    # File Upload Configuration
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_UPLOAD_MB', '10')) * 1024 * 1024
    
    # Email Configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() in ('1', 'true', 'yes')
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False').lower() in ('1', 'true', 'yes')
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or os.environ.get('MAIL_USERNAME')
    MAIL_SUPPRESS_SEND = os.environ.get('MAIL_SUPPRESS_SEND', '0').lower() in ('1', 'true', 'yes')
    MAIL_MAX_EMAILS = int(os.environ.get('MAIL_MAX_EMAILS', '0') or 0) or None
    
    
