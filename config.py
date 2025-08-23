import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_super_secret_key_change_this_in_production'
    DEBUG = os.environ.get('FLASK_DEBUG', '0').lower() in ('1', 'true', 'yes')
    PORT = int(os.environ.get('PORT', os.environ.get('FLASK_RUN_PORT', '5000')))
    
    # Database Configuration
    MYSQL_USER = os.environ.get('MYSQL_USER', 'ctfuser')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'ctfpass123')
    MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
    MYSQL_DB = os.environ.get('MYSQL_DB', 'ctfdb')
    
    # Build database URI
    DATABASE_URL = os.environ.get('DATABASE_URL')
    if not DATABASE_URL:
        # Use SQLite for local development
        DATABASE_URL = 'sqlite:///instance/ctf.sqlite'
    else:
        # Handle PostgreSQL URL from Render (fix postgres:// to postgresql://)
        if DATABASE_URL.startswith('postgres://'):
            DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

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
    
    
