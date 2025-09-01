"""
HUNTING-CTF - Modern Capture The Flag Platform
A clean, modern, and fully functional CTF application
"""

import os
import secrets
import hashlib
import time
import sys
import platform
import flask
import sqlalchemy
from datetime import datetime, timedelta
from functools import wraps
from threading import Thread
from dotenv import load_dotenv
# Load environment variables from a .env file if present
load_dotenv()

# Try to import psutil for system monitoring
try:
    import psutil
except ImportError:
    pass

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from sqlalchemy.sql import func
from sqlalchemy import text

# Import SocketIO with error handling
try:
    from flask_socketio import SocketIO, emit, join_room, leave_room
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False
    SocketIO = None

# Import models and extensions
from models import (
    db, User, Challenge, Solve, Submission, Team, TeamMembership,
    Tournament, Hint, UserHint, Notification, ChatMessage, Friend
)
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask_compress import Compress

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')

# Database configuration with psycopg3 support
database_url = os.environ.get('DATABASE_URL', 'sqlite:///ctf.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql+psycopg://', 1)
elif database_url.startswith('postgresql://'):
    database_url = database_url.replace('postgresql://', 'postgresql+psycopg://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

# Initialize extensions
db.init_app(app)

# Email configuration

def _env_bool(val, default=False):
    if val is None:
        return default
    if isinstance(val, (bool, int)):
        return bool(val)
    return str(val).strip().lower() in ('true', '1', 't', 'yes', 'y', 'on')

def _clean_app_password(pwd: str) -> str:
    # Gmail app passwords are displayed with spaces for readability; remove them
    return (pwd or '').replace(' ', '').strip()

app.config['MAIL_SERVER'] = (os.environ.get('MAIL_SERVER') or 'smtp.gmail.com').strip()
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = _env_bool(os.environ.get('MAIL_USE_TLS', True), True)
app.config['MAIL_USE_SSL'] = _env_bool(os.environ.get('MAIL_USE_SSL', False), False)
app.config['MAIL_SUPPRESS_SEND'] = _env_bool(os.environ.get('MAIL_SUPPRESS_SEND', False), False)
app.config['MAIL_USERNAME'] = (os.environ.get('MAIL_USERNAME') or '').strip()
app.config['MAIL_PASSWORD'] = _clean_app_password(os.environ.get('MAIL_PASSWORD'))
_default_sender = os.environ.get('MAIL_DEFAULT_SENDER') or app.config['MAIL_USERNAME']
app.config['MAIL_DEFAULT_SENDER'] = _default_sender.strip()
app.config['NOTIFICATION_EMAIL'] = (os.environ.get('ADMIN_EMAIL') or '').strip() or app.config['MAIL_USERNAME']

# If both TLS and SSL were set, prefer TLS on port 587
if app.config['MAIL_USE_TLS'] and app.config['MAIL_USE_SSL']:
    app.config['MAIL_USE_SSL'] = False

# Email notification settings
app.config['EMAIL_ON_LOGIN'] = os.environ.get('EMAIL_ON_LOGIN', 'True').lower() in ('true', '1', 't')
app.config['EMAIL_ON_LOGOUT'] = os.environ.get('EMAIL_ON_LOGOUT', 'True').lower() in ('true', '1', 't')
app.config['EMAIL_NEW_USER'] = os.environ.get('EMAIL_NEW_USER', 'True').lower() in ('true', '1', 't')
app.config['EMAIL_CHALLENGE_SOLVED'] = os.environ.get('EMAIL_CHALLENGE_SOLVED', 'True').lower() in ('true', '1', 't')
app.config['EMAIL_TEAM_CREATED'] = os.environ.get('EMAIL_TEAM_CREATED', 'True').lower() in ('true', '1', 't')

# Add custom Jinja2 filters
def nl2br(value):
    """Convert newlines to HTML line breaks"""
    if value is None:
        return ''
    return value.replace('\n', '<br>\n')

app.jinja_env.filters['nl2br'] = nl2br
migrate = Migrate(app, db)
mail = Mail(app)
compress = Compress(app)

# Initialize SocketIO if available
if SOCKETIO_AVAILABLE:
    socketio = SocketIO(app, cors_allowed_origins="*")
else:
    socketio = None

# Encryption for flags
# Prefer FERNET_KEY from .env, fallback to ENCRYPTION_KEY, then persistent key file under instance/

def _load_encryption_key():
    key = os.environ.get('FERNET_KEY') or os.environ.get('ENCRYPTION_KEY')
    if key:
        # If key is a string, ensure bytes
        if isinstance(key, str):
            try:
                return key.encode()
            except Exception:
                pass
        return key

    # Fallback: persistent key file in instance/fernet.key
    instance_dir = os.path.join(app.root_path, 'instance')
    os.makedirs(instance_dir, exist_ok=True)
    key_path = os.path.join(instance_dir, 'fernet.key')
    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            return f.read()

    # Generate and persist a new key if none exists
    new_key = Fernet.generate_key()
    try:
        with open(key_path, 'wb') as f:
            f.write(new_key)
    except OSError:
        # If we cannot persist, still return the generated key
        pass
    return new_key

ENCRYPTION_KEY = _load_encryption_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Supabase configuration

def _sb_config():
    return {
        'url': os.environ.get('SUPABASE_URL'),
        'service_key': os.environ.get('SUPABASE_SERVICE_ROLE_KEY') or os.environ.get('SUPABASE_KEY'),
        'bucket': os.environ.get('SUPABASE_BUCKET'),
        'public_base': os.environ.get('SUPABASE_PUBLIC_BASE_URL'),
    }


def _sb_enabled():
    cfg = _sb_config()
    return bool(cfg['url'] and cfg['service_key'] and cfg['bucket'])


def _get_supabase_client():
    if not _sb_enabled():
        return None
    from supabase import create_client
    cfg = _sb_config()
    return create_client(cfg['url'], cfg['service_key'])

# Cloudflare R2 / S3-compatible storage helpers

def _r2_config():
    return {
        'endpoint': os.environ.get('R2_ENDPOINT'),
        'access_key': os.environ.get('R2_ACCESS_KEY_ID'),
        'secret_key': os.environ.get('R2_SECRET_ACCESS_KEY'),
        'bucket': os.environ.get('R2_BUCKET'),
        'public_base': os.environ.get('R2_PUBLIC_BASE_URL'),
    }


def _r2_enabled():
    cfg = _r2_config()
    return bool(cfg['endpoint'] and cfg['access_key'] and cfg['secret_key'] and cfg['bucket'])


def _get_s3_client():
    if not _r2_enabled():
        return None
    import boto3
    cfg = _r2_config()
    return boto3.client(
        's3',
        endpoint_url=cfg['endpoint'],
        aws_access_key_id=cfg['access_key'],
        aws_secret_access_key=cfg['secret_key']
    )

# Helper functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        user = db.session.get(User, session['user_id'])
        if not user or user.role != 'admin':
            flash('Admin privileges required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    if 'user_id' in session:
        return db.session.get(User, session['user_id'])
    return None

def encrypt_flag(flag):
    return cipher_suite.encrypt(flag.encode())

def decrypt_flag(encrypted_flag):
    try:
        return cipher_suite.decrypt(encrypted_flag).decode()
    except:
        return None

def validate_flag(submitted_flag, challenge):
    try:
        # Try to decrypt first (for production encrypted flags)
        actual_flag = decrypt_flag(challenge.flag_encrypted)
        if actual_flag:
            return submitted_flag.strip() == actual_flag.strip()
    except:
        pass

    try:
        # Fallback: try simple decode (for development)
        actual_flag = challenge.flag_encrypted.decode() if isinstance(challenge.flag_encrypted, bytes) else challenge.flag_encrypted
        return submitted_flag.strip() == actual_flag.strip()
    except:
        return False

def calculate_user_score(user_id):
    total = db.session.query(func.sum(Challenge.points)).join(Solve).filter(
        Solve.user_id == user_id
    ).scalar()
    return total or 0

def get_user_rank(user_id):
    user_score = calculate_user_score(user_id)
    higher_scores = db.session.query(func.count(func.distinct(User.id))).join(Solve).join(Challenge).group_by(User.id).having(
        func.sum(Challenge.points) > user_score
    ).scalar()
    return (higher_scores or 0) + 1

def send_email(subject, recipients, body, html=None):
    """Send email using Flask-Mail with retries and proper checks"""
    import smtplib
    if not app.config.get('MAIL_SERVER') or not app.config.get('MAIL_PORT'):
        app.logger.warning('Email not sent: MAIL_SERVER/MAIL_PORT not configured')
        return False
    if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
        app.logger.warning('Email not sent: MAIL_USERNAME/MAIL_PASSWORD not configured')
        return False
    if app.config.get('MAIL_SUPPRESS_SEND'):
        app.logger.info('MAIL_SUPPRESS_SEND enabled, skipping actual email send')
        return True

    # Normalize recipients list
    if isinstance(recipients, str):
        recipients = [recipients]

    msg = Message(
        subject or 'Notification',
        recipients=recipients,
        sender=app.config.get('MAIL_DEFAULT_SENDER') or app.config.get('MAIL_USERNAME')
    )
    msg.body = body or ''
    if html:
        msg.html = html

    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        try:
            if flask.has_app_context():
                with mail.connect() as conn:
                    conn.send(msg)
            else:
                with app.app_context():
                    with mail.connect() as conn:
                        conn.send(msg)
            return True
        except smtplib.SMTPAuthenticationError as e:
            app.logger.error(f'SMTP auth error: {e}')
            break  # no point retrying on bad credentials
        except (smtplib.SMTPServerDisconnected, smtplib.SMTPException, OSError) as e:
            app.logger.error(f'Email send attempt {attempt}/{max_attempts} failed: {e}')
            time.sleep(min(2 ** attempt, 8))
        except Exception as e:
            app.logger.error(f'Unexpected email error: {e}')
            time.sleep(min(2 ** attempt, 8))
    return False

# Context processors
@app.context_processor
def inject_user():
    return dict(current_user=get_current_user())

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = db.session.get(User, user_id) if user_id else None

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

# Routes
@app.route('/')
def index():
    """Home page with statistics"""
    user = get_current_user()

    # Get basic stats with error handling
    try:
        total_challenges = Challenge.query.count()
        total_users = User.query.filter(User.role != 'admin', User.is_player == True).count()
    except Exception as e:
        print(f"Database query error: {e}")
        total_challenges = 0
        total_users = 0

    if user:
        try:
            user_solves = Solve.query.filter_by(user_id=user.id).count()
            user_score = calculate_user_score(user.id)
            user_rank = get_user_rank(user.id)

            # Get recent solves
            recent_solves = db.session.query(Solve, Challenge).join(Challenge).filter(
                Solve.user_id == user.id
            ).order_by(Solve.solved_at.desc()).limit(5).all()
        except Exception as e:
            print(f"User stats error: {e}")
            user_solves = 0
            user_score = 0
            user_rank = 0
            recent_solves = []
    else:
        user_solves = 0
        user_score = 0
        user_rank = 0
        recent_solves = []

    return render_template('index.html',
                         total_challenges=total_challenges,
                         total_users=total_users,
                         user_solves=user_solves,
                         user_score=user_score,
                         user_rank=user_rank,
                         recent_solves=recent_solves)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('auth/register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('auth/register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('auth/register.html')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('auth/register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('auth/register.html')
        
        # Create new user
        try:
            user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                role='user'
            )
            db.session.add(user)
            db.session.commit()

            # Send welcome email on registration
            if user.email:
                subject = "HUNTING-CTF: Welcome to the platform"
                body = f"Hello {user.username},\n\nYour account has been created successfully.\nStart solving challenges and climb the leaderboard!\n\nRegards,\nThe HUNTING-CTF Team"
                html = f"""
                <h2>Welcome to HUNTING-CTF</h2>
                <p>Hello {user.username},</p>
                <p>Your account has been created successfully.</p>
                <p>Start solving challenges and climb the leaderboard!</p>
                <p>Regards,<br>The HUNTING-CTF Team</p>
                """
                Thread(target=send_email, args=(subject, [user.email], body, html)).start()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('auth/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('auth/login.html')
        
        # Find user by username or email
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['is_player'] = user.is_player
            
            # Update last login time
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            flash(f'Welcome back, {user.username}!', 'success')
            
            # Send login email notification with stats (always)
            if user.email and user.role == 'user':
                user_score = calculate_user_score(user.id)
                user_rank = get_user_rank(user.id)
                challenges_solved = Solve.query.filter_by(user_id=user.id).count()
                total_challenges = Challenge.query.count()
                
                subject = f"HUNTING-CTF: Login Notification"
                body = f"Hello {user.username},\n\nYou have successfully logged in to your HUNTING-CTF account.\n\nYour current statistics:\n- Score: {user_score}\n- Rank: {user_rank}\n- Challenges solved: {challenges_solved}/{total_challenges}\n\nKeep up the good work!\n\nRegards,\nThe HUNTING-CTF Team"
                
                html = f"""
                <h2>HUNTING-CTF: Login Notification</h2>
                <p>Hello {user.username},</p>
                <p>You have successfully logged in to your HUNTING-CTF account.</p>
                <h3>Your current statistics:</h3>
                <ul>
                    <li><strong>Score:</strong> {user_score}</li>
                    <li><strong>Rank:</strong> {user_rank}</li>
                    <li><strong>Challenges solved:</strong> {challenges_solved}/{total_challenges}</li>
                </ul>
                <p>Keep up the good work!</p>
                <p>Regards,<br>The HUNTING-CTF Team</p>
                """
                
                # Send email in background to avoid delaying the response
                Thread(target=send_email, args=(subject, [user.email], body, html)).start()
            
            # Redirect admin users directly to admin dashboard
            if user.role == 'admin' and not user.is_player:
                flash('You are logged in as an administrator. This is not a player account.', 'info')
                return redirect(url_for('admin_dashboard'))
            
            # Redirect regular users to dashboard
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('auth/login.html')

@app.route('/logout')
def logout():
    """User logout"""
    username = session.get('username', 'User')
    user_id = session.get('user_id')
    user_role = session.get('role')
    user_email = None
    
    # Get user information before clearing session
    if user_id:
        user = User.query.get(user_id)
        if user:
            user_email = user.email
            
            # Send logout email notification with score if enabled
            # Send logout email notification with current game status (always)
            if user_email and user_role == 'user':
                user_score = calculate_user_score(user.id)
                user_rank = get_user_rank(user.id)
                challenges_solved = Solve.query.filter_by(user_id=user.id).count()
                total_challenges = Challenge.query.count()
                
                subject = f"HUNTING-CTF: Logout Notification"
                body = f"Hello {username},\n\nYou have successfully logged out from your HUNTING-CTF account.\n\nYour current statistics:\n- Score: {user_score}\n- Rank: {user_rank}\n- Challenges solved: {challenges_solved}/{total_challenges}\n\nWe hope to see you back soon!\n\nRegards,\nThe HUNTING-CTF Team"
                
                html = f"""
                <h2>HUNTING-CTF: Logout Notification</h2>
                <p>Hello {username},</p>
                <p>You have successfully logged out from your HUNTING-CTF account.</p>
                <h3>Your current statistics:</h3>
                <ul>
                    <li><strong>Score:</strong> {user_score}</li>
                    <li><strong>Rank:</strong> {user_rank}</li>
                    <li><strong>Challenges solved:</strong> {challenges_solved}/{total_challenges}</li>
                </ul>
                <p>We hope to see you back soon!</p>
                <p>Regards,<br>The HUNTING-CTF Team</p>
                """
                
                # Send email in background to avoid delaying the response
                Thread(target=send_email, args=(subject, [user_email], body, html)).start()
    
    session.clear()
    flash(f'Goodbye, {username}!', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    user = get_current_user()

    # Get user statistics
    user_solves = Solve.query.filter_by(user_id=user.id).count()
    user_score = calculate_user_score(user.id)
    user_rank = get_user_rank(user.id)

    # Get recent activity
    recent_solves = db.session.query(Solve, Challenge).join(Challenge).filter(
        Solve.user_id == user.id
    ).order_by(Solve.solved_at.desc()).limit(10).all()

    # Get available challenges by category
    challenges_by_category = {}
    challenges = Challenge.query.all()

    for challenge in challenges:
        category = challenge.category or 'Miscellaneous'
        if category not in challenges_by_category:
            challenges_by_category[category] = []

        # Check if user has solved this challenge
        solved = Solve.query.filter_by(user_id=user.id, challenge_id=challenge.id).first()
        challenge_data = {
            'id': challenge.id,
            'title': challenge.title,
            'points': challenge.points,
            'difficulty': challenge.difficulty,
            'solved': bool(solved),
            'solved_at': solved.solved_at if solved else None
        }
        challenges_by_category[category].append(challenge_data)

    # Get notifications
    notifications = Notification.query.filter_by(
        user_id=user.id, read=False
    ).order_by(Notification.created_at.desc()).limit(5).all()

    return render_template('dashboard.html',
                         user=user,
                         user_solves=user_solves,
                         user_score=user_score,
                         user_rank=user_rank,
                         recent_solves=recent_solves,
                         challenges_by_category=challenges_by_category,
                         notifications=notifications)

@app.route('/challenges')
@login_required
def challenges():
    """Challenges page"""
    user = get_current_user()

    # Prevent admin from accessing challenges as a player
    if user.role == 'admin' and not user.is_player:
        flash('Administrators cannot participate in challenges. Please use the admin panel to manage challenges.', 'warning')
        return redirect(url_for('admin_dashboard'))

    # Read filters from query params
    search_query = request.args.get('search', '').strip()
    category_filter = request.args.get('category', '')
    difficulty_filter = request.args.get('difficulty', '')
    solved_filter = request.args.get('solved', '')  # 'solved' | 'unsolved' | ''

    # Build query
    query = Challenge.query

    if category_filter:
        query = query.filter(func.lower(Challenge.category) == category_filter.lower())
    if difficulty_filter:
        query = query.filter(func.lower(Challenge.difficulty) == difficulty_filter.lower())
    if search_query:
        query = query.filter((Challenge.title.ilike(f"%{search_query}%")) | (Challenge.description.ilike(f"%{search_query}%")))

    # Get user's solves before applying solved filter
    user = get_current_user()
    user_solves = {solve.challenge_id for solve in Solve.query.filter_by(user_id=user.id).all()}

    # Fetch and apply solved filter in-memory for simplicity
    challenges = query.order_by(Challenge.points.asc()).all()
    if solved_filter == 'solved':
        challenges = [c for c in challenges if c.id in user_solves]
    elif solved_filter == 'unsolved':
        challenges = [c for c in challenges if c.id not in user_solves]

    # Get categories and difficulties for filters
    categories = db.session.query(Challenge.category).filter(Challenge.category.isnot(None)).distinct().all()
    categories = sorted({(cat[0] or '').lower() for cat in categories if cat[0]})

    difficulties = ['easy', 'medium', 'hard', 'expert']

    # Calculate additional stats for the template
    total_challenges = Challenge.query.count()
    solved_count = len(user_solves)
    total_points = calculate_user_score(user.id)

    return render_template('challenges.html',
                         challenges=challenges,
                         categories=categories,
                         difficulties=difficulties,
                         category_filter=category_filter,
                         difficulty_filter=difficulty_filter,
                         solved_filter=solved_filter,
                         search_query=search_query,
                         total_challenges=total_challenges,
                         solved_count=solved_count,
                         total_points=total_points,
                         solved_ids=list(user_solves))

@app.route('/challenge/<int:challenge_id>')
@login_required
def challenge_detail(challenge_id):
    """Individual challenge page"""
    challenge = Challenge.query.get_or_404(challenge_id)
    user = get_current_user()

    # Previous and next challenges by ID
    prev_challenge = Challenge.query.filter(Challenge.id < challenge.id).order_by(Challenge.id.desc()).first()
    next_challenge = Challenge.query.filter(Challenge.id > challenge.id).order_by(Challenge.id.asc()).first()

    # Check if user has solved this challenge
    solve = Solve.query.filter_by(user_id=user.id, challenge_id=challenge.id).first()

    # Get hints for this challenge
    hints = Hint.query.filter_by(challenge_id=challenge.id).order_by(Hint.display_order).all()

    # Get user's revealed hints
    revealed_hints = {uh.hint_id for uh in UserHint.query.filter_by(user_id=user.id).all()}

    # Get recent submissions
    recent_submissions = Submission.query.filter_by(
        user_id=user.id, challenge_id=challenge.id
    ).order_by(Submission.submitted_at.desc()).limit(5).all()
    
    # Get friends for chat functionality
    friends = []
    if user:
        friends = db.session.query(User).join(
            Friend, 
            ((Friend.user_id == user.id) & (Friend.friend_id == User.id)) | 
            ((Friend.friend_id == user.id) & (Friend.user_id == User.id))
        ).filter(Friend.status == 'accepted').all()

    return render_template('challenge_detail.html',
                         challenge=challenge,
                         solve=solve,
                         hints=hints,
                         revealed_hints=revealed_hints,
                         recent_submissions=recent_submissions,
                         prev_challenge=prev_challenge,
                         next_challenge=next_challenge,
                         friends=friends,
                         user_team=user.team_membership.team if user and user.team_membership else None)

@app.route('/submit_flag', methods=['POST'])
@login_required
def submit_flag():
    """Submit flag for a challenge"""
    # Support both JSON and form-urlencoded submissions
    if request.is_json:
        data = request.get_json(silent=True) or {}
        challenge_id = data.get('challenge_id')
        submitted_flag = (data.get('flag') or '').strip()
    else:
        challenge_id = request.form.get('challenge_id', type=int)
        submitted_flag = request.form.get('flag', '').strip()

    if not challenge_id or not submitted_flag:
        return jsonify({'success': False, 'message': 'Challenge ID and flag are required.'})

    challenge = Challenge.query.get(challenge_id)
    if not challenge:
        return jsonify({'success': False, 'message': 'Challenge not found.'})

    user = get_current_user()

    # Check if user has already solved this challenge
    existing_solve = Solve.query.filter_by(user_id=user.id, challenge_id=challenge.id).first()
    if existing_solve:
        return jsonify({'success': False, 'message': 'You have already solved this challenge.'})

    # Record submission
    submission = Submission(
        user_id=user.id,
        challenge_id=challenge.id,
        submitted_flag=submitted_flag,
        is_correct=False
    )

    # Validate flag
    is_correct = validate_flag(submitted_flag, challenge)
    submission.is_correct = is_correct

    try:
        db.session.add(submission)

        if is_correct:
            # Create solve record
            solve = Solve(
                user_id=user.id,
                challenge_id=challenge.id,
                solved_at=datetime.utcnow()
            )
            db.session.add(solve)

            # Create notification
            notification = Notification(
                user_id=user.id,
                title='Challenge Solved!',
                message=f'Congratulations! You solved "{challenge.title}" and earned {challenge.points} points.',
                type='success'
            )
            db.session.add(notification)

            db.session.commit()

            return jsonify({
                'success': True,
                'message': f'Correct! You earned {challenge.points} points.',
                'points': challenge.points
            })
        else:
            db.session.commit()
            return jsonify({'success': False, 'message': 'Incorrect flag. Try again!'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred. Please try again.'})

# Fast challenge JSON API
@app.route('/api/fast/challenge/<int:challenge_id>')
@login_required
def api_fast_challenge(challenge_id):
    user = get_current_user()
    challenge = Challenge.query.get_or_404(challenge_id)

    # Check solved
    is_solved = bool(Solve.query.filter_by(user_id=user.id, challenge_id=challenge.id).first())

    # Collect hints with reveal status
    hints = []
    for hint in Hint.query.filter_by(challenge_id=challenge.id).order_by(Hint.display_order).all():
        revealed = bool(UserHint.query.filter_by(user_id=user.id, hint_id=hint.id).first())
        hints.append({
            'id': hint.id,
            'cost': hint.cost,
            'revealed': revealed,
            'text': hint.content if revealed else None
        })

    return jsonify({
        'success': True,
        'challenge': {
            'id': challenge.id,
            'title': challenge.title,
            'description': challenge.description,
            'category': challenge.category,
            'difficulty': challenge.difficulty,
            'points': challenge.points,
            'is_solved': is_solved,
            'hints': hints
        }
    })

# Submit flag for fast challenge UI (by path parameter)
@app.route('/api/submit_flag/<int:challenge_id>', methods=['POST'])
@login_required
def api_submit_flag(challenge_id):
    user = get_current_user()
    challenge = Challenge.query.get_or_404(challenge_id)

    data = request.get_json(silent=True) or {}
    submitted_flag = (data.get('flag') or '').strip()
    if not submitted_flag:
        return jsonify({'success': False, 'error': 'Flag is required'}), 400

    # Already solved?
    if Solve.query.filter_by(user_id=user.id, challenge_id=challenge.id).first():
        return jsonify({'success': False, 'error': 'You have already solved this challenge'}), 400

    # Record submission
    submission = Submission(
        user_id=user.id,
        challenge_id=challenge.id,
        submitted_flag=submitted_flag,
        is_correct=False
    )

    is_correct = validate_flag(submitted_flag, challenge)
    submission.is_correct = is_correct

    try:
        db.session.add(submission)
        if is_correct:
            solve = Solve(user_id=user.id, challenge_id=challenge.id, solved_at=datetime.utcnow())
            db.session.add(solve)
            notification = Notification(
                user_id=user.id,
                title='Challenge Solved!',
                message=f'Congratulations! You solved "{challenge.title}" and earned {challenge.points} points.',
                type='success'
            )
            db.session.add(notification)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Database error'}), 500

    if is_correct:
        return jsonify({'success': True, 'message': 'Correct flag!', 'points': challenge.points})
    else:
        return jsonify({'success': False, 'error': 'Incorrect flag'})

@app.route('/scoreboard')
def scoreboard():
    """Public scoreboard"""
    try:
        # Get filters from request
        time_filter = request.args.get('time', 'all')
        category_filter = request.args.get('category', 'all')

        # Get all users who have solved at least one challenge
        users_data = []
        users_with_solves = db.session.query(User).join(Solve).distinct().all()

        # Also include users without solves for complete leaderboard
        all_users = User.query.filter(User.role != 'admin').all()

        # Determine time window for filtering
        time_from = None
        if time_filter == 'day':
            time_from = datetime.utcnow() - timedelta(days=1)
        elif time_filter == 'week':
            time_from = datetime.utcnow() - timedelta(weeks=1)
        elif time_filter == 'month':
            time_from = datetime.utcnow() - timedelta(days=30)

        for user in all_users:
            # Base solve query for this user with optional filters
            base_query = db.session.query(Solve).join(Challenge).filter(Solve.user_id == user.id)
            if time_from is not None:
                base_query = base_query.filter(Solve.solved_at >= time_from)
            if category_filter != 'all':
                base_query = base_query.filter(func.lower(Challenge.category) == category_filter.lower())

            # Total score within filters
            score_query = db.session.query(func.coalesce(func.sum(Challenge.points), 0)).select_from(Solve).join(Challenge).filter(
                Solve.user_id == user.id
            )
            if time_from is not None:
                score_query = score_query.filter(Solve.solved_at >= time_from)
            if category_filter != 'all':
                score_query = score_query.filter(func.lower(Challenge.category) == category_filter.lower())
            total_score = score_query.scalar() or 0

            # Solve count within filters
            solve_count = base_query.count()

            # Last solve time within filters
            last_solve_query = db.session.query(func.max(Solve.solved_at)).select_from(Solve).join(Challenge).filter(Solve.user_id == user.id)
            if time_from is not None:
                last_solve_query = last_solve_query.filter(Solve.solved_at >= time_from)
            if category_filter != 'all':
                last_solve_query = last_solve_query.filter(func.lower(Challenge.category) == category_filter.lower())
            last_solve = last_solve_query.scalar()

            users_data.append({
                'id': user.id,
                'username': user.username,
                'score': total_score,
                'solve_count': solve_count,
                'last_solve': last_solve,
                'country': getattr(user, 'country', None),
                'is_current_user': 'user_id' in session and user.id == session['user_id']
            })

        # Sort by score descending, then by last solve time ascending (for tiebreaking)
        users_data.sort(key=lambda x: (-x['score'], x['last_solve'] or datetime.min))

        # Compute average across full (filtered) user list BEFORE slicing
        avg_score = sum(u['score'] for u in users_data) / len(users_data) if users_data else 0

        # Add rank to each user
        for i, user in enumerate(users_data, 1):
            user['rank'] = i

        # Limit to top 100 for display
        users_data = users_data[:100]

        # Calculate statistics
        total_users = User.query.filter(User.role != 'admin').count()
        if category_filter != 'all':
            total_challenges = Challenge.query.filter(func.lower(Challenge.category) == category_filter.lower()).count()
        else:
            total_challenges = Challenge.query.count()
        total_solves_query = Solve.query
        if time_from is not None:
            total_solves_query = total_solves_query.filter(Solve.solved_at >= time_from)
        if category_filter != 'all':
            total_solves_query = total_solves_query.join(Challenge).filter(func.lower(Challenge.category) == category_filter.lower())
        total_solves = total_solves_query.count()
        avg_score = avg_score

        # Get categories for filter
        categories = db.session.query(Challenge.category).distinct().all()
        categories = [cat[0] for cat in categories if cat[0]]

        # Get recent solves for activity feed (with filters)
        recent_query = db.session.query(
            Solve.solved_at.label('timestamp'),
            User.username,
            Challenge.title,
            Challenge.points
        ).select_from(Solve).join(User, User.id == Solve.user_id).join(Challenge, Challenge.id == Solve.challenge_id)
        if time_from is not None:
            recent_query = recent_query.filter(Solve.solved_at >= time_from)
        if category_filter != 'all':
            recent_query = recent_query.filter(func.lower(Challenge.category) == category_filter.lower())
        recent_solves = recent_query.filter(User.role != 'admin').order_by(Solve.solved_at.desc()).limit(10).all()

    except Exception as e:
        print(f"Scoreboard error: {e}")
        users_data = []
        total_users = 0
        total_challenges = 0
        total_solves = 0
        avg_score = 0
        categories = []
        recent_solves = []

    return render_template('scoreboard.html',
                         users=users_data,
                         total_users=total_users,
                         total_challenges=total_challenges,
                         total_solves=total_solves,
                         avg_score=avg_score,
                         categories=categories,
                         recent_solves=recent_solves,
                         time_filter=time_filter,
                         category_filter=category_filter)

@app.route('/scoreboard/teams')
def team_scoreboard():
    """Team rankings scoreboard"""
    try:
        # Filters for team scoreboard
        time_filter = request.args.get('time', 'all')
        category_filter = request.args.get('category', 'all')
        time_from = None
        if time_filter == 'day':
            time_from = datetime.utcnow() - timedelta(days=1)
        elif time_filter == 'week':
            time_from = datetime.utcnow() - timedelta(weeks=1)
        elif time_filter == 'month':
            time_from = datetime.utcnow() - timedelta(days=30)

        # Get all teams with their statistics
        teams_data = []
        all_teams = Team.query.all()

        for team in all_teams:
            # Get all team members
            team_members = db.session.query(User).join(TeamMembership).filter(
                TeamMembership.team_id == team.id
            ).all()

            # Calculate team total score
            team_score = 0
            team_solves = 0
            last_solve = None

            for member in team_members:
                # Get member's total score (with filters)
                member_score_query = db.session.query(func.coalesce(func.sum(Challenge.points), 0)).select_from(Solve).join(Challenge).filter(
                    Solve.user_id == member.id
                )
                if time_from is not None:
                    member_score_query = member_score_query.filter(Solve.solved_at >= time_from)
                if category_filter != 'all':
                    member_score_query = member_score_query.filter(func.lower(Challenge.category) == category_filter.lower())
                member_score = member_score_query.scalar() or 0
                team_score += member_score

                # Get member's solve count (with filters)
                member_solves_query = Solve.query.filter_by(user_id=member.id)
                if time_from is not None:
                    member_solves_query = member_solves_query.filter(Solve.solved_at >= time_from)
                if category_filter != 'all':
                    member_solves_query = member_solves_query.join(Challenge).filter(func.lower(Challenge.category) == category_filter.lower())
                member_solves = member_solves_query.count()
                team_solves += member_solves

                # Get member's last solve time (with filters)
                member_last_solve_query = db.session.query(func.max(Solve.solved_at)).select_from(Solve).join(Challenge).filter(
                    Solve.user_id == member.id
                )
                if time_from is not None:
                    member_last_solve_query = member_last_solve_query.filter(Solve.solved_at >= time_from)
                if category_filter != 'all':
                    member_last_solve_query = member_last_solve_query.join(Challenge).filter(func.lower(Challenge.category) == category_filter.lower())
                member_last_solve = member_last_solve_query.scalar()

                if member_last_solve and (not last_solve or member_last_solve > last_solve):
                    last_solve = member_last_solve

            teams_data.append({
                'id': team.id,
                'name': team.name,
                'team_code': team.team_code,
                'member_count': len(team_members),
                'score': team_score,
                'solve_count': team_solves,
                'last_solve': last_solve,
                'created_at': team.created_at,
                'members': [{'username': m.username, 'id': m.id} for m in team_members]
            })

        # Sort teams by score descending, then by last solve time ascending
        teams_data.sort(key=lambda x: (-x['score'], x['last_solve'] or datetime.min))

        # Add rank to each team
        for i, team in enumerate(teams_data, 1):
            team['rank'] = i

        # Calculate statistics
        total_teams = len(teams_data)
        total_team_members = sum(team['member_count'] for team in teams_data)
        avg_team_score = sum(team['score'] for team in teams_data) / len(teams_data) if teams_data else 0
        avg_team_size = total_team_members / total_teams if total_teams > 0 else 0

        # Get recent team activities (team solves)
        recent_team_solves = []
        recent_query = db.session.query(
            Solve.solved_at.label('timestamp'),
            User.username,
            Challenge.title,
            Challenge.points,
            Team.name.label('team_name')
        ).select_from(Solve).join(User, User.id == Solve.user_id).join(Challenge, Challenge.id == Solve.challenge_id).join(TeamMembership, TeamMembership.user_id == User.id)\
         .join(Team, Team.id == TeamMembership.team_id)
        if time_from is not None:
            recent_query = recent_query.filter(Solve.solved_at >= time_from)
        if category_filter != 'all':
            recent_query = recent_query.filter(func.lower(Challenge.category) == category_filter.lower())
        recent_solves = recent_query.filter(User.role != 'admin').order_by(Solve.solved_at.desc()).limit(15).all()

        recent_team_solves = recent_solves

    except Exception as e:
        print(f"Team scoreboard error: {e}")
        teams_data = []
        total_teams = 0
        total_team_members = 0
        avg_team_score = 0
        avg_team_size = 0
        recent_team_solves = []

    return render_template('team_scoreboard.html',
                         teams=teams_data,
                         total_teams=total_teams,
                         total_team_members=total_team_members,
                         avg_team_score=avg_team_score,
                         avg_team_size=avg_team_size,
                         recent_team_solves=recent_team_solves)

@app.route('/purchase_hint', methods=['POST'])
@login_required
def purchase_hint():
    """Purchase a hint for a challenge"""
    # Support both JSON and form-urlencoded submissions
    if request.is_json:
        data = request.get_json(silent=True) or {}
        hint_id = data.get('hint_id')
    else:
        hint_id = request.form.get('hint_id', type=int)
    if not hint_id:
        return jsonify({'success': False, 'message': 'Hint ID is required.'})

    hint = Hint.query.get(hint_id)
    if not hint:
        return jsonify({'success': False, 'message': 'Hint not found.'})

    user = get_current_user()

    # Check if user already purchased this hint
    existing_purchase = UserHint.query.filter_by(user_id=user.id, hint_id=hint.id).first()
    if existing_purchase:
        return jsonify({'success': False, 'message': 'You have already purchased this hint.'})

    # Check if user has enough points
    user_score = calculate_user_score(user.id)
    if user_score < hint.cost:
        return jsonify({'success': False, 'message': f'You need {hint.cost} points to purchase this hint. You have {user_score} points.'})

    try:
        # Create hint purchase record
        purchase = UserHint(
            user_id=user.id,
            hint_id=hint.id,
            purchased_at=datetime.utcnow()
        )
        db.session.add(purchase)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Hint purchased for {hint.cost} points!',
            'hint_content': hint.content,
            'remaining_points': user_score - hint.cost
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error purchasing hint. Please try again.'})

@app.route('/show_answer/<int:challenge_id>')
@login_required
def show_answer(challenge_id):
    """Show answer and explanation for any challenge"""
    user = get_current_user()
    challenge = Challenge.query.get_or_404(challenge_id)

    # Check if user has solved this challenge (optional - for display purposes)
    solve = Solve.query.filter_by(user_id=user.id, challenge_id=challenge.id).first()

    # Get the actual flag
    try:
        actual_flag = decrypt_flag(challenge.flag_encrypted)
        if not actual_flag:
            # Fallback for development
            actual_flag = challenge.flag_encrypted.decode() if isinstance(challenge.flag_encrypted, bytes) else challenge.flag_encrypted
    except:
        actual_flag = "Flag decryption error"

    # Support JSON format for fast challenge UI
    if request.args.get('format') == 'json':
        return jsonify({'success': True, 'answer': actual_flag})

    return render_template('show_answer.html',
                         challenge=challenge,
                         solve=solve,
                         actual_flag=actual_flag)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile page"""
    user = get_current_user()

    if request.method == 'POST':
        # Handle profile updates
        try:
            # Update basic profile info
            if 'first_name' in request.form:
                user.first_name = request.form.get('first_name', '').strip()
            if 'last_name' in request.form:
                user.last_name = request.form.get('last_name', '').strip()
            if 'bio' in request.form:
                user.bio = request.form.get('bio', '').strip()
            if 'country' in request.form:
                user.country = request.form.get('country', '').strip()

            # Handle profile picture upload
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and file.filename:
                    import os
                    import uuid
                    from werkzeug.utils import secure_filename

                    # Generate unique filename
                    filename = secure_filename(file.filename)
                    name, ext = os.path.splitext(filename)
                    unique_filename = f"{name}_{uuid.uuid4().hex[:8]}{ext}"

                    # Try Supabase Storage first if configured, then S3/R2, else local
                    if _sb_enabled():
                        try:
                            supa = _get_supabase_client()
                            cfg = _sb_config()
                            # Read file content for upload
                            file.stream.seek(0)
                            content = file.stream.read()
                            path = unique_filename
                            res = supa.storage.from_(cfg['bucket']).upload(path, content, {
                                'contentType': file.mimetype,
                                'upsert': True
                            })
                            # Store object key
                            user.profile_picture = path
                        except Exception:
                            # Fall through to next options
                            pass

                    if not user.profile_picture:
                        if _r2_enabled():
                            try:
                                s3 = _get_s3_client()
                                cfg = _r2_config()
                                # Reset stream before reuse
                                file.stream.seek(0)
                                s3.upload_fileobj(
                                    file.stream,
                                    cfg['bucket'],
                                    unique_filename,
                                    ExtraArgs={'ContentType': file.mimetype}
                                )
                                user.profile_picture = unique_filename
                            except Exception:
                                pass

                    if not user.profile_picture:
                        # Local save (development or no object storage configured)
                        uploads_dir = os.path.join(app.root_path, 'static', 'uploads')
                        os.makedirs(uploads_dir, exist_ok=True)
                        file_path = os.path.join(uploads_dir, unique_filename)
                        file.save(file_path)
                        user.profile_picture = unique_filename

            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))

        except Exception as e:
            db.session.rollback()
            flash('Error updating profile. Please try again.', 'error')
            print(f"Profile update error: {e}")

    # Get user statistics
    user_score = calculate_user_score(user.id)
    user_rank = get_user_rank(user.id)
    solve_count = Solve.query.filter_by(user_id=user.id).count()

    # Get solve history
    solve_history = db.session.query(Solve, Challenge).join(Challenge).filter(
        Solve.user_id == user.id
    ).order_by(Solve.solved_at.desc()).all()

    # Get category breakdown
    category_stats = db.session.query(
        Challenge.category,
        func.count(Solve.id).label('count'),
        func.sum(Challenge.points).label('points')
    ).join(Solve).filter(Solve.user_id == user.id).group_by(Challenge.category).all()

    return render_template('profile.html',
                         user=user,
                         user_score=user_score,
                         user_rank=user_rank,
                         solve_count=solve_count,
                         solve_history=solve_history,
                         category_stats=category_stats)

@app.route('/profile_picture/<filename>')
def profile_picture(filename):
    """Serve profile pictures from object storage if configured, else local uploads"""
    import os
    from flask import send_from_directory

    # Supabase public or signed URL
    try:
        if _sb_enabled():
            cfg = _sb_config()
            supa = _get_supabase_client()
            if cfg['public_base']:
                base = cfg['public_base'].rstrip('/')
                return redirect(f"{base}/{filename}")
            # Signed URL fallback
            signed = supa.storage.from_(cfg['bucket']).create_signed_url(filename, 3600)
            if signed and isinstance(signed, dict) and signed.get('signedURL'):
                return redirect(signed['signedURL'])
    except Exception:
        pass

    # If R2/S3 is configured, redirect to public URL or a presigned URL
    try:
        if _r2_enabled():
            cfg = _r2_config()
            if cfg['public_base']:
                base = cfg['public_base'].rstrip('/')
                return redirect(f"{base}/{filename}")
            else:
                s3 = _get_s3_client()
                url = s3.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': cfg['bucket'], 'Key': filename},
                    ExpiresIn=3600
                )
                return redirect(url)
    except Exception:
        pass

    # Fallback: serve from local uploads directory
    uploads_dir = os.path.join(app.root_path, 'static', 'uploads')
    file_path = os.path.join(uploads_dir, filename)
    if os.path.exists(file_path):
        return send_from_directory(uploads_dir, filename)
    else:
        # Fallback to default avatar
        return redirect(url_for('static', filename='images/default-avatar.svg'))

@app.route('/admin')
@app.route('/admin_panel')
@admin_required
def admin_dashboard():
    """Admin dashboard with comprehensive overview"""
    try:
        # Get comprehensive statistics
        total_users = User.query.filter(User.role != 'admin').count()
        total_challenges = Challenge.query.count()
        total_teams = Team.query.count()
        total_solves = Solve.query.count()

        # Get recent activity
        recent_users = User.query.filter(User.role != 'admin').order_by(User.created_at.desc()).limit(5).all()
        recent_challenges = Challenge.query.order_by(Challenge.created_at.desc()).limit(5).all()
        recent_solves = db.session.query(
            Solve.solved_at,
            User.username,
            Challenge.title,
            Challenge.points
        ).join(User, Solve.user_id == User.id).join(Challenge, Solve.challenge_id == Challenge.id).order_by(Solve.solved_at.desc()).limit(10).all()

        # Get category statistics
        category_stats = db.session.query(
            Challenge.category,
            func.count(Challenge.id).label('count'),
            func.sum(Challenge.points).label('total_points')
        ).group_by(Challenge.category).all()

        # Get top performers
        top_users = db.session.query(
            User.username,
            func.sum(Challenge.points).label('total_score'),
            func.count(Solve.id).label('solve_count')
        ).join(Solve, User.id == Solve.user_id).join(Challenge, Solve.challenge_id == Challenge.id).filter(User.role != 'admin').group_by(User.id).order_by(func.sum(Challenge.points).desc()).limit(5).all()

        # Get team statistics
        team_stats = db.session.query(
            Team.name,
            func.count(TeamMembership.id).label('member_count')
        ).join(TeamMembership, Team.id == TeamMembership.team_id).group_by(Team.id).order_by(func.count(TeamMembership.id).desc()).limit(5).all()

    except Exception as e:
        print(f"Admin dashboard error: {e}")
        total_users = total_challenges = total_teams = total_solves = 0
        recent_users = recent_challenges = recent_solves = category_stats = top_users = team_stats = []

    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_challenges=total_challenges,
                         total_teams=total_teams,
                         total_solves=total_solves,
                         recent_users=recent_users,
                         recent_challenges=recent_challenges,
                         recent_solves=recent_solves,
                         category_stats=category_stats,
                         top_users=top_users,
                         team_stats=team_stats)

@app.route('/admin/users')
@admin_required
def admin_users():
    """Admin users management"""
    users = User.query.filter(User.role != 'admin').order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/create', methods=['GET', 'POST'])
@admin_required
def admin_create_user():
    """Admin create a new user"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', 'user').strip().lower()
        is_player = request.form.get('is_player') == 'on'

        if role not in ('user', 'admin'):
            role = 'user'
        if role == 'admin':
            is_player = False

        if not username or not email or not password:
            flash('Username, email, and password are required.', 'error')
            return render_template('admin/create_user.html', form={'username': username, 'email': email, 'role': role, 'is_player': is_player})
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('admin/create_user.html', form={'username': username, 'email': email, 'role': role, 'is_player': is_player})
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('admin/create_user.html', form={'username': username, 'email': email, 'role': role, 'is_player': is_player})

        # Uniqueness checks
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('admin/create_user.html', form={'username': username, 'email': email, 'role': role, 'is_player': is_player})
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('admin/create_user.html', form={'username': username, 'email': email, 'role': role, 'is_player': is_player})

        try:
            new_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                role=role,
                is_player=is_player
            )
            db.session.add(new_user)
            db.session.commit()

            # Optional welcome email
            if new_user.email:
                subject = "HUNTING-CTF: Your account has been created"
                body = f"Hello {new_user.username},\n\nAn account has been created for you on HUNTING-CTF.\nYou can now log in and start solving challenges.\n\nRegards,\nThe HUNTING-CTF Team"
                html = f"""
                <h2>HUNTING-CTF Account Created</h2>
                <p>Hello {new_user.username},</p>
                <p>An account has been created for you on HUNTING-CTF.</p>
                <p>You can now log in and start solving challenges.</p>
                <p>Regards,<br>The HUNTING-CTF Team</p>
                """
                Thread(target=send_email, args=(subject, [new_user.email], body, html)).start()

            flash(f'User "{username}" created successfully.', 'success')
            return redirect(url_for('admin_users'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating user. Please try again.', 'error')

    return render_template('admin/create_user.html')

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Delete a user"""
    user = User.query.get_or_404(user_id)

    if user.role == 'admin':
        flash('Cannot delete admin users.', 'error')
        return redirect(url_for('admin_users'))

    try:
        # Delete user's solves
        Solve.query.filter_by(user_id=user.id).delete()

        # Delete user's team memberships
        TeamMembership.query.filter_by(user_id=user.id).delete()

        # Delete the user
        db.session.delete(user)
        db.session.commit()

        flash(f'User "{user.username}" has been deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting user. Please try again.', 'error')

    return redirect(url_for('admin_users'))

@app.route('/admin/teams')
@admin_required
def admin_teams():
    """Admin teams management"""
    teams = Team.query.order_by(Team.created_at.desc()).all()
    team_data = []

    for team in teams:
        member_count = TeamMembership.query.filter_by(team_id=team.id).count()
        team_score = 0

        # Calculate team score
        team_members = db.session.query(User).join(TeamMembership).filter(
            TeamMembership.team_id == team.id
        ).all()

        for member in team_members:
            member_score = db.session.query(func.sum(Challenge.points)).join(Solve).filter(
                Solve.user_id == member.id
            ).scalar() or 0
            team_score += member_score

        team_data.append({
            'team': team,
            'member_count': member_count,
            'score': team_score,
            'members': team_members
        })

    return render_template('admin/teams.html', team_data=team_data)

@app.route('/admin/teams/delete/<int:team_id>', methods=['POST'])
@admin_required
def admin_delete_team(team_id):
    """Delete a team"""
    team = Team.query.get_or_404(team_id)

    try:
        # Delete team memberships
        TeamMembership.query.filter_by(team_id=team.id).delete()

        # Delete the team
        db.session.delete(team)
        db.session.commit()

        flash(f'Team "{team.name}" has been deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting team. Please try again.', 'error')

    return redirect(url_for('admin_teams'))

@app.route('/admin/challenges')
@admin_required
def admin_challenges():
    """Admin challenges management"""
    challenges = Challenge.query.filter(Challenge.is_template != True).order_by(Challenge.created_at.desc()).all()

    # Get challenge statistics
    challenge_stats = []
    for challenge in challenges:
        solve_count = Solve.query.filter_by(challenge_id=challenge.id).count()
        challenge_stats.append({
            'challenge': challenge,
            'solve_count': solve_count
        })

    return render_template('admin/challenges.html', challenge_stats=challenge_stats)

@app.route('/admin/challenges/create', methods=['GET', 'POST'])
@admin_required
def admin_create_challenge():
    """Create a new challenge"""
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '').strip()
        difficulty = request.form.get('difficulty', 'easy')
        points = int(request.form.get('points', 100))
        flag = request.form.get('flag', '').strip()
        answer_explanation = request.form.get('answer_explanation', '').strip()
        solution_steps = request.form.get('solution_steps', '').strip()
        
        # Validation
        if not title or not description or not flag:
            flash('Title, description, and flag are required.', 'error')
            return render_template('admin/create_challenge.html')
        
        # Check if challenge title already exists
        existing_challenge = Challenge.query.filter_by(title=title).first()
        if existing_challenge:
            flash('Challenge title already exists. Please choose a different title.', 'error')
            return render_template('admin/create_challenge.html')
        
        try:
            # Create new challenge
            challenge = Challenge(
                title=title,
                description=description,
                category=category,
                difficulty=difficulty,
                points=points,
                flag_encrypted=flag.encode(),  # Simple encoding for development
                answer_explanation=answer_explanation,
                solution_steps=solution_steps,
                created_at=datetime.utcnow(),
                created_by_id=session.get('user_id')
            )
            db.session.add(challenge)
            db.session.commit()
            
            flash(f'Challenge "{title}" created successfully!', 'success')
            return redirect(url_for('admin_challenges'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating challenge. Please try again.', 'error')
            print(f"Challenge creation error: {e}")
    
    return render_template('admin/create_challenge.html')

@app.route('/admin/challenges/edit/<int:challenge_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_challenge(challenge_id):
    """Edit an existing challenge"""
    challenge = Challenge.query.get_or_404(challenge_id)
    
    if request.method == 'POST':
        challenge.title = request.form.get('title', '').strip()
        challenge.description = request.form.get('description', '').strip()
        challenge.category = request.form.get('category', '').strip()
        challenge.difficulty = request.form.get('difficulty', 'easy')
        challenge.points = int(request.form.get('points', 100))
        
        new_flag = request.form.get('flag', '').strip()
        if new_flag:
            challenge.flag_encrypted = new_flag.encode()
        
        challenge.answer_explanation = request.form.get('answer_explanation', '').strip()
        challenge.solution_steps = request.form.get('solution_steps', '').strip()
        
        try:
            db.session.commit()
            flash(f'Challenge "{challenge.title}" updated successfully!', 'success')
            return redirect(url_for('admin_challenges'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating challenge. Please try again.', 'error')
            print(f"Challenge update error: {e}")
    
    # Get current flag for editing
    try:
        current_flag = challenge.flag_encrypted.decode() if challenge.flag_encrypted else ''
    except:
        current_flag = ''
    
    return render_template('admin/edit_challenge.html', challenge=challenge, current_flag=current_flag)

@app.route('/admin/challenges/delete/<int:challenge_id>', methods=['POST'])
@admin_required
def admin_delete_challenge(challenge_id):
    """Delete a challenge"""
    challenge = Challenge.query.get_or_404(challenge_id)

    try:
        # Delete challenge solves
        Solve.query.filter_by(challenge_id=challenge.id).delete()

        # Delete the challenge
        db.session.delete(challenge)
        db.session.commit()

        flash(f'Challenge "{challenge.title}" has been deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting challenge. Please try again.', 'error')

    return redirect(url_for('admin_challenges'))



@app.route('/admin/app_info')
@admin_required
def admin_app_info():
    """Admin application information page"""
    # Build database statistics expected by the template
    database_stats = {
        'total_users': User.query.count(),
        'total_challenges': Challenge.query.count(),
        'total_teams': Team.query.count(),
        'total_solves': Solve.query.count(),
        'total_submissions': Submission.query.count(),
        'total_hints': Hint.query.count()
    }

    # App info structure aligned with admin_app_info.html expectations
    app_info = {
        'version': '2.0.0',
        'last_updated': datetime.now().strftime('%Y-%m-%d'),
        'database_stats': database_stats,
        'features': [
            'User authentication and profile management',
            'Challenge creation and management',
            'Team collaboration',
            'Real-time notifications',
            'Leaderboards and scoring',
            'Admin dashboard',
            'Hint system',
            'Tournament mode',
            'Chat functionality'
        ],
        'security_features': [
            'Password hashing and salting',
            'CSRF protection',
            'XSS prevention',
            'SQL injection protection',
            'Rate limiting',
            'Session management',
            'Flag encryption'
        ]
    }

    # Get challenges list for total points calculation block in template
    challenges = Challenge.query.all()

    return render_template('admin_app_info.html', app_info=app_info, challenges=challenges)

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    """Admin settings page"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_email_settings':
            app.config['MAIL_SERVER'] = request.form.get('mail_server', 'smtp.gmail.com')
            app.config['MAIL_PORT'] = int(request.form.get('mail_port', 587))
            app.config['MAIL_USE_TLS'] = request.form.get('mail_use_tls') == 'on'
            app.config['MAIL_USERNAME'] = request.form.get('mail_username', 'nirotyaymukherjee563@gmail.com')
            
            # Only update password if provided
            new_password = request.form.get('mail_password')
            if new_password:
                app.config['MAIL_PASSWORD'] = new_password.replace(' ', '').strip()
                
            app.config['MAIL_DEFAULT_SENDER'] = request.form.get('mail_default_sender', 'NIROTYAY MUKHERJEE <nirotyaymukherjee563@gmail.com>')
            
            # Update notification settings
            app.config['EMAIL_ON_LOGIN'] = request.form.get('email_on_login') == 'on'
            app.config['EMAIL_ON_LOGOUT'] = request.form.get('email_on_logout') == 'on'
            app.config['EMAIL_NEW_USER'] = request.form.get('email_new_user') == 'on'
            app.config['EMAIL_CHALLENGE_SOLVED'] = request.form.get('email_challenge_solved') == 'on'
            app.config['EMAIL_TEAM_CREATED'] = request.form.get('email_team_created') == 'on'
            app.config['NOTIFICATION_EMAIL'] = request.form.get('notification_email', 'nirotyaymukherjee563@gmail.com')
            
            flash('Email settings updated successfully', 'success')
            
        elif action == 'test_email':
            recipient = request.form.get('test_email_recipient')
            if not recipient:
                flash('Please provide a recipient email address', 'error')
            else:
                subject = 'CTF Platform - Test Email'
                body = 'This is a test email from your CTF Platform.'
                html = '<h1>CTF Platform</h1><p>This is a test email from your CTF Platform.</p>'
                
                if send_email(subject, [recipient], body, html):
                    flash(f'Test email sent successfully to {recipient}', 'success')
                else:
                    flash('Failed to send test email. Please check your email settings.', 'error')
    
    # Get current email settings for the form
    email_settings = {
        'mail_server': app.config.get('MAIL_SERVER', 'smtp.gmail.com'),
        'mail_port': app.config.get('MAIL_PORT', 587),
        'mail_use_tls': app.config.get('MAIL_USE_TLS', True),
        'mail_username': app.config.get('MAIL_USERNAME', 'nirotyaymukherjee563@gmail.com'),
        'mail_default_sender': app.config.get('MAIL_DEFAULT_SENDER', 'NIROTYAY MUKHERJEE <nirotyaymukherjee563@gmail.com>'),
        'email_on_login': app.config.get('EMAIL_ON_LOGIN', False),
        'email_on_logout': app.config.get('EMAIL_ON_LOGOUT', False),
        'email_new_user': app.config.get('EMAIL_NEW_USER', False),
        'email_challenge_solved': app.config.get('EMAIL_CHALLENGE_SOLVED', False),
        'email_team_created': app.config.get('EMAIL_TEAM_CREATED', False),
        'notification_email': app.config.get('NOTIFICATION_EMAIL', 'nirotyaymukherjee563@gmail.com')
    }
    
    return render_template('admin/settings.html', email_settings=email_settings)

@app.route('/admin/chat')
@admin_required
def admin_chat():
    """Admin chat monitoring page"""
    # Get chat statistics
    total_messages = ChatMessage.query.filter_by(team_id=None).count()
    
    # Count unique users who have sent messages
    active_users = db.session.query(User.id).join(ChatMessage).filter(ChatMessage.team_id==None).distinct().count()
    
    # Count messages from today
    today = datetime.utcnow().date()
    today_messages = ChatMessage.query.filter(
        ChatMessage.team_id==None,
        func.date(ChatMessage.created_at) == today
    ).count()
    
    # Get recent messages (limit to 100 most recent)
    messages = ChatMessage.query.filter_by(team_id=None).order_by(ChatMessage.created_at.desc()).limit(100).all()
    messages.reverse()  # Show oldest first
    
    # Get moderation settings
    banned_words = []
    auto_moderate = False
    
    return render_template('admin/chat.html', 
                           messages=messages,
                           total_messages=total_messages,
                           active_users=active_users,
                           today_messages=today_messages,
                           banned_words=banned_words,
                           auto_moderate=auto_moderate)

# API Routes
@app.route('/api/stats')
def api_stats():
    """API endpoint for basic statistics"""
    total_challenges = Challenge.query.count()
    total_users = User.query.count()
    total_solves = Solve.query.count()

    return jsonify({
        'total_challenges': total_challenges,
        'total_users': total_users,
        'total_solves': total_solves
    })

# Admin optimization routes
@app.route('/optimize_performance', methods=['POST'])
@admin_required
def optimize_performance():
    """Optimize app performance by clearing cache and cleaning old data"""
    try:
        # Clear old sessions
        db.session.execute(text("DELETE FROM notification WHERE created_at < NOW() - INTERVAL '30 days'"))
        
        # Clean up old submissions that didn't result in solves
        db.session.execute(text("DELETE FROM submission WHERE created_at < NOW() - INTERVAL '30 days' AND NOT EXISTS (SELECT 1 FROM solve WHERE solve.user_id = submission.user_id AND solve.challenge_id = submission.challenge_id)"))
        
        # Commit changes
        db.session.commit()
        
        flash('Performance optimization completed successfully. Cache cleared and old data cleaned.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error during performance optimization: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/speed_optimize', methods=['POST'])
@admin_required
def speed_optimize():
    """Run aggressive speed optimizations including database indexing"""
    try:
        # Run VACUUM ANALYZE for PostgreSQL or similar optimization for SQLite
        if 'postgresql' in str(db.engine.url):
            db.session.execute(text("VACUUM ANALYZE"))
        elif 'sqlite' in str(db.engine.url):
            db.session.execute(text("VACUUM"))
            db.session.execute(text("ANALYZE"))
        
        # Optimize tables
        db.session.commit()
        
        flash('Aggressive speed optimization completed successfully. Database has been optimized.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error during speed optimization: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/app_info')
@admin_required
def app_info():
    """Display comprehensive application information"""
    # Get database statistics
    database_stats = {
        'total_users': User.query.count(),
        'total_challenges': Challenge.query.count(),
        'total_teams': Team.query.count(),
        'total_solves': Solve.query.count(),
        'total_submissions': Submission.query.count(),
        'total_hints': Hint.query.count()
    }
    
    # Get challenges for total points calculation
    challenges = Challenge.query.all()
    
    # Application info
    app_info = {
        'version': '2.0.0',
        'last_updated': datetime.now().strftime('%Y-%m-%d'),
        'database_stats': database_stats,
        'features': [
            'User authentication and profile management',
            'Challenge creation and management',
            'Team collaboration',
            'Real-time notifications',
            'Leaderboards and scoring',
            'Admin dashboard',
            'Hint system',
            'Tournament mode',
            'Chat functionality'
        ],
        'security_features': [
            'Password hashing and salting',
            'CSRF protection',
            'XSS prevention',
            'SQL injection protection',
            'Rate limiting',
            'Session management',
            'Flag encryption'
        ]
    }
    
    return render_template('admin_app_info.html', app_info=app_info, challenges=challenges)

@app.route('/api/leaderboard')
def api_leaderboard():
    """API endpoint for leaderboard data"""
    limit = request.args.get('limit', 10, type=int)
    limit = min(limit, 100)  # Cap at 100

    user_scores = db.session.query(
        User.username,
        func.sum(Challenge.points).label('total_score'),
        func.count(Solve.id).label('solve_count')
    ).join(Solve).join(Challenge).group_by(User.id, User.username).order_by(
        func.sum(Challenge.points).desc()
    ).limit(limit).all()

    leaderboard = []
    for i, (username, score, solves) in enumerate(user_scores, 1):
        leaderboard.append({
            'rank': i,
            'username': username,
            'score': score,
            'solves': solves
        })

    return jsonify({'leaderboard': leaderboard})

# SocketIO Events (if available)
if SOCKETIO_AVAILABLE:
    @socketio.on('connect')
    def handle_connect():
        if 'user_id' in session:
            user = get_current_user()
            user.is_online = True
            user.last_seen = datetime.utcnow()
            db.session.commit()
            
            # Emit online status to friends
            emit('friend_online', {'user_id': user.id}, broadcast=True)
            emit('status', {'message': f'Welcome, {user.username}!'})

    @app.route('/api/chat/initial_data')
    @login_required
    def get_initial_chat_data():
        user = get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401

        chat_rooms = [
            {
                'id': 'general',
                'name': 'general',
                'displayName': 'General Chat',
                'icon': 'globe',
                'description': 'Public discussion for all players'
            }
        ]

        # Add team chat if user is in a team and is a player (not an admin-only account)
        if user.is_player:
            user_team_membership = TeamMembership.query.filter_by(user_id=user.id).first()
            if user_team_membership:
                team = user_team_membership.team
                chat_rooms.append({
                    'id': f'team-{team.id}',
                    'name': team.name,
                    'displayName': f'Team: {team.name}',
                    'icon': 'users',
                    'description': 'Private team discussion'
                })

        # Add friend chats (for accepted friends)
        friend_relationships = Friend.query.filter(
            ((Friend.user_id == user.id) | (Friend.friend_id == user.id)) &
            (Friend.status == 'accepted')
        ).all()

        for relationship in friend_relationships:
            friend_user = None
            if relationship.user_id == user.id:
                friend_user = db.session.get(User, relationship.friend_id)
            else:
                friend_user = db.session.get(User, relationship.user_id)
            
            if friend_user:
                # Implement private chat room ID logic (e.g., sort user IDs to create consistent room name)
                room_users = sorted([user.id, friend_user.id])
                private_room_id = f'private-{room_users[0]}-{room_users[1]}'

                chat_rooms.append({
                    'id': private_room_id,
                    'name': f'{friend_user.username}',
                    'displayName': f'Private with {friend_user.username}',
                    'icon': 'user',
                    'description': f'Private chat with {friend_user.username}'
                })

        return jsonify({
            'currentUser': {
                'id': user.id,
                'username': user.username,
                'profile_picture': user.profile_picture or '/static/images/default-avatar.svg'
            },
            'chatRooms': chat_rooms,
            'friends': [
                {'id': f.id, 'username': f.username, 'profile_picture': f.profile_picture, 'is_online': f.is_online}
                for f in [db.session.get(User, r.friend_id) if r.user_id == user.id else db.session.get(User, r.user_id) for r in friend_relationships]
            ],
            'pendingRequests': [
                {'id': r.id, 'sender_id': r.user_id, 'sender_username': db.session.get(User, r.user_id).username,
                 'sender_profile_picture': db.session.get(User, r.user_id).profile_picture}
                for r in Friend.query.filter_by(friend_id=user.id, status='pending').all()
            ]
        })

    @socketio.on('disconnect')
    def handle_disconnect():
        if 'user_id' in session:
            user = get_current_user()
            user.is_online = False
            user.last_seen = datetime.utcnow()
            db.session.commit()
            
            # Emit offline status to friends
            emit('friend_offline', {'user_id': user.id}, broadcast=True)

    @socketio.on('join_chat')
    def handle_join_chat(data):
        if 'user_id' in session:
            room = data.get('room', 'general')
            join_room(room)
            user = get_current_user()
            emit('status', {'message': f'{user.username} joined the chat'}, room=room)

    @socketio.on('leave_chat')
    def handle_leave_chat(data):
        if 'user_id' in session:
            room = data.get('room', 'general')
            leave_room(room)
            user = get_current_user()
            emit('status', {'message': f'{user.username} left the chat'}, room=room)

    @socketio.on('send_message')
    def handle_message(data):
        if 'user_id' in session:
            user = get_current_user()
            room = data.get('room', 'general')
            message = data.get('message', '').strip()

            if message:
                # Save message to database
                chat_message = ChatMessage(
                    user_id=user.id,
                    content=message,
                    room=room
                )
                db.session.add(chat_message)
                db.session.commit()

                # Emit to room with full message data
                emit('new_message', {
                    'id': chat_message.id,
                    'user_id': user.id,
                    'username': user.username,
                    'content': message,
                    'created_at': chat_message.created_at.isoformat(),
                    'room': room,
                    'user_avatar': user.profile_picture or '/static/images/default-avatar.svg'
                }, room=room)

    @socketio.on('typing')
    def handle_typing(data):
        if 'user_id' in session:
            user = get_current_user()
            room = data.get('room', 'general')
            is_typing = data.get('is_typing', False)
            
            if is_typing:
                emit('user_typing', {
                    'username': user.username,
                    'user_id': user.id
                }, room=room, include_self=False)

# Team Management Routes
@app.route('/teams')
@login_required
def teams():
    """Display teams page with team management"""
    user = db.session.get(User, session['user_id'])

    # Prevent admin from accessing team features
    if user.role == 'admin' and not user.is_player:
        flash('Administrators cannot participate in teams. Please use the admin panel to manage teams.', 'warning')
        return redirect(url_for('admin_dashboard'))

    # Get user's current team
    user_team = None
    user_membership = TeamMembership.query.filter_by(user_id=user.id).first()
    if user_membership:
        user_team = user_membership.team

    # Get all teams for display
    all_teams = Team.query.all()

    # Get team stats
    team_stats = []
    for team in all_teams:
        member_count = TeamMembership.query.filter_by(team_id=team.id).count()
        team_solves = db.session.query(Solve).join(User).join(TeamMembership).filter(
            TeamMembership.team_id == team.id
        ).count()

        team_stats.append({
            'team': team,
            'member_count': member_count,
            'solve_count': team_solves
        })

    return render_template('teams.html',
                         user_team=user_team,
                         user_membership=user_membership,
                         team_stats=team_stats)

@app.route('/teams/create', methods=['POST'])
@login_required
def create_team():
    """Create a new team"""
    user = db.session.get(User, session['user_id'])

    # Check if user is already in a team
    existing_membership = TeamMembership.query.filter_by(user_id=user.id).first()
    if existing_membership:
        flash('You are already a member of a team. Leave your current team first.', 'error')
        return redirect(url_for('teams'))

    team_name = request.form.get('team_name', '').strip()

    if not team_name:
        flash('Team name is required.', 'error')
        return redirect(url_for('teams'))

    if len(team_name) < 3 or len(team_name) > 50:
        flash('Team name must be between 3 and 50 characters.', 'error')
        return redirect(url_for('teams'))

    # Check if team name already exists
    existing_team = Team.query.filter_by(name=team_name).first()
    if existing_team:
        flash('Team name already exists. Please choose a different name.', 'error')
        return redirect(url_for('teams'))

    try:
        # Generate unique team code
        team_code = secrets.token_hex(4).upper()
        while Team.query.filter_by(team_code=team_code).first():
            team_code = secrets.token_hex(4).upper()

        # Create team
        team = Team(name=team_name, team_code=team_code)
        db.session.add(team)
        db.session.flush()  # Get team ID

        # Add creator as team leader
        membership = TeamMembership(
            team_id=team.id,
            user_id=user.id,
            role='leader'
        )
        db.session.add(membership)
        db.session.commit()

        flash(f'Team "{team_name}" created successfully! Team code: {team_code}', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error creating team. Please try again.', 'error')

    return redirect(url_for('teams'))

@app.route('/teams/join', methods=['POST'])
@login_required
def join_team():
    """Join a team using team code"""
    user = db.session.get(User, session['user_id'])

    # Check if user is already in a team
    existing_membership = TeamMembership.query.filter_by(user_id=user.id).first()
    if existing_membership:
        flash('You are already a member of a team. Leave your current team first.', 'error')
        return redirect(url_for('teams'))

    team_code = request.form.get('team_code', '').strip().upper()

    if not team_code:
        flash('Team code is required.', 'error')
        return redirect(url_for('teams'))

    # Find team by code
    team = Team.query.filter_by(team_code=team_code).first()
    if not team:
        flash('Invalid team code. Please check and try again.', 'error')
        return redirect(url_for('teams'))

    # Check team size limit (optional - set to 4 members max)
    current_members = TeamMembership.query.filter_by(team_id=team.id).count()
    if current_members >= 4:
        flash('Team is full. Maximum 4 members allowed per team.', 'error')
        return redirect(url_for('teams'))

    try:
        # Add user to team
        membership = TeamMembership(
            team_id=team.id,
            user_id=user.id,
            role='member'
        )
        db.session.add(membership)
        db.session.commit()

        flash(f'Successfully joined team "{team.name}"!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error joining team. Please try again.', 'error')

    return redirect(url_for('teams'))

@app.route('/teams/leave', methods=['POST'])
@login_required
def leave_team():
    """Leave current team"""
    user = db.session.get(User, session['user_id'])

    membership = TeamMembership.query.filter_by(user_id=user.id).first()
    if not membership:
        flash('You are not a member of any team.', 'error')
        return redirect(url_for('teams'))

    team = membership.team
    team_name = team.name

    try:
        # Check if user is the only leader
        leaders = TeamMembership.query.filter_by(team_id=team.id, role='leader').all()
        members = TeamMembership.query.filter_by(team_id=team.id).all()

        if membership.role == 'leader' and len(leaders) == 1 and len(members) > 1:
            flash('You cannot leave the team as the only leader. Promote another member to leader first.', 'error')
            return redirect(url_for('teams'))

        # Remove membership
        db.session.delete(membership)

        # If this was the last member, delete the team
        remaining_members = TeamMembership.query.filter_by(team_id=team.id).count()
        if remaining_members == 1:  # Only this member left
            db.session.delete(team)
            flash(f'Left team "{team_name}". Team was deleted as you were the last member.', 'success')
        else:
            flash(f'Successfully left team "{team_name}".', 'success')

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash('Error leaving team. Please try again.', 'error')

    return redirect(url_for('teams'))

@app.route('/teams/delete', methods=['POST'])
@login_required
def delete_team():
    """Delete the current team (leader only)"""
    current_user = db.session.get(User, session['user_id'])

    # Check if current user is a team leader
    current_membership = TeamMembership.query.filter_by(user_id=current_user.id).first()
    if not current_membership or current_membership.role != 'leader':
        flash('Only team leaders can delete teams.', 'error')
        return redirect(url_for('teams'))

    team = current_membership.team
    team_name = team.name

    try:
        # Delete all team memberships first
        TeamMembership.query.filter_by(team_id=team.id).delete()

        # Delete the team
        db.session.delete(team)
        db.session.commit()

        flash(f'Team "{team_name}" has been successfully deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting team. Please try again.', 'error')

    return redirect(url_for('teams'))

@app.route('/teams/promote/<int:user_id>', methods=['POST'])
@login_required
def promote_member(user_id):
    """Promote a team member to leader (current leader only)"""
    current_user = db.session.get(User, session['user_id'])
    
    # Check if current user is a team leader
    current_membership = TeamMembership.query.filter_by(user_id=current_user.id).first()
    if not current_membership or current_membership.role != 'leader':
        flash('Only team leaders can promote members.', 'error')
        return redirect(url_for('teams'))
    
    # Get the member to promote
    member_membership = TeamMembership.query.filter_by(
        user_id=user_id, 
        team_id=current_membership.team_id
    ).first()
    
    if not member_membership:
        flash('Member not found in team.', 'error')
        return redirect(url_for('teams'))
    
    try:
        # Demote current leader to member
        current_membership.role = 'member'
        
        # Promote new member to leader
        member_membership.role = 'leader'
        
        db.session.commit()
        flash(f'{member_membership.user.username} has been promoted to team leader.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error promoting member. Please try again.', 'error')
    
    return redirect(url_for('teams'))

@app.route('/teams/kick/<int:user_id>', methods=['POST'])
@login_required
def kick_member(user_id):
    """Kick a member from the team (leader only)"""
    current_user = db.session.get(User, session['user_id'])
    
    # Check if current user is a team leader
    current_membership = TeamMembership.query.filter_by(user_id=current_user.id).first()
    if not current_membership or current_membership.role != 'leader':
        flash('Only team leaders can kick members.', 'error')
        return redirect(url_for('teams'))
    
    # Get the member to kick
    member_membership = TeamMembership.query.filter_by(
        user_id=user_id, 
        team_id=current_membership.team_id
    ).first()
    
    if not member_membership:
        flash('Member not found in team.', 'error')
        return redirect(url_for('teams'))
    
    if member_membership.user_id == current_user.id:
        flash('You cannot kick yourself from the team.', 'error')
        return redirect(url_for('teams'))
    
    try:
        member_name = member_membership.user.username
        db.session.delete(member_membership)
        db.session.commit()
        flash(f'{member_name} has been removed from the team.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error removing member. Please try again.', 'error')
    
    return redirect(url_for('teams'))

# Team Management: add member (leader only)
@app.route('/teams/add_member', methods=['POST'])
@login_required
def add_team_member():
    """Add a user to the current team (leader only)"""
    current_user = db.session.get(User, session['user_id'])

    # Verify leader
    current_membership = TeamMembership.query.filter_by(user_id=current_user.id).first()
    if not current_membership or current_membership.role != 'leader':
        flash('Only team leaders can add members.', 'error')
        return redirect(url_for('teams'))

    identifier = request.form.get('username', '').strip()
    if not identifier:
        flash('Please provide a username or email.', 'error')
        return redirect(url_for('teams'))

    # Find user by username or email
    user_to_add = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
    if not user_to_add:
        flash('User not found.', 'error')
        return redirect(url_for('teams'))

    # Prevent adding non-player admins
    if user_to_add.role == 'admin' and not user_to_add.is_player:
        flash('Administrators cannot be added to teams.', 'error')
        return redirect(url_for('teams'))

    # Prevent adding user who is already in any team
    existing_membership = TeamMembership.query.filter_by(user_id=user_to_add.id).first()
    if existing_membership:
        flash('User is already a member of a team.', 'error')
        return redirect(url_for('teams'))

    # Enforce max team size (4)
    current_count = TeamMembership.query.filter_by(team_id=current_membership.team_id).count()
    if current_count >= 4:
        flash('Team is full. Maximum 4 members allowed per team.', 'error')
        return redirect(url_for('teams'))

    try:
        membership = TeamMembership(
            team_id=current_membership.team_id,
            user_id=user_to_add.id,
            role='member'
        )
        db.session.add(membership)
        db.session.commit()
        flash(f'Added {user_to_add.username} to the team.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error adding member. Please try again.', 'error')

    return redirect(url_for('teams'))

# File upload for chat (images/documents/videos)
@app.route('/api/upload', methods=['POST'])
@login_required
def upload_chat_file():
    """Handle chat media uploads and create a message referencing the file"""
    user = db.session.get(User, session['user_id'])

    # Disallow admin-only accounts from sending media
    if user.role == 'admin' and not user.is_player:
        return jsonify({'success': False, 'message': 'Administrators cannot upload files'}), 403

    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400

    upload = request.files['file']
    if not upload or upload.filename == '':
        return jsonify({'success': False, 'message': 'Invalid file'}), 400

    room = request.form.get('room', 'general')

    # Handle team room permissions
    team_id = None
    if room.startswith('team-'):
        try:
            team_id = int(room.split('-')[1])
        except Exception:
            return jsonify({'success': False, 'message': 'Invalid room'}), 400

        # Verify membership and that admin-only accounts cannot access team chats
        if user.role == 'admin' and not user.is_player:
            return jsonify({'success': False, 'message': 'Administrators cannot access team chats'}), 403
        membership = TeamMembership.query.filter_by(user_id=user.id, team_id=team_id).first()
        if not membership:
            return jsonify({'success': False, 'message': 'Access denied to team chat'}), 403

    # Ensure upload directory exists
    import os, uuid
    from werkzeug.utils import secure_filename
    uploads_dir = os.path.join(app.root_path, 'static', 'uploads', 'chat')
    os.makedirs(uploads_dir, exist_ok=True)

    # Build secure unique filename
    original_name = secure_filename(upload.filename)
    name, ext = os.path.splitext(original_name)
    unique_name = f"{name}_{uuid.uuid4().hex[:12]}{ext}"
    filepath = os.path.join(uploads_dir, unique_name)

    try:
        upload.save(filepath)
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to save file: {str(e)}'}), 500

    # Determine message type by mimetype
    mimetype = upload.mimetype or ''
    if mimetype.startswith('image/'):
        message_type = 'image'
        label = 'Image'
        icon = '📷'
    elif mimetype.startswith('video/'):
        message_type = 'video'
        label = 'Video'
        icon = '🎥'
    else:
        message_type = 'document'
        label = 'Document'
        icon = '📄'

    file_url = url_for('static', filename=f'uploads/chat/{unique_name}')
    content = f"{icon} [{label}: {original_name}]({file_url})"

    # Create chat message
    message = ChatMessage(
        user_id=user.id,
        content=content,
        room=room,
        team_id=team_id,
        message_type=message_type
    )

    try:
        db.session.add(message)
        db.session.commit()

        # Prepare payload for clients
        payload = message.to_dict()
        payload['file_url'] = file_url

        # Emit via SocketIO if available
        try:
            if socketio:
                socketio.emit('new_message', payload, room=room)
        except Exception:
            pass

        return jsonify({'success': True, 'message': 'File uploaded', 'file_url': file_url})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Failed to create message: {str(e)}'}), 500

# Chat Routes
@app.route('/chat')
@login_required
def chat():
    """Main chat page"""
    user = db.session.get(User, session['user_id'])

    # Allow admin access to chat system, but not as a player
    if user.role == 'admin' and not user.is_player:
        flash('Administrator access granted to chat system. You can view public chats but not team chats.', 'info')

    # Get user's team for team chat (only for players or admin-players)
    user_team = None
    if user.is_player:
        team_membership = TeamMembership.query.filter_by(user_id=user.id).first()
        if team_membership:
            user_team = team_membership.team

    # Get user's friends for friends chat
    friends = []
    friend_relationships = Friend.query.filter(
        ((Friend.user_id == user.id) | (Friend.friend_id == user.id)) &
        (Friend.status == 'accepted')
    ).all()
    
    for relationship in friend_relationships:
        if relationship.user_id == user.id:
            friend_user = db.session.get(User, relationship.friend_id)
        else:
            friend_user = db.session.get(User, relationship.user_id)
        
        if friend_user:
            friends.append(friend_user)

    return render_template('chat.html', user_team=user_team, current_user=user, friends=friends)

@app.route('/api/chat/messages')
@login_required
def get_chat_messages():
    """Get chat messages for a specific room"""
    room = request.args.get('room', 'general')
    limit = int(request.args.get('limit', 50))
    user = db.session.get(User, session['user_id'])

    # Admin can only see public messages, not team messages
    query = ChatMessage.query

    if room.startswith('team-'):
        # Team chat - verify user is in the team and is a player
        if user.role == 'admin' and not user.is_player:
            return jsonify({'error': 'Administrators cannot access team chats'}), 403
            
        team_id = int(room.split('-')[1])
        team_membership = TeamMembership.query.filter_by(user_id=user.id, team_id=team_id).first()
        if not team_membership:
            return jsonify({'error': 'Access denied to team chat'}), 403
        query = query.filter_by(team_id=team_id)
    else:
        # General chat
        query = query.filter_by(room=room, team_id=None)

    messages = query.order_by(ChatMessage.created_at.desc()).limit(limit).all()
    messages.reverse()  # Show oldest first

    return jsonify([message.to_dict() for message in messages])

@app.route('/api/chat/send', methods=['POST'])
@login_required
def send_chat_message():
    """Send a chat message"""
    user = db.session.get(User, session['user_id'])

    # Prevent admin from sending messages
    if user.role == 'admin':
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    content = data.get('content', '').strip()
    room = data.get('room', 'general')
    reply_to_id = data.get('reply_to_id')

    if not content:
        return jsonify({'error': 'Message content is required'}), 400

    if len(content) > 1000:
        return jsonify({'error': 'Message too long (max 1000 characters)'}), 400

    # Create message
    message = ChatMessage(
        user_id=user.id,
        content=content,
        room=room,
        reply_to_id=reply_to_id
    )

    # Handle team chat
    if room.startswith('team-'):
        team_id = int(room.split('-')[1])
        team_membership = TeamMembership.query.filter_by(user_id=user.id, team_id=team_id).first()
        if not team_membership:
            return jsonify({'error': 'Access denied to team chat'}), 403
        message.team_id = team_id

    try:
        db.session.add(message)
        db.session.commit()
        return jsonify(message.to_dict())
    except Exception as e:
        db.session.rollback()
        print(f"Error sending message: {e}")  # Debug logging
        return jsonify({'error': f'Failed to send message: {str(e)}'}), 500

@app.route('/api/chat/edit/<int:message_id>', methods=['PUT'])
@login_required
def edit_chat_message(message_id):
    """Edit a chat message"""
    user = db.session.get(User, session['user_id'])

    message = ChatMessage.query.get_or_404(message_id)

    # Only allow user to edit their own messages
    if message.user_id != user.id:
        return jsonify({'error': 'Access denied'}), 403

    # Don't allow editing messages older than 5 minutes
    if (datetime.utcnow() - message.created_at).total_seconds() > 300:
        return jsonify({'error': 'Cannot edit messages older than 5 minutes'}), 400

    data = request.get_json()
    new_content = data.get('content', '').strip()

    if not new_content:
        return jsonify({'error': 'Message content is required'}), 400

    if len(new_content) > 1000:
        return jsonify({'error': 'Message too long (max 1000 characters)'}), 400

    try:
        message.content = new_content
        message.edited = True
        message.edited_at = datetime.utcnow()
        db.session.commit()
        return jsonify(message.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to edit message'}), 500

@app.route('/api/chat/delete/<int:message_id>', methods=['DELETE'])
@login_required
def delete_chat_message(message_id):
    """Delete a chat message"""
    user = db.session.get(User, session['user_id'])

    message = ChatMessage.query.get_or_404(message_id)

    # Only allow user to delete their own messages or admins
    if message.user_id != user.id and user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    try:
        db.session.delete(message)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete message'}), 500

@app.route('/api/chat/clear', methods=['POST'])
@login_required
def clear_chat_history():
    """Clear all chat messages (admin only)"""
    user = db.session.get(User, session['user_id'])

    if user.role != 'admin':
        return jsonify({'error': 'Access denied. Admin only.'}), 403

    try:
        # Delete only public chat messages (not team messages)
        ChatMessage.query.filter_by(team_id=None).delete()
        db.session.commit()
        return jsonify({'success': True, 'message': 'Public chat history cleared successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to clear chat history'}), 500

@app.route('/api/admin/chat/messages')
@login_required
def admin_get_chat_messages():
    """Get all public chat messages for admin monitoring"""
    user = db.session.get(User, session['user_id'])
    
    if user.role != 'admin':
        return jsonify({'error': 'Access denied. Admin only.'}), 403
    
    # Get chat statistics
    total_messages = ChatMessage.query.filter_by(team_id=None).count()
    
    # Count unique users who have sent messages
    active_users = db.session.query(User.id).join(ChatMessage).filter(ChatMessage.team_id==None).distinct().count()
    
    # Count messages from today
    today = datetime.utcnow().date()
    today_messages = ChatMessage.query.filter(
        ChatMessage.team_id==None,
        func.date(ChatMessage.created_at) == today
    ).count()
    
    # Get recent messages (limit to 100 most recent)
    messages = ChatMessage.query.filter_by(team_id=None).order_by(ChatMessage.created_at.desc()).limit(100).all()
    messages.reverse()  # Show oldest first
    
    return jsonify({
        'messages': [{
            'id': message.id,
            'content': message.content,
            'username': message.user.username,
            'user_id': message.user_id,
            'created_at': message.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'room': message.room
        } for message in messages],
        'total_messages': total_messages,
        'active_users': active_users,
        'today_messages': today_messages
    })

@app.route('/api/admin/chat/moderation', methods=['POST'])
@login_required
def admin_chat_moderation():
    """Update chat moderation settings"""
    user = db.session.get(User, session['user_id'])
    
    if user.role != 'admin':
        return jsonify({'error': 'Access denied. Admin only.'}), 403
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    banned_words = data.get('banned_words', [])
    auto_moderate = data.get('auto_moderate', False)
    
    # In a real implementation, you would save these settings to the database
    # For now, we'll just return success
    return jsonify({
        'success': True,
        'message': 'Moderation settings updated successfully'
    })

# Friend System API Routes (for chat integration)

@app.route('/friends/search')
@login_required
def search_users():
    """Search for users to add as friends"""
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])
    
    # Search users by username or email
    users = User.query.filter(
        (User.username.contains(query)) | (User.email.contains(query))
    ).filter(User.id != get_current_user().id).limit(10).all()
    
    # Check friendship status for each user
    current_user = get_current_user()
    results = []
    for user in users:
        # Check if already friends
        friendship = Friend.query.filter(
            ((Friend.user_id == current_user.id) & (Friend.friend_id == user.id)) |
            ((Friend.user_id == user.id) & (Friend.friend_id == current_user.id))
        ).first()
        
        status = 'none'
        if friendship:
            status = friendship.status
        
        results.append({
            'id': user.id,
            'username': user.username,
            'profile_picture': user.profile_picture,
            'is_online': user.is_online,
            'last_seen': user.last_seen.isoformat() if user.last_seen else None,
            'friendship_status': status
        })
    
    return jsonify(results)

@app.route('/friends/request', methods=['POST'])
@login_required
def send_friend_request():
    """Send a friend request"""
    friend_id = request.form.get('friend_id', type=int)
    if not friend_id:
        return jsonify({'success': False, 'message': 'Friend ID is required'})
    
    current_user = get_current_user()
    
    # Check if already friends or request exists
    existing = Friend.query.filter(
        ((Friend.user_id == current_user.id) & (Friend.friend_id == friend_id)) |
        ((Friend.user_id == friend_id) & (Friend.friend_id == current_user.id))
    ).first()
    
    if existing:
        return jsonify({'success': False, 'message': 'Friend request already exists'})
    
    # Create friend request
    friend_request = Friend(
        user_id=current_user.id,
        friend_id=friend_id,
        status='pending'
    )
    
    try:
        db.session.add(friend_request)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Friend request sent!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error sending friend request'})

@app.route('/friends/accept/<int:request_id>', methods=['POST'])
@login_required
def accept_friend_request(request_id):
    """Accept a friend request"""
    friend_request = Friend.query.get_or_404(request_id)
    
    if friend_request.friend_id != get_current_user().id:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    friend_request.status = 'accepted'
    friend_request.accepted_at = datetime.utcnow()
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'message': 'Friend request accepted!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error accepting friend request'})

@app.route('/friends/reject/<int:request_id>', methods=['POST'])
@login_required
def reject_friend_request(request_id):
    """Reject a friend request"""
    friend_request = Friend.query.get_or_404(request_id)
    
    if friend_request.friend_id != get_current_user().id:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    try:
        db.session.delete(friend_request)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Friend request rejected!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error rejecting friend request'})

@app.route('/friends/cancel/<int:friend_id>', methods=['POST'])
@login_required
def cancel_friend_request(friend_id):
    """Cancel a friend request sent by the current user"""
    current_user = get_current_user()
    
    # Find the pending friend request
    friend_request = Friend.query.filter_by(
        user_id=current_user.id,
        friend_id=friend_id,
        status='pending'
    ).first_or_404()
    
    try:
        db.session.delete(friend_request)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Friend request cancelled!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error cancelling friend request'})

@app.route('/friends/pending', methods=['GET'])
@login_required
def get_pending_friend_requests():
    """Get pending friend requests for the current user"""
    current_user = get_current_user()
    
    # Get pending friend requests
    pending_requests = Friend.query.filter_by(friend_id=current_user.id, status='pending').all()
    
    requests = []
    for request in pending_requests:
        sender = db.session.get(User, request.user_id)
        if sender:
            requests.append({
                'id': request.id,
                'user_id': sender.id,
                'username': sender.username,
                'profile_picture': sender.profile_picture,
                'created_at': request.created_at.isoformat()
            })
    
    return jsonify({'success': True, 'requests': requests})

# Chat Messages API
@app.route('/api/messages', methods=['GET', 'POST'])
@login_required
def handle_messages():
    """Handle chat messages"""
    if request.method == 'GET':
        # Get messages for a room
        room = request.args.get('room', 'general')
        messages = ChatMessage.query.filter_by(room=room).order_by(ChatMessage.created_at.desc()).limit(50).all()
        messages.reverse()  # Show oldest first
        
        message_list = []
        for msg in messages:
            user = db.session.get(User, msg.user_id)
            message_list.append({
                'id': msg.id,
                'content': msg.content,
                'user_id': msg.user_id,
                'username': user.username if user else 'Unknown',
                'timestamp': msg.created_at.isoformat(),
                'room': msg.room
            })
        
        return jsonify({'success': True, 'messages': message_list})
    
    elif request.method == 'POST':
        # Send a new message
        data = request.get_json()
        content = data.get('content', '').strip()
        room = data.get('room', 'general')
        
        if not content:
            return jsonify({'success': False, 'message': 'Message content is required'})
        
        current_user = get_current_user()
        
        # Create new message
        message = ChatMessage(
            content=content,
            user_id=current_user.id,
            room=room,
            created_at=datetime.utcnow()
        )
        
        try:
            db.session.add(message)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Message sent successfully',
                'message': {
                    'id': message.id,
                    'content': message.content,
                    'user_id': message.user_id,
                    'username': current_user.username,
                    'timestamp': message.created_at.isoformat(),
                    'room': message.room
                }
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': 'Error sending message'})

# File Upload API
@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    """Handle file uploads for chat"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'})
    
    file = request.files['file']
    room = request.form.get('room', 'general')
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'})
    
    if file:
        # Check file size (max 10MB)
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > 10 * 1024 * 1024:  # 10MB
            return jsonify({'success': False, 'message': 'File size must be less than 10MB'})
        
        # Generate unique filename
        filename = secure_filename(file.filename)
        timestamp = int(time.time())
        name, ext = os.path.splitext(filename)
        unique_filename = f"{name}_{timestamp}{ext}"
        
        # Save file to uploads directory
        upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'chat_files')
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, unique_filename)
        file.save(file_path)
        
        # Create message for the uploaded file
        current_user = get_current_user()
        file_url = url_for('static', filename=f'uploads/chat_files/{unique_filename}')
        
        # Determine file type and create appropriate message
        file_ext = ext.lower()
        message_type = 'file'

        if file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
            message_content = f"📷 [Image: {filename}]({file_url})"
            message_type = 'image'
        elif file_ext in ['.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm']:
            message_content = f"🎥 [Video: {filename}]({file_url})"
            message_type = 'video'
        elif file_ext in ['.pdf', '.doc', '.docx', '.txt']:
            message_content = f"📄 [Document: {filename}]({file_url})"
            message_type = 'document'
        else:
            message_content = f"📎 [File: {filename}]({file_url})"
            message_type = 'file'

        # Save message to database
        message = ChatMessage(
            content=message_content,
            user_id=current_user.id,
            room=room,
            message_type=message_type,
            created_at=datetime.utcnow()
        )
        db.session.add(message)
        db.session.commit()

        # Emit new message via SocketIO
        if SOCKETIO_AVAILABLE:
            socketio.emit('new_message', message.to_dict(), room=room)

        # Return success response
        return jsonify({
            'success': True,
            'message': 'File uploaded successfully',
            'file_url': file_url,
            'filename': filename,
            'message_id': message.id # Optionally return message ID
        })

    return jsonify({'success': False, 'message': 'Error uploading file'})
    
    try:
        db.session.delete(friend_request)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Friend request rejected'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error rejecting friend request'})

@app.route('/friends/remove/<int:friend_id>', methods=['POST'])
@login_required
def remove_friend(friend_id):
    """Remove a friend"""
    current_user = db.session.get(User, session['user_id'])
    
    friendship = Friend.query.filter(
        ((Friend.user_id == current_user.id) & (Friend.friend_id == friend_id)) |
        ((Friend.user_id == friend_id) & (Friend.friend_id == current_user.id))
    ).first()
    
    if not friendship:
        return jsonify({'success': False, 'message': 'Friendship not found'})
    
    try:
        db.session.delete(friendship)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Friend removed'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error removing friend'})

# Update online status
@app.route('/api/online', methods=['POST'])
@login_required
def update_online_status():
    """Update user's online status"""
    user = db.session.get(User, session['user_id'])
    user.is_online = True
    user.last_seen = datetime.utcnow()
    
    try:
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False})

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            print("✅ Database tables created/verified")

            # Lightweight schema reconciliation for legacy SQLite databases
            try:
                if str(db.engine.url).startswith('sqlite:///'):
                    # Handle chat_message table
                    result = db.session.execute(text("PRAGMA table_info(chat_message)"))
                    existing_columns = {row[1] for row in result}

                    # Add missing columns expected by current models
                    if 'team_id' not in existing_columns:
                        db.session.execute(text("ALTER TABLE chat_message ADD COLUMN team_id INTEGER"))
                    if 'message_type' not in existing_columns:
                        db.session.execute(text("ALTER TABLE chat_message ADD COLUMN message_type VARCHAR(20)"))
                    if 'edited' not in existing_columns:
                        db.session.execute(text("ALTER TABLE chat_message ADD COLUMN edited BOOLEAN DEFAULT 0"))
                    if 'edited_at' not in existing_columns:
                        db.session.execute(text("ALTER TABLE chat_message ADD COLUMN edited_at DATETIME"))
                    if 'reply_to_id' not in existing_columns:
                        db.session.execute(text("ALTER TABLE chat_message ADD COLUMN reply_to_id INTEGER"))
                    if 'room' not in existing_columns:
                        db.session.execute(text("ALTER TABLE chat_message ADD COLUMN room VARCHAR(50) DEFAULT 'general'"))
                    if 'created_at' not in existing_columns:
                        db.session.execute(text("ALTER TABLE chat_message ADD COLUMN created_at DATETIME"))
                    
                    # Handle user table
                    result = db.session.execute(text("PRAGMA table_info(user)"))
                    existing_user_columns = {row[1] for row in result}
                    
                    if 'is_online' not in existing_user_columns:
                        db.session.execute(text("ALTER TABLE user ADD COLUMN is_online BOOLEAN DEFAULT 0"))
                    if 'last_seen' not in existing_user_columns:
                        db.session.execute(text("ALTER TABLE user ADD COLUMN last_seen DATETIME"))
                    
                    # Check if friend table exists
                    try:
                        db.session.execute(text("SELECT 1 FROM friend LIMIT 1"))
                    except:
                        # Create friend table if it doesn't exist
                        db.session.execute(text("""
                            CREATE TABLE friend (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                user_id INTEGER NOT NULL,
                                friend_id INTEGER NOT NULL,
                                status VARCHAR(20) NOT NULL DEFAULT 'pending',
                                created_at DATETIME NOT NULL,
                                accepted_at DATETIME,
                                FOREIGN KEY (user_id) REFERENCES user (id),
                                FOREIGN KEY (friend_id) REFERENCES user (id)
                            )
                        """))
                    
                    db.session.commit()
                    print("✅ Schema reconciliation completed")
            except Exception as schema_err:
                print(f"⚠️ Schema reconciliation skipped/failed: {schema_err}")

            # Create admin user if it doesn't exist
            admin = db.session.query(User).filter_by(username='admin').first()
            if not admin:
                admin = User(
                    username='admin',
                    email='admin@ctf.local',
                    password_hash=generate_password_hash('admin123'),
                    role='admin',
                    is_player=False
                )
                db.session.add(admin)
                db.session.commit()
                print("✅ Admin user created: admin/admin123 (non-player account)")
        except Exception as e:
            print(f"⚠️ Database initialization error: {e}")

    if SOCKETIO_AVAILABLE:
        socketio.run(app, debug=True, host='0.0.0.0', port=5000)
    else:
        app.run(debug=True, host='0.0.0.0', port=5000)
