"""
HUNTING-CTF - Full Featured CTF Platform
Enhanced with modern UI and complete functionality
"""

from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify, g, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import RequestEntityTooLarge, BadRequest
from cryptography.fernet import Fernet
import os
import time
import logging
from datetime import datetime, timedelta
import functools
from sqlalchemy.sql import func
from sqlalchemy import text
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask_compress import Compress
import json
import secrets
import hashlib

# Import SocketIO with error handling
try:
    from flask_socketio import SocketIO, emit, join_room, leave_room
    SOCKETIO_AVAILABLE = True
except ImportError:
    print("Warning: flask-socketio not available, running without WebSocket support")
    SOCKETIO_AVAILABLE = False
    SocketIO = None

# Import models
from models import (
    db, User, Challenge, Solve, Submission, Team, TeamMembership,
    Tournament, Hint, UserHint, Notification, ChatMessage
)

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Fix DATABASE_URL for psycopg3 compatibility
database_url = os.environ.get('DATABASE_URL', 'sqlite:///ctf.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = False  # Disable for API compatibility
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file upload
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

# Initialize extensions
try:
    db.init_app(app)
    migrate = Migrate(app, db)
    mail = Mail(app)
    compress = Compress(app)
    print("✅ Extensions initialized successfully")
except Exception as e:
    print(f"❌ Extension initialization failed: {e}")
    raise

# Initialize SocketIO if available
if SOCKETIO_AVAILABLE:
    socketio = SocketIO(app, cors_allowed_origins="*")
else:
    socketio = None

# Encryption key for flags
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY)

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Helper functions
def login_required(f):
    """Decorator to require login for routes"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin privileges"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash('Admin privileges required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Get current logged-in user"""
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

def encrypt_flag(flag):
    """Encrypt a flag for storage"""
    return cipher_suite.encrypt(flag.encode())

def decrypt_flag(encrypted_flag):
    """Decrypt a flag for validation"""
    try:
        return cipher_suite.decrypt(encrypted_flag).decode()
    except:
        return None

def validate_flag(submitted_flag, challenge):
    """Validate a submitted flag against a challenge"""
    try:
        actual_flag = decrypt_flag(challenge.flag_encrypted)
        return submitted_flag.strip() == actual_flag.strip()
    except:
        return False

def calculate_user_score(user_id):
    """Calculate total score for a user"""
    total = db.session.query(func.sum(Challenge.points)).join(Solve).filter(
        Solve.user_id == user_id
    ).scalar()
    return total or 0

def get_user_rank(user_id):
    """Get user's rank on leaderboard"""
    user_score = calculate_user_score(user_id)
    higher_scores = db.session.query(func.count(func.distinct(User.id))).join(Solve).join(Challenge).group_by(User.id).having(
        func.sum(Challenge.points) > user_score
    ).scalar()
    return (higher_scores or 0) + 1

# Context processors
@app.context_processor
def inject_user():
    """Inject current user into all templates"""
    return dict(current_user=get_current_user())

@app.before_request
def load_logged_in_user():
    """Load user info before each request"""
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = User.query.get(user_id)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    flash('File too large. Maximum size is 16MB.', 'error')
    return redirect(request.url)

# Main routes
@app.route('/')
def index():
    """Home page"""
    user = get_current_user()
    
    # Get basic stats
    total_challenges = Challenge.query.count()
    total_users = User.query.count()
    recent_solves = []
    
    if user:
        user_solves = Solve.query.filter_by(user_id=user.id).count()
        user_score = calculate_user_score(user.id)
        user_rank = get_user_rank(user.id)
        
        # Get recent solves
        recent_solves = db.session.query(Solve, Challenge).join(Challenge).filter(
            Solve.user_id == user.id
        ).order_by(Solve.solved_at.desc()).limit(5).all()
    else:
        user_solves = 0
        user_score = 0
        user_rank = 0
    
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
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {e}")
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
            
            flash(f'Welcome back, {user.username}!', 'success')
            
            # Redirect to next page or dashboard
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
    session.clear()
    flash(f'Goodbye, {username}!', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    user = get_current_user()

    # Get user statistics
    user_score = calculate_user_score(user.id)
    user_rank = get_user_rank(user.id)
    challenges_solved = Solve.query.filter_by(user_id=user.id).count()
    total_challenges = Challenge.query.count()

    # Get recent activity
    recent_solves = db.session.query(Solve, Challenge).join(Challenge).filter(
        Solve.user_id == user.id
    ).order_by(Solve.solved_at.desc()).limit(10).all()

    # Get team info
    team_membership = TeamMembership.query.filter_by(user_id=user.id).first()
    team = team_membership.team if team_membership else None

    # Get notifications
    notifications = Notification.query.filter_by(user_id=user.id, read=False).order_by(
        Notification.created_at.desc()
    ).limit(5).all()

    return render_template('dashboard.html',
                         user=user,
                         user_score=user_score,
                         user_rank=user_rank,
                         challenges_solved=challenges_solved,
                         total_challenges=total_challenges,
                         recent_solves=recent_solves,
                         team=team,
                         notifications=notifications)

@app.route('/dashboard/modern')
@login_required
def dashboard_modern():
    """Modern dashboard with enhanced UI"""
    user = get_current_user()

    # Get comprehensive statistics
    user_score = calculate_user_score(user.id)
    user_rank = get_user_rank(user.id)
    challenges_solved = Solve.query.filter_by(user_id=user.id).count()
    total_challenges = Challenge.query.count()
    total_users = User.query.count()

    # Calculate completion rate
    completion_rate = (challenges_solved / total_challenges * 100) if total_challenges > 0 else 0

    # Get category statistics
    category_stats = db.session.query(
        Challenge.category,
        func.count(Challenge.id).label('total'),
        func.count(Solve.id).label('solved')
    ).outerjoin(Solve, (Solve.challenge_id == Challenge.id) & (Solve.user_id == user.id)).group_by(
        Challenge.category
    ).all()

    # Get recent activity
    recent_solves = db.session.query(Solve, Challenge).join(Challenge).filter(
        Solve.user_id == user.id
    ).order_by(Solve.solved_at.desc()).limit(5).all()

    # Get team info
    team_membership = TeamMembership.query.filter_by(user_id=user.id).first()
    team = team_membership.team if team_membership else None

    return render_template('dashboard_modern.html',
                         user=user,
                         user_score=user_score,
                         user_rank=user_rank,
                         challenges_solved=challenges_solved,
                         total_challenges=total_challenges,
                         total_users=total_users,
                         completion_rate=completion_rate,
                         category_stats=category_stats,
                         recent_solves=recent_solves,
                         team=team)

@app.route('/challenges')
@login_required
def challenges():
    """Basic challenges page"""
    user = get_current_user()

    # Get filters from request
    category_filter = request.args.get('category', '')
    difficulty_filter = request.args.get('difficulty', '')
    search_query = request.args.get('search', '')
    solved_filter = request.args.get('solved', '')

    # Build query
    query = Challenge.query

    # Apply filters
    if category_filter:
        query = query.filter(Challenge.category == category_filter)

    if difficulty_filter:
        query = query.filter(Challenge.difficulty == difficulty_filter)

    if search_query:
        query = query.filter(Challenge.title.contains(search_query) |
                           Challenge.description.contains(search_query))

    # Get challenges
    challenges = query.order_by(Challenge.points.asc()).all()

    # Get solved challenge IDs for current user
    solved_ids = set(solve.challenge_id for solve in Solve.query.filter_by(user_id=user.id).all())

    # Filter by solved status
    if solved_filter == 'solved':
        challenges = [c for c in challenges if c.id in solved_ids]
    elif solved_filter == 'unsolved':
        challenges = [c for c in challenges if c.id not in solved_ids]

    # Get category and difficulty info
    categories = ['web', 'crypto', 'pwn', 'reverse', 'forensics', 'misc', 'osint', 'steganography']
    difficulties = ['easy', 'medium', 'hard', 'expert']

    category_info = {
        'web': {'name': 'Web Security', 'icon': 'fas fa-globe', 'color': '#3b82f6'},
        'crypto': {'name': 'Cryptography', 'icon': 'fas fa-lock', 'color': '#8b5cf6'},
        'pwn': {'name': 'Binary Exploitation', 'icon': 'fas fa-bug', 'color': '#ef4444'},
        'reverse': {'name': 'Reverse Engineering', 'icon': 'fas fa-undo', 'color': '#f59e0b'},
        'forensics': {'name': 'Digital Forensics', 'icon': 'fas fa-search', 'color': '#10b981'},
        'misc': {'name': 'Miscellaneous', 'icon': 'fas fa-puzzle-piece', 'color': '#06b6d4'},
        'osint': {'name': 'OSINT', 'icon': 'fas fa-eye', 'color': '#ec4899'},
        'steganography': {'name': 'Steganography', 'icon': 'fas fa-image', 'color': '#84cc16'}
    }

    difficulty_info = {
        'easy': {'name': 'Easy', 'icon': 'fas fa-star', 'color': '#22c55e'},
        'medium': {'name': 'Medium', 'icon': 'fas fa-star-half-alt', 'color': '#f59e0b'},
        'hard': {'name': 'Hard', 'icon': 'fas fa-fire', 'color': '#ef4444'},
        'expert': {'name': 'Expert', 'icon': 'fas fa-crown', 'color': '#8b5cf6'}
    }

    # Calculate statistics
    total_challenges = len(challenges)
    solved_count = len([c for c in challenges if c.id in solved_ids])
    total_points = sum(c.points for c in challenges if c.id in solved_ids)

    return render_template('challenges_basic.html',
                         challenges=challenges,
                         solved_ids=solved_ids,
                         categories=categories,
                         difficulties=difficulties,
                         category_info=category_info,
                         difficulty_info=difficulty_info,
                         category_filter=category_filter,
                         difficulty_filter=difficulty_filter,
                         search_query=search_query,
                         solved_filter=solved_filter,
                         total_challenges=total_challenges,
                         solved_count=solved_count,
                         total_points=total_points)

@app.route('/challenges/enhanced')
@login_required
def challenges_enhanced():
    """Enhanced challenges page with modern UI"""
    user = get_current_user()

    # Get filters from request
    category_filter = request.args.get('category', '')
    difficulty_filter = request.args.get('difficulty', '')
    search_query = request.args.get('search', '')
    solved_filter = request.args.get('solved', '')

    # Build query
    query = Challenge.query

    # Apply filters
    if category_filter:
        query = query.filter(Challenge.category == category_filter)

    if difficulty_filter:
        query = query.filter(Challenge.difficulty == difficulty_filter)

    if search_query:
        query = query.filter(Challenge.title.contains(search_query) |
                           Challenge.description.contains(search_query))

    # Get challenges
    challenges = query.order_by(Challenge.points.asc()).all()

    # Get solved challenge IDs for current user
    solved_ids = set(solve.challenge_id for solve in Solve.query.filter_by(user_id=user.id).all())

    # Filter by solved status
    if solved_filter == 'solved':
        challenges = [c for c in challenges if c.id in solved_ids]
    elif solved_filter == 'unsolved':
        challenges = [c for c in challenges if c.id not in solved_ids]

    # Get category and difficulty info
    categories = ['web', 'crypto', 'pwn', 'reverse', 'forensics', 'misc', 'osint', 'steganography']
    difficulties = ['easy', 'medium', 'hard', 'expert']

    category_info = {
        'web': {'name': 'Web Security', 'icon': 'fas fa-globe', 'color': '#3b82f6'},
        'crypto': {'name': 'Cryptography', 'icon': 'fas fa-lock', 'color': '#8b5cf6'},
        'pwn': {'name': 'Binary Exploitation', 'icon': 'fas fa-bug', 'color': '#ef4444'},
        'reverse': {'name': 'Reverse Engineering', 'icon': 'fas fa-undo', 'color': '#f59e0b'},
        'forensics': {'name': 'Digital Forensics', 'icon': 'fas fa-search', 'color': '#10b981'},
        'misc': {'name': 'Miscellaneous', 'icon': 'fas fa-puzzle-piece', 'color': '#06b6d4'},
        'osint': {'name': 'OSINT', 'icon': 'fas fa-eye', 'color': '#ec4899'},
        'steganography': {'name': 'Steganography', 'icon': 'fas fa-image', 'color': '#84cc16'}
    }

    difficulty_info = {
        'easy': {'name': 'Easy', 'icon': 'fas fa-star', 'color': '#22c55e'},
        'medium': {'name': 'Medium', 'icon': 'fas fa-star-half-alt', 'color': '#f59e0b'},
        'hard': {'name': 'Hard', 'icon': 'fas fa-fire', 'color': '#ef4444'},
        'expert': {'name': 'Expert', 'icon': 'fas fa-crown', 'color': '#8b5cf6'}
    }

    # Calculate statistics
    total_challenges = len(challenges)
    solved_count = len([c for c in challenges if c.id in solved_ids])
    total_points = sum(c.points for c in challenges if c.id in solved_ids)

    return render_template('challenges.html',
                         challenges=challenges,
                         solved_ids=solved_ids,
                         categories=categories,
                         difficulties=difficulties,
                         category_info=category_info,
                         difficulty_info=difficulty_info,
                         category_filter=category_filter,
                         difficulty_filter=difficulty_filter,
                         search_query=search_query,
                         solved_filter=solved_filter,
                         total_challenges=total_challenges,
                         solved_count=solved_count,
                         total_points=total_points)

@app.route('/challenge/<int:challenge_id>')
@login_required
def challenge_detail(challenge_id):
    """Individual challenge page"""
    user = get_current_user()
    challenge = Challenge.query.get_or_404(challenge_id)

    # Check if user has solved this challenge
    solve = Solve.query.filter_by(user_id=user.id, challenge_id=challenge_id).first()
    is_solved = solve is not None

    # Get hints for this challenge
    hints = Hint.query.filter_by(challenge_id=challenge_id).order_by(Hint.cost.asc()).all()

    # Get user's purchased hints
    user_hints = UserHint.query.filter_by(user_id=user.id).all()
    purchased_hint_ids = set(uh.hint_id for uh in user_hints)

    # Get recent submissions for this challenge
    recent_submissions = Submission.query.filter_by(
        user_id=user.id, challenge_id=challenge_id
    ).order_by(Submission.submitted_at.desc()).limit(5).all()

    return render_template('challenge_detail.html',
                         challenge=challenge,
                         is_solved=is_solved,
                         solve=solve,
                         hints=hints,
                         purchased_hint_ids=purchased_hint_ids,
                         recent_submissions=recent_submissions)

@app.route('/submit_flag', methods=['POST'])
@login_required
def submit_flag():
    """Submit a flag for a challenge"""
    user = get_current_user()
    challenge_id = request.form.get('challenge_id', type=int)
    submitted_flag = request.form.get('flag', '').strip()

    if not challenge_id or not submitted_flag:
        flash('Challenge ID and flag are required.', 'error')
        return redirect(url_for('challenges'))

    challenge = Challenge.query.get_or_404(challenge_id)

    # Check if user has already solved this challenge
    existing_solve = Solve.query.filter_by(user_id=user.id, challenge_id=challenge_id).first()
    if existing_solve:
        flash('You have already solved this challenge!', 'info')
        return redirect(url_for('challenge_detail', challenge_id=challenge_id))

    # Record the submission
    submission = Submission(
        user_id=user.id,
        challenge_id=challenge_id,
        submitted_flag=submitted_flag,
        is_correct=False,
        submitted_at=datetime.utcnow()
    )

    try:
        # Validate the flag
        is_correct = validate_flag(submitted_flag, challenge)
        submission.is_correct = is_correct

        db.session.add(submission)

        if is_correct:
            # Create solve record
            solve = Solve(
                user_id=user.id,
                challenge_id=challenge_id,
                solved_at=datetime.utcnow()
            )
            db.session.add(solve)

            # Update user score
            user.score = calculate_user_score(user.id) + challenge.points

            # Create notification
            notification = Notification(
                user_id=user.id,
                title='Challenge Solved!',
                message=f'Congratulations! You solved "{challenge.title}" and earned {challenge.points} points.',
                type='success',
                created_at=datetime.utcnow()
            )
            db.session.add(notification)

            db.session.commit()

            flash(f'Correct! You earned {challenge.points} points!', 'success')

            # Emit real-time notification if SocketIO is available
            if SOCKETIO_AVAILABLE and socketio:
                socketio.emit('solve_notification', {
                    'user': user.username,
                    'challenge': challenge.title,
                    'points': challenge.points
                }, room='global')
        else:
            db.session.commit()
            flash('Incorrect flag. Try again!', 'error')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Flag submission error: {e}")
        flash('An error occurred while processing your submission.', 'error')

    return redirect(url_for('challenge_detail', challenge_id=challenge_id))

# API Routes
@app.route('/api/dashboard/stats')
@login_required
def api_dashboard_stats():
    """API endpoint for dashboard statistics"""
    user = get_current_user()

    user_score = calculate_user_score(user.id)
    user_rank = get_user_rank(user.id)
    challenges_solved = Solve.query.filter_by(user_id=user.id).count()
    total_challenges = Challenge.query.count()
    total_users = User.query.count()

    return jsonify({
        'success': True,
        'username': user.username,
        'user_score': user_score,
        'challenges_solved': challenges_solved,
        'total_challenges': total_challenges,
        'total_users': total_users,
        'user_rank': user_rank
    })

@app.route('/api/challenges/categories')
def api_challenge_categories():
    """API endpoint for challenge categories and difficulties"""
    categories = {
        'web': {'name': 'Web Security', 'icon': 'fas fa-globe', 'color': '#3b82f6'},
        'crypto': {'name': 'Cryptography', 'icon': 'fas fa-lock', 'color': '#8b5cf6'},
        'pwn': {'name': 'Binary Exploitation', 'icon': 'fas fa-bug', 'color': '#ef4444'},
        'reverse': {'name': 'Reverse Engineering', 'icon': 'fas fa-undo', 'color': '#f59e0b'},
        'forensics': {'name': 'Digital Forensics', 'icon': 'fas fa-search', 'color': '#10b981'},
        'misc': {'name': 'Miscellaneous', 'icon': 'fas fa-puzzle-piece', 'color': '#06b6d4'},
        'osint': {'name': 'OSINT', 'icon': 'fas fa-eye', 'color': '#ec4899'},
        'steganography': {'name': 'Steganography', 'icon': 'fas fa-image', 'color': '#84cc16'}
    }

    difficulties = {
        'easy': {'name': 'Easy', 'icon': 'fas fa-star', 'color': '#22c55e'},
        'medium': {'name': 'Medium', 'icon': 'fas fa-star-half-alt', 'color': '#f59e0b'},
        'hard': {'name': 'Hard', 'icon': 'fas fa-fire', 'color': '#ef4444'},
        'expert': {'name': 'Expert', 'icon': 'fas fa-crown', 'color': '#8b5cf6'}
    }

    return jsonify({
        'success': True,
        'categories': categories,
        'difficulties': difficulties
    })

@app.route('/api/challenges')
@login_required
def api_challenges():
    """API endpoint for challenges list"""
    user = get_current_user()

    # Get filters
    category = request.args.get('category')
    difficulty = request.args.get('difficulty')
    search = request.args.get('search')
    solved = request.args.get('solved')

    # Build query
    query = Challenge.query

    if category:
        query = query.filter(Challenge.category == category)
    if difficulty:
        query = query.filter(Challenge.difficulty == difficulty)
    if search:
        query = query.filter(Challenge.title.contains(search) |
                           Challenge.description.contains(search))

    challenges = query.order_by(Challenge.points.asc()).all()

    # Get solved challenge IDs
    solved_ids = set(solve.challenge_id for solve in Solve.query.filter_by(user_id=user.id).all())

    # Filter by solved status
    if solved == 'solved':
        challenges = [c for c in challenges if c.id in solved_ids]
    elif solved == 'unsolved':
        challenges = [c for c in challenges if c.id not in solved_ids]

    # Format response
    challenges_data = []
    for challenge in challenges:
        challenges_data.append({
            'id': challenge.id,
            'title': challenge.title,
            'description': challenge.description,
            'points': challenge.points,
            'category': challenge.category,
            'difficulty': challenge.difficulty,
            'is_solved': challenge.id in solved_ids,
            'created_at': challenge.created_at.isoformat() if challenge.created_at else None
        })

    return jsonify({
        'success': True,
        'challenges': challenges_data,
        'total': len(challenges_data),
        'solved_count': len([c for c in challenges_data if c['is_solved']])
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@ctf.local',
                password_hash=generate_password_hash('admin123'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created: admin/admin123")
    
    if SOCKETIO_AVAILABLE:
        socketio.run(app, debug=True, host='0.0.0.0', port=5000)
    else:
        app.run(debug=True, host='0.0.0.0', port=5000)
