"""
HUNTING-CTF - Modern Capture The Flag Platform
A clean, modern, and fully functional CTF application
"""

import os
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from sqlalchemy.sql import func

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
    Tournament, Hint, UserHint, Notification, ChatMessage
)
from flask_mail import Mail
from flask_migrate import Migrate
from flask_compress import Compress

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

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
migrate = Migrate(app, db)
mail = Mail(app)
compress = Compress(app)

# Initialize SocketIO if available
if SOCKETIO_AVAILABLE:
    socketio = SocketIO(app, cors_allowed_origins="*")
else:
    socketio = None

# Encryption for flags
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY)

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
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash('Admin privileges required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
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
        actual_flag = decrypt_flag(challenge.flag_encrypted)
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

# Context processors
@app.context_processor
def inject_user():
    return dict(current_user=get_current_user())

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = User.query.get(user_id) if user_id else None

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
        total_users = User.query.count()
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
    user_solves = Solve.query.filter_by(user_id=user.id).count()
    user_score = calculate_user_score(user.id)
    user_rank = get_user_rank(user.id)

    # Get recent activity
    recent_solves = db.session.query(Solve, Challenge).join(Challenge).filter(
        Solve.user_id == user.id
    ).order_by(Solve.solved_at.desc()).limit(10).all()

    # Get available challenges by category
    challenges_by_category = {}
    challenges = Challenge.query.filter_by(active=True).all()

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
    category = request.args.get('category', '')
    difficulty = request.args.get('difficulty', '')

    # Build query
    query = Challenge.query.filter_by(active=True)

    if category:
        query = query.filter_by(category=category)
    if difficulty:
        query = query.filter_by(difficulty=difficulty)

    challenges = query.order_by(Challenge.points.asc()).all()

    # Get user's solves
    user = get_current_user()
    user_solves = {solve.challenge_id for solve in Solve.query.filter_by(user_id=user.id).all()}

    # Get categories and difficulties for filters
    categories = db.session.query(Challenge.category).distinct().filter(
        Challenge.category.isnot(None), Challenge.active == True
    ).all()
    categories = [cat[0] for cat in categories if cat[0]]

    difficulties = ['easy', 'medium', 'hard', 'expert']

    return render_template('challenges.html',
                         challenges=challenges,
                         user_solves=user_solves,
                         categories=categories,
                         difficulties=difficulties,
                         selected_category=category,
                         selected_difficulty=difficulty)

@app.route('/challenge/<int:challenge_id>')
@login_required
def challenge_detail(challenge_id):
    """Individual challenge page"""
    challenge = Challenge.query.get_or_404(challenge_id)
    user = get_current_user()

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

    return render_template('challenge_detail.html',
                         challenge=challenge,
                         solve=solve,
                         hints=hints,
                         revealed_hints=revealed_hints,
                         recent_submissions=recent_submissions)

@app.route('/submit_flag', methods=['POST'])
@login_required
def submit_flag():
    """Submit flag for a challenge"""
    challenge_id = request.form.get('challenge_id', type=int)
    submitted_flag = request.form.get('flag', '').strip()

    if not challenge_id or not submitted_flag:
        return jsonify({'success': False, 'message': 'Challenge ID and flag are required.'})

    challenge = Challenge.query.get(challenge_id)
    if not challenge or not challenge.active:
        return jsonify({'success': False, 'message': 'Challenge not found or inactive.'})

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

@app.route('/scoreboard')
def scoreboard():
    """Public scoreboard"""
    # Get top users by score
    user_scores = db.session.query(
        User.id,
        User.username,
        func.sum(Challenge.points).label('total_score'),
        func.count(Solve.id).label('solve_count'),
        func.max(Solve.solved_at).label('last_solve')
    ).join(Solve).join(Challenge).group_by(User.id, User.username).order_by(
        func.sum(Challenge.points).desc(),
        func.max(Solve.solved_at).asc()
    ).limit(50).all()

    return render_template('scoreboard.html', user_scores=user_scores)

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    user = get_current_user()

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

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    # Get system statistics
    total_users = User.query.count()
    total_challenges = Challenge.query.count()
    total_solves = Solve.query.count()
    total_submissions = Submission.query.count()

    # Get recent activity
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    recent_solves = db.session.query(Solve, User, Challenge).join(User).join(Challenge).order_by(
        Solve.solved_at.desc()
    ).limit(10).all()

    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_challenges=total_challenges,
                         total_solves=total_solves,
                         total_submissions=total_submissions,
                         recent_users=recent_users,
                         recent_solves=recent_solves)

@app.route('/admin/challenges')
@admin_required
def admin_challenges():
    """Admin challenges management"""
    challenges = Challenge.query.order_by(Challenge.created_at.desc()).all()
    return render_template('admin/challenges.html', challenges=challenges)

@app.route('/admin/users')
@admin_required
def admin_users():
    """Admin users management"""
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

# API Routes
@app.route('/api/stats')
def api_stats():
    """API endpoint for basic statistics"""
    total_challenges = Challenge.query.filter_by(active=True).count()
    total_users = User.query.count()
    total_solves = Solve.query.count()

    return jsonify({
        'total_challenges': total_challenges,
        'total_users': total_users,
        'total_solves': total_solves
    })

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
            emit('status', {'message': f'Welcome, {user.username}!'})

    @socketio.on('disconnect')
    def handle_disconnect():
        pass

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

                # Emit to room
                emit('new_message', {
                    'username': user.username,
                    'message': message,
                    'timestamp': datetime.utcnow().isoformat(),
                    'room': room
                }, room=room)

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            print("✅ Database tables created/verified")

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
                print("✅ Admin user created: admin/admin123")
        except Exception as e:
            print(f"⚠️ Database initialization error: {e}")

    if SOCKETIO_AVAILABLE:
        socketio.run(app, debug=True, host='0.0.0.0', port=5000)
    else:
        app.run(debug=True, host='0.0.0.0', port=5000)
