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
    if user.role == 'admin':
        flash('Administrators cannot participate in challenges. Please use the admin panel to manage challenges.', 'warning')
        return redirect(url_for('admin_dashboard'))

    category = request.args.get('category', '')
    difficulty = request.args.get('difficulty', '')

    # Build query
    query = Challenge.query

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
        Challenge.category.isnot(None)
    ).all()
    categories = [cat[0] for cat in categories if cat[0]]

    difficulties = ['easy', 'medium', 'hard', 'expert']

    # Calculate additional stats for the template
    total_challenges = Challenge.query.count()
    solved_count = len(user_solves)

    return render_template('challenges.html',
                         challenges=challenges,
                         user_solves=user_solves,
                         categories=categories,
                         difficulties=difficulties,
                         selected_category=category,
                         selected_difficulty=difficulty,
                         total_challenges=total_challenges,
                         solved_count=solved_count)

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
        all_users = User.query.all()

        for user in all_users:
            # Calculate total score for this user
            total_score = db.session.query(func.sum(Challenge.points)).join(Solve).filter(
                Solve.user_id == user.id
            ).scalar() or 0

            # Count solves for this user
            solve_count = Solve.query.filter_by(user_id=user.id).count()

            # Get last solve time
            last_solve = db.session.query(func.max(Solve.solved_at)).filter(
                Solve.user_id == user.id
            ).scalar()

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

        # Add rank to each user
        for i, user in enumerate(users_data, 1):
            user['rank'] = i

        # Limit to top 100 for display
        users_data = users_data[:100]

        # Calculate statistics
        total_users = User.query.count()
        total_challenges = Challenge.query.count()
        total_solves = Solve.query.count()
        avg_score = sum(user['score'] for user in users_data) / len(users_data) if users_data else 0

        # Get categories for filter
        categories = db.session.query(Challenge.category).distinct().all()
        categories = [cat[0] for cat in categories if cat[0]]

        # Get recent solves for activity feed
        recent_solves = db.session.query(
            Solve.solved_at.label('timestamp'),
            User.username,
            Challenge.title,
            Challenge.points
        ).join(User).join(Challenge).order_by(Solve.solved_at.desc()).limit(10).all()

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
                # Get member's total score
                member_score = db.session.query(func.sum(Challenge.points)).join(Solve).filter(
                    Solve.user_id == member.id
                ).scalar() or 0
                team_score += member_score

                # Get member's solve count
                member_solves = Solve.query.filter_by(user_id=member.id).count()
                team_solves += member_solves

                # Get member's last solve time
                member_last_solve = db.session.query(func.max(Solve.solved_at)).filter(
                    Solve.user_id == member.id
                ).scalar()

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
        recent_solves = db.session.query(
            Solve.solved_at.label('timestamp'),
            User.username,
            Challenge.title,
            Challenge.points,
            Team.name.label('team_name')
        ).join(User).join(Challenge).join(TeamMembership, TeamMembership.user_id == User.id)\
         .join(Team, Team.id == TeamMembership.team_id)\
         .order_by(Solve.solved_at.desc()).limit(15).all()

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

                    # Save file to uploads directory
                    uploads_dir = os.path.join(app.root_path, 'static', 'uploads')
                    os.makedirs(uploads_dir, exist_ok=True)
                    file_path = os.path.join(uploads_dir, unique_filename)
                    file.save(file_path)

                    # Update user profile picture
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
    """Serve profile pictures"""
    import os
    from flask import send_from_directory

    # Check if file exists in uploads directory
    uploads_dir = os.path.join(app.root_path, 'static', 'uploads')
    file_path = os.path.join(uploads_dir, filename)

    if os.path.exists(file_path):
        return send_from_directory(uploads_dir, filename)
    else:
        # Fallback to default avatar
        return redirect(url_for('static', filename='images/default-avatar.svg'))

@app.route('/admin')
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
        ).join(User).join(Challenge).order_by(Solve.solved_at.desc()).limit(10).all()

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
        ).join(Solve).join(Challenge).filter(User.role != 'admin').group_by(User.id).order_by(func.sum(Challenge.points).desc()).limit(5).all()

        # Get team statistics
        team_stats = db.session.query(
            Team.name,
            func.count(TeamMembership.id).label('member_count')
        ).join(TeamMembership).group_by(Team.id).order_by(func.count(TeamMembership.id).desc()).limit(5).all()

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
    challenges = Challenge.query.order_by(Challenge.created_at.desc()).all()

    # Get challenge statistics
    challenge_stats = []
    for challenge in challenges:
        solve_count = Solve.query.filter_by(challenge_id=challenge.id).count()
        challenge_stats.append({
            'challenge': challenge,
            'solve_count': solve_count
        })

    return render_template('admin/challenges.html', challenge_stats=challenge_stats)

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

@app.route('/admin/settings')
@admin_required
def admin_settings():
    """Admin settings page"""
    return render_template('admin/settings.html')

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

# Team Management Routes
@app.route('/teams')
@login_required
def teams():
    """Display teams page with team management"""
    user = User.query.get(session['user_id'])

    # Prevent admin from accessing team features
    if user.role == 'admin':
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
    user = User.query.get(session['user_id'])

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
    user = User.query.get(session['user_id'])

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
    user = User.query.get(session['user_id'])

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
    current_user = User.query.get(session['user_id'])

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

# Chat Routes
@app.route('/chat')
@login_required
def chat():
    """Main chat page"""
    user = User.query.get(session['user_id'])

    # Prevent admin from accessing chat
    if user.role == 'admin':
        flash('Administrators cannot access the chat system.', 'warning')
        return redirect(url_for('admin_dashboard'))

    # Get user's team for team chat
    user_team = None
    team_membership = TeamMembership.query.filter_by(user_id=user.id).first()
    if team_membership:
        user_team = team_membership.team

    return render_template('chat.html', user_team=user_team, current_user=user)

@app.route('/api/chat/messages')
@login_required
def get_chat_messages():
    """Get chat messages for a specific room"""
    room = request.args.get('room', 'general')
    limit = int(request.args.get('limit', 50))
    user = User.query.get(session['user_id'])

    # Prevent admin from accessing chat
    if user.role == 'admin':
        return jsonify({'error': 'Access denied'}), 403

    query = ChatMessage.query

    if room.startswith('team-'):
        # Team chat - verify user is in the team
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
    user = User.query.get(session['user_id'])

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
    user = User.query.get(session['user_id'])

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
    user = User.query.get(session['user_id'])

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
