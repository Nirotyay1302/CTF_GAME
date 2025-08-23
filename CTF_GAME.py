from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify, send_from_directory, g
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os
import time
from datetime import datetime, timedelta
import functools
from sqlalchemy.sql import func
from sqlalchemy import text
from flask_mail import Mail, Message
from flask_migrate import Migrate
from models import (
    db,
    User,
    Challenge,
    Solve,
    Submission,
    Team,
    TeamMembership,
    Tournament,
    Hint,
    UserHint,
    Achievement,
    UserAchievement,
    ChallengeTemplate,
    DynamicChallenge,
    UserProgress,
    Notification,
    ChatMessage,
    ChatChannel,
)
import threading
import json
from dynamic_challenges import (
    generate_crypto_base64_flag,
    generate_stego_text_image,
)
import secrets
import hashlib
import random
import string
from werkzeug.utils import secure_filename
import mimetypes
from config import Config


# Simplified tournament timer functions
def start_tournament_timer():
    """Start background task for tournament timer updates"""
    pass  # Simplified - no background timer needed

def broadcast_tournament_timer():
    """Broadcast tournament timer updates"""
    pass  # Simplified - no background timer needed

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Aggressive performance optimizations for speed
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 20,           # Increased pool size
    'pool_recycle': 300,       # Longer recycle time
    'pool_pre_ping': True,
    'max_overflow': 30,        # Higher overflow
    'pool_timeout': 10,        # Faster timeout
    'echo': False,             # Disable SQL logging
    'connect_args': {
        'connect_timeout': 5,
        'application_name': 'ctf_app_fast'
    }
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_RECORD_QUERIES'] = False  # Disable query recording

# Template optimization for speed
app.jinja_env.auto_reload = False
app.jinja_env.cache_size = 1000  # Increased cache size
app.jinja_env.optimized = True

mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize compression for faster responses
try:
    from flask_compress import Compress
    app.config['COMPRESS_MIMETYPES'] = [
        'text/html', 'text/css', 'text/xml', 'text/javascript',
        'application/json', 'application/javascript', 'application/xml+rss',
        'application/atom+xml', 'image/svg+xml'
    ]
    app.config['COMPRESS_LEVEL'] = 6
    app.config['COMPRESS_MIN_SIZE'] = 500
    Compress(app)
    print("✅ Response compression enabled")
except ImportError:
    print("⚠️ Flask-Compress not available")

# Initialize database with app
db.init_app(app)
Migrate(app, db)

# Aggressive multi-level caching for maximum speed
cache = {}
cache_stats = {'hits': 0, 'misses': 0, 'sets': 0}

# Different cache timeouts for different data types
cache_timeouts = {
    'leaderboard': 60,      # 1 minute - frequently changing
    'challenge_stats': 180, # 3 minutes - moderately changing
    'user_profile': 30,     # 30 seconds - user-specific
    'challenge_list': 120,  # 2 minutes - semi-static
    'team_stats': 240,      # 4 minutes - less frequently changing
    'recent_solves': 15,    # 15 seconds - very dynamic
    'dashboard_data': 45,   # 45 seconds - user dashboard
    'admin_stats': 300,     # 5 minutes - admin data
    'default': 120          # 2 minutes default
}

def get_from_cache(key, generator_func, timeout=None):
    """Get data from cache or generate if expired - optimized for speed"""
    now = time.time()

    # Determine timeout based on key prefix
    if timeout is None:
        key_prefix = key.split('_')[0] if '_' in key else 'default'
        timeout = cache_timeouts.get(key_prefix, cache_timeouts['default'])

    # Check cache first
    if key in cache:
        data, timestamp = cache[key]
        if now - timestamp < timeout:
            cache_stats['hits'] += 1
            return data

    # Cache miss - generate fresh data
    cache_stats['misses'] += 1
    try:
        data = generator_func()
        cache[key] = (data, now)
        cache_stats['sets'] += 1

        # Prevent cache from growing too large (memory optimization)
        if len(cache) > 1000:
            # Remove oldest 20% of entries
            sorted_cache = sorted(cache.items(), key=lambda x: x[1][1])
            for old_key, _ in sorted_cache[:200]:
                cache.pop(old_key, None)

        return data
    except Exception as e:
        print(f"Cache generation error for {key}: {e}")
        return None

def clear_cache(pattern=None):
    """Clear cache entries - optimized"""
    if pattern:
        keys_to_remove = [k for k in cache.keys() if pattern in k]
        for key in keys_to_remove:
            cache.pop(key, None)
    else:
        cache.clear()
        cache_stats['hits'] = cache_stats['misses'] = cache_stats['sets'] = 0

def get_cache_stats():
    """Get cache performance statistics"""
    total_requests = cache_stats['hits'] + cache_stats['misses']
    hit_rate = (cache_stats['hits'] / total_requests * 100) if total_requests > 0 else 0
    return {
        'entries': len(cache),
        'hits': cache_stats['hits'],
        'misses': cache_stats['misses'],
        'hit_rate': round(hit_rate, 2),
        'total_requests': total_requests
    }

# Performance monitoring
@app.before_request
def before_request():
    """Record request start time"""
    g.start_time = time.time()

@app.after_request
def after_request(response):
    """Optimized response processing for maximum speed"""
    if hasattr(g, 'start_time'):
        duration = time.time() - g.start_time
        response.headers['X-Response-Time'] = f"{duration:.3f}s"

        # Log slow requests (reduced threshold for better monitoring)
        if duration > 1.0:  # Log requests taking more than 1 second
            print(f"⚠️ Slow request: {request.endpoint} took {duration:.2f}s")

    # Aggressive caching for static files
    if request.endpoint and 'static' in request.endpoint:
        response.cache_control.max_age = 86400  # 24 hours
        response.cache_control.public = True
        response.headers['Expires'] = (datetime.utcnow() + timedelta(days=1)).strftime('%a, %d %b %Y %H:%M:%S GMT')

    # Cache API responses
    if request.endpoint and 'api' in request.endpoint:
        response.cache_control.max_age = 30  # 30 seconds for API
        response.cache_control.public = True

    # Cache page responses
    if request.endpoint in ['dashboard', 'scoreboard', 'challenges']:
        response.cache_control.max_age = 60  # 1 minute for pages
        response.cache_control.public = True

    # Security headers (minimal for speed)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'

    # Performance headers
    response.headers['X-Cache-Status'] = 'HIT' if hasattr(g, 'cache_hit') else 'MISS'

    return response

# Cached data generators
def generate_leaderboard_data():
    """Generate leaderboard data"""
    users = User.query.filter(User.role != 'admin').order_by(User.score.desc()).limit(50).all()
    return [
        {
            'username': user.username,
            'total_points': user.score,
            'team_name': user.team.name if user.team else None
        }
        for user in users
    ]

def generate_challenge_stats():
    """Generate challenge statistics"""
    challenges = Challenge.query.all()
    stats = {
        'total_challenges': len(challenges),
        'categories': {},
        'difficulties': {},
        'total_points': 0
    }

    for challenge in challenges:
        stats['categories'][challenge.category] = stats['categories'].get(challenge.category, 0) + 1
        stats['difficulties'][challenge.difficulty] = stats['difficulties'].get(challenge.difficulty, 0) + 1
        stats['total_points'] += challenge.points

    return stats

# Add cached functions to app
app.get_cached_leaderboard = lambda: get_from_cache('leaderboard', generate_leaderboard_data)
app.get_cached_challenge_stats = lambda: get_from_cache('challenge_stats', generate_challenge_stats)

# Start tournament timer background task once per process (for production servers too)
if not app.config.get('TOURNAMENT_TIMER_STARTED'):
    try:
        start_tournament_timer()
        app.config['TOURNAMENT_TIMER_STARTED'] = True
    except Exception as _e:
        print(f"[WARN] Could not start tournament timer: {_e}")

# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')

@socketio.on('join_tournament')
def handle_join_tournament():
    """Handle client joining tournament room"""
    active_tournament = Tournament.query.filter_by(active=True).first()
    if active_tournament:
        emit('tournament_update', {
            'name': active_tournament.name,
            'end_time': active_tournament.end_time.isoformat(),
            'active': True
        })

@socketio.on('join_leaderboard')
def handle_join_leaderboard():
    """Handle client joining leaderboard room"""
    # Send initial leaderboard data
    send_leaderboard_updates()

def send_leaderboard_updates():
    """Send leaderboard updates to all connected clients"""
    try:
        # Individual leaderboard
        players = (
            db.session.query(User.username, User.score)
            .filter(User.role != 'admin')
            .order_by(User.score.desc(), User.username)
            .limit(50)
            .all()
        )
        
        individual_data = [{
            'username': player.username,
            'score': player.score
        } for player in players]
        
        # Team leaderboard
        teams = (
            db.session.query(
                Team.name,
                func.coalesce(func.sum(User.score), 0).label('score'),
                func.count(User.id).label('members')
            )
            .join(TeamMembership, TeamMembership.team_id == Team.id)
            .join(User, User.id == TeamMembership.user_id)
            .group_by(Team.id)
            .order_by(func.coalesce(func.sum(User.score), 0).desc(), Team.name)
            .limit(50)
            .all()
        )
        
        teams_data = [{
            'name': team.name,
            'score': team.score,
            'members': team.members
        } for team in teams]
        
        # Broadcast updates
        socketio.emit('leaderboard_update', {
            'type': 'individual',
            'players': individual_data
        })
        
        socketio.emit('leaderboard_update', {
            'type': 'teams',
            'teams': teams_data
        })
        
    except Exception as e:
        print(f"Error sending leaderboard updates: {e}")



FERNET_KEY = os.getenv('FERNET_KEY')
if not FERNET_KEY:
    # Use persistent local key file for dev; avoids committing secrets
    os.makedirs(app.instance_path, exist_ok=True)
    key_path = os.path.join(app.instance_path, 'fernet.key')
    if os.path.exists(key_path):
        with open(key_path, 'rb') as fh:
            FERNET_KEY = fh.read().strip()
    else:
        generated = Fernet.generate_key()
        with open(key_path, 'wb') as fh:
            fh.write(generated)
        FERNET_KEY = generated
fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)

def trigger_export_async():
    """Kick off Excel export in the background; log errors without interrupting user flow."""
    try:
        from export_to_excel import export_all_to_excel
        threading.Thread(target=export_all_to_excel, daemon=True).start()
    except Exception as e:
        print(f"[EXPORT ERROR] Failed to start export thread: {e}")

def get_admin_email():
    """Return admin notification email from env or first admin user."""
    admin_email_env = os.getenv("ADMIN_EMAIL")
    if admin_email_env:
        return admin_email_env
    try:
        admin_user = User.query.filter_by(role='admin').first()
        if admin_user and admin_user.email:
            return admin_user.email
    except Exception:
        pass
    return None

def notify_admin(subject: str, body: str) -> None:
    """Send a notification email to the admin address if available."""
    admin_email = get_admin_email()
    if not admin_email:
        print(f"[ADMIN NOTIFY] No admin email configured. Subject: {subject}")
        return
    send_email(admin_email, subject, body)

def send_email(to_email, subject, body, html: str | None = None, cc: list | None = None, bcc: list | None = None, reply_to: str | None = None):
    try:
        msg = Message(subject, recipients=[to_email], cc=cc or [], bcc=bcc or [], reply_to=reply_to)
        msg.body = body or ''
        if html:
            msg.html = html
        # Mark emails as high priority
        try:
            msg.extra_headers = {
                'X-Priority': '1',
                'X-MSMail-Priority': 'High',
                'Importance': 'High',
            }
        except Exception:
            pass
        if app.config.get('MAIL_SUPPRESS_SEND'):
            print(f"[EMAIL SUPPRESSED] To: {to_email} | Subject: {subject}\nBody: {body}\nHTML: {bool(html)}")
        else:
            mail.send(msg)
        print(f"[EMAIL SENT] To: {to_email} | Subject: {subject}")
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send email to {to_email}: {e}")

# =================== ROUTES =====================

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password', '')
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for('signup'))
        if len(password) < 6:
            flash("Password must be at least 6 characters long", "error")
            return redirect(url_for('signup'))
        # Check if username or email already exists
        existing_user = User.query.filter((User.username == username)|(User.email == email)).first()
        if existing_user:
            flash("Username or email already exists", "error")
            return redirect(url_for('signup'))
        
        # If no existing user found, allow creation (this handles the case where user was previously deleted)
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()  # <-- ADD THIS LINE
        trigger_export_async()
        notify_admin(
            "New user signup",
            f"User '{new_user.username}' ({new_user.email}) has signed up."
        )
        send_email(
            new_user.email,
            "🎉 Welcome to the CTF Game!",
            f"Hello {new_user.username},\n\nYou're successfully signed up! Let's start solving challenges and capture the flags! 💥",
            html=f"<p>Hello <strong>{new_user.username}</strong>,</p><p>You're successfully signed up! Let's start solving challenges and capture the flags! 💥</p>"
        )
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            # Send email on successful login only for non-admin users and only once
            if user.role != 'admin' and 'login_email_sent' not in session:
                send_email(
                    user.email,
                    "🔓 Login Successful - CTF Game",
                    f"Hello {user.username},\n\nYou have successfully logged in to the CTF platform.",
                    html=f"<p>Hello <strong>{user.username}</strong>,</p><p>You have successfully logged in to the CTF platform.</p>"
                )
                # Mark that login email has been sent to prevent duplicates
                session['login_email_sent'] = True
            return redirect(url_for('dashboard'))
        flash("Invalid credentials", "error")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """Main dashboard - now redirects to enhanced dashboard"""
    return redirect(url_for('dashboard_enhanced'))

@app.route('/dashboard/fast')
def dashboard_fast():
    """Ultra-fast dashboard with minimal loading"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Just render the template - data loaded via AJAX for maximum speed
    return render_template('dashboard_fast.html')

@app.route('/dashboard/enhanced')
def dashboard_enhanced():
    """Enhanced dashboard with modern UI and real-time features"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    if user.role == 'admin':
        flash("Admins cannot play the game. You have access to admin controls only.", "info")
        return redirect(url_for('admin_panel'))
    db.session.refresh(user)  # Ensure latest score
    now = datetime.utcnow()
    # Super-optimized dashboard data loading with aggressive caching
    dashboard_cache_key = f"dashboard_data_{user.id}"

    def generate_dashboard_data():
        # Single optimized query for challenges with solve status
        challenges_query = db.session.query(
            Challenge.id,
            Challenge.title,
            Challenge.description,
            Challenge.points,
            Challenge.category,
            Challenge.difficulty,
            Challenge.opens_at,
            Challenge.closes_at,
            Solve.id.isnot(None).label('is_solved')
        ).outerjoin(
            Solve, (Challenge.id == Solve.challenge_id) & (Solve.user_id == user.id)
        ).filter(
            (Challenge.opens_at.is_(None) | (Challenge.opens_at <= now)) &
            (Challenge.closes_at.is_(None) | (Challenge.closes_at > now))
        )

        challenges_data = challenges_query.all()
        solved_ids = {c.id for c in challenges_data if c.is_solved}

        return {
            'challenges': challenges_data,
            'solved_ids': solved_ids,
            'challenge_count': len(challenges_data),
            'solved_count': len(solved_ids)
        }

    # Get cached dashboard data
    dashboard_data = get_from_cache(dashboard_cache_key, generate_dashboard_data, timeout=45)

    if not dashboard_data:
        # Fallback to basic data if cache fails
        challenges = Challenge.query.limit(50).all()  # Limit for speed
        solved_ids = set()
        dashboard_data = {
            'challenges': challenges,
            'solved_ids': solved_ids,
            'challenge_count': len(challenges),
            'solved_count': 0
        }

    # Extract data from dashboard_data
    challenges = dashboard_data.get('challenges', [])
    solved_ids = dashboard_data.get('solved_ids', set())

    # Get cached stats
    stats_data = get_from_cache('challenge_stats', generate_challenge_stats, timeout=180)
    total_challenges = stats_data.get('total_challenges', 0) if stats_data else dashboard_data.get('challenge_count', 0)
    max_score = stats_data.get('total_points', 0) if stats_data else 0

    # Get cached counts
    def generate_counts():
        return {
            'total_players': User.query.filter(User.role != 'admin').count(),
            'total_solves': Solve.query.count() if 'Solve' in globals() else 0
        }

    counts_data = get_from_cache('player_counts', generate_counts, timeout=120)
    total_players = counts_data.get('total_players', 0) if counts_data else 0
    total_solves = counts_data.get('total_solves', 0) if counts_data else 0
    
    # Get user's team information
    user_team = None
    team_score = 0
    membership = TeamMembership.query.filter_by(user_id=session['user_id']).first()
    if membership:
        user_team = db.session.get(Team, membership.team_id)
        if user_team:
            # Calculate team score
            team_members = (
                db.session.query(User.score)
                .join(TeamMembership, TeamMembership.user_id == User.id)
                .filter(TeamMembership.team_id == user_team.id)
                .all()
            )
            team_score = sum(member.score for member in team_members)
    
    # Get revealed hints for this user
    revealed_hint_ids = set(h.hint_id for h in UserHint.query.filter_by(user_id=session['user_id']).all())

    # Get active tournament
    active_tournament = Tournament.query.filter_by(active=True).first()
    
    return render_template(
        'dashboard_enhanced.html',
        username=user.username,
        user=user,
        challenges=challenges,
        solved_ids=solved_ids,
        total_players=total_players,
        total_challenges=total_challenges,
        total_solves=total_solves,
        user_score=user.score,
        user_team=user_team,
        team_score=team_score,
        active_tournament=active_tournament,
        revealed_hint_ids=revealed_hint_ids,
        last_updated=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

@app.route('/challenge/<int:challenge_id>')
def challenge_enhanced(challenge_id):
    """Optimized challenge view with fast loading and caching"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Use caching for faster loading
    cache_key = f"challenge_data_{challenge_id}_{user_id}"

    def generate_challenge_data():
        # Single optimized query to get user and check admin role
        user = db.session.query(User.id, User.role, User.username, User.profile_picture).filter_by(id=user_id).first()
        if not user:
            return None

        if user.role == 'admin':
            return {'error': 'admin_not_allowed'}

        # Get challenge with optimized query
        challenge = db.session.query(
            Challenge.id,
            Challenge.title,
            Challenge.description,
            Challenge.points,
            Challenge.category,
            Challenge.difficulty,
            Challenge.opens_at,
            Challenge.closes_at
        ).filter_by(id=challenge_id).first()

        if not challenge:
            return {'error': 'challenge_not_found'}

        # Time window guard
        now = datetime.utcnow()
        if (challenge.opens_at and now < challenge.opens_at) or (challenge.closes_at and now >= challenge.closes_at):
            return {'error': 'challenge_not_available'}

        # Optimized query to check if user solved this challenge
        is_solved = db.session.query(Solve.id).filter_by(
            user_id=user_id,
            challenge_id=challenge_id
        ).first() is not None

        # Get revealed hints for this user (optimized query)
        revealed_hint_ids = set(
            h.hint_id for h in db.session.query(UserHint.hint_id).filter_by(user_id=user_id).all()
        )

        # Get challenge hints
        hints = db.session.query(
            Hint.id,
            Hint.text,
            Hint.cost,
            Hint.display_order
        ).filter_by(challenge_id=challenge_id).order_by(Hint.display_order).all()

        return {
            'user': user,
            'challenge': challenge,
            'is_solved': is_solved,
            'revealed_hint_ids': revealed_hint_ids,
            'hints': hints
        }

    # Get cached data (30 second cache for challenge data)
    data = get_from_cache(cache_key, generate_challenge_data, timeout=30)

    if not data:
        flash('Error loading challenge data.', 'error')
        return redirect(url_for('dashboard'))

    if 'error' in data:
        if data['error'] == 'admin_not_allowed':
            flash("Admins cannot play the game.", "error")
            return redirect(url_for('admin_panel'))
        elif data['error'] == 'challenge_not_found':
            flash('Challenge not found.', 'danger')
            return redirect(url_for('dashboard'))
        elif data['error'] == 'challenge_not_available':
            flash('Challenge is not currently available.', 'error')
            return redirect(url_for('dashboard'))

    # Get message from flash or session
    message = request.args.get('message')

    return render_template(
        'challenge_enhanced.html',
        challenge=data['challenge'],
        is_solved=data['is_solved'],
        revealed_hint_ids=data['revealed_hint_ids'],
        hints=data['hints'],
        message=message,
        user=data['user']
    )

@app.route('/challenge/<int:challenge_id>/fast')
def challenge_fast(challenge_id):
    """Ultra-fast challenge page with AJAX loading"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    if user.role == 'admin':
        flash("Admins cannot play the game.", "error")
        return redirect(url_for('admin_panel'))

    # Just get basic challenge info for initial render
    challenge = db.session.query(Challenge.id, Challenge.title).filter_by(id=challenge_id).first()
    if not challenge:
        flash('Challenge not found.', 'danger')
        return redirect(url_for('dashboard'))

    return render_template('challenge_fast.html', challenge=challenge)

@app.route('/submit/<int:challenge_id>', methods=['POST'])
def submit_flag(challenge_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    if user.role == 'admin':
        flash("Admins cannot submit flags.", "error")
        return redirect(url_for('admin_panel'))
    challenge = db.session.get(Challenge, challenge_id)
    if not challenge:
        flash('Challenge not found.', 'danger')
        return redirect(url_for('dashboard'))
    # Time window guard
    now = datetime.utcnow()
    if (challenge.opens_at and now < challenge.opens_at) or (challenge.closes_at and now >= challenge.closes_at):
        flash('Challenge is not currently available.', 'error')
        return redirect(url_for('dashboard'))
    # Prevent double scoring for already-solved challenges
    already_solved = db.session.query(Solve.id).filter_by(user_id=user.id, challenge_id=challenge.id).first()
    if already_solved:
        flash('You have already solved this challenge. No additional points awarded.', 'info')
        return redirect(url_for('dashboard'))
    submitted_flag = request.form.get('flag')
    try:
        submission = Submission(user_id=user.id, challenge_id=challenge_id, submitted_flag=submitted_flag)
        is_correct = False
        try:
            if challenge.flag_hash and challenge.flag_salt:
                candidate = hashlib.sha256(challenge.flag_salt + submitted_flag.strip().encode()).digest()
                is_correct = secrets.compare_digest(candidate, challenge.flag_hash)
            else:
                correct_flag = fernet.decrypt(challenge.flag_encrypted).decode()
                is_correct = (submitted_flag.strip() == correct_flag)
        except Exception:
            is_correct = False
        if is_correct:
            submission.correct = True
            user.score += challenge.points
            db.session.add(Solve(user_id=user.id, challenge_id=challenge.id))
            db.session.commit()  # Commit to ensure score is updated
            
            # Send real-time updates
            try:
                socketio.emit('score_update', {
                    'username': user.username,
                    'score': user.score
                })
                send_leaderboard_updates()
            except Exception as e:
                print(f"Error sending real-time updates: {e}")
            
            flash(f'✅ Correct! You earned {challenge.points} points.', 'success')
            
            # Create notification for challenge solved
            create_notification(
                user_id=user.id,
                title="🎯 Challenge Solved!",
                message=f"You successfully solved '{challenge.title}' and earned {challenge.points} points. Your new score is {user.score}.",
                notification_type="challenge_solved",
                related_id=challenge.id,
                related_type="challenge",
                priority="high"
            )
            
            try:
                send_email(
                    user.email,
                    "✅ Challenge Solved!",
                    f"Great job {user.username}! You solved '{challenge.title}' and earned {challenge.points} points. Your new score is {user.score}.",
                    html=f"<p>Great job <strong>{user.username}</strong>! You solved '<em>{challenge.title}</em>' and earned <strong>{challenge.points}</strong> points. Your new score is <strong>{user.score}</strong>.</p>"
                )
            except Exception:
                pass
            notify_admin(
                "Challenge solved",
                f"User '{user.username}' solved '{challenge.title}' for {challenge.points} points. New score: {user.score}."
            )

            # Award achievements and update streaks
            try:
                # Streaks
                today = datetime.utcnow().date()
                if user.last_solve_date == today:
                    pass
                elif user.last_solve_date == (today - timedelta(days=1)):
                    user.current_streak = (user.current_streak or 0) + 1
                else:
                    user.current_streak = 1
                user.longest_streak = max(user.longest_streak or 0, user.current_streak or 0)
                user.last_solve_date = today

                # Ensure base achievements exist
                def ensure_achievement(code, title, desc):
                    ach = Achievement.query.filter_by(code=code).first()
                    if not ach:
                        ach = Achievement(code=code, title=title, description=desc)
                        db.session.add(ach)
                        db.session.flush()
                    return ach

                first_blood = ensure_achievement('FIRST_BLOOD', 'First Blood', 'Be the first to solve a challenge')
                speed_solver = ensure_achievement('SPEED_SOLVER', 'Speed Solver', 'Solve a challenge within 10 minutes of release')

                # First Blood: first solve for this challenge overall
                solve_count = db.session.query(func.count(Solve.id)).filter(Solve.challenge_id == challenge.id).scalar() or 0
                if solve_count == 0:
                    # Current submission will be the first; award after commit via flag
                    pass

                # Speed Solver: within 10 minutes of challenge creation
                created_at = getattr(challenge, 'created_at', None)
                if created_at and (datetime.utcnow() - created_at) <= timedelta(minutes=10):
                    if not UserAchievement.query.filter_by(user_id=user.id, achievement_id=speed_solver.id).first():
                        db.session.add(UserAchievement(user_id=user.id, achievement_id=speed_solver.id))

            except Exception:
                pass
        else:
            submission.correct = False
            flash('❌ Incorrect flag. Try again or click "Show Answer".', 'danger')
        db.session.add(submission)
        db.session.commit()
        # Post-commit check for First Blood (after Solve row persisted)
        try:
            first_blood_ach = Achievement.query.filter_by(code='FIRST_BLOOD').first()
            if first_blood_ach:
                solve_rank = (
                    db.session.query(func.count(Solve.id))
                    .filter(Solve.challenge_id == challenge.id, Solve.id <= submission.id)
                    .scalar() or 0
                )
                if solve_rank == 1 and not UserAchievement.query.filter_by(user_id=user.id, achievement_id=first_blood_ach.id).first():
                    db.session.add(UserAchievement(user_id=user.id, achievement_id=first_blood_ach.id))
                    db.session.commit()
        except Exception:
            pass
        trigger_export_async()
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {e}', 'danger')
        return redirect(url_for('dashboard'))

    # Game completion check (move this inside the function)
    total_challenges = Challenge.query.count()
    solved_challenges = db.session.query(Solve).filter_by(user_id=user.id).count()
    if solved_challenges == total_challenges and total_challenges > 0 and user.role != 'admin':
        # Check if completion email has already been sent
        if 'completion_email_sent' not in session:
            send_email(
                user.email,
                "🏆 Congratulations on Completing the CTF!",
                f"Great job, {user.username}!\n\nYou've completed all {total_challenges} challenges and scored {user.score} points.\n\nThanks for playing!",
                html=f"<p>Great job, <strong>{user.username}</strong>!</p><p>You've completed all <strong>{total_challenges}</strong> challenges and scored <strong>{user.score}</strong> points.</p><p>Thanks for playing!</p>"
            )
            # Mark that completion email has been sent to prevent duplicates
            session['completion_email_sent'] = True
    
    # Redirect to enhanced challenge view with appropriate message
    if is_correct:
        return redirect(url_for('challenge_enhanced', challenge_id=challenge_id, message=f'✅ Correct! You earned {challenge.points} points.'))
    else:
        return redirect(url_for('challenge_enhanced', challenge_id=challenge_id, message='❌ Incorrect flag. Try again or click "Show Answer".'))


@app.route('/api/submit_flag/<int:challenge_id>', methods=['POST'])
def api_submit_flag(challenge_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    user = db.session.get(User, session['user_id'])
    if user.role == 'admin':
        return jsonify({'success': False, 'error': 'Admins cannot submit flags.'}), 403
    challenge = db.session.get(Challenge, challenge_id)
    if not challenge:
        return jsonify({'success': False, 'error': 'Challenge not found.'}), 404
    # Time window guard
    now = datetime.utcnow()
    if (challenge.opens_at and now < challenge.opens_at) or (challenge.closes_at and now >= challenge.closes_at):
        return jsonify({'success': False, 'error': 'Challenge is not currently available.'}), 403
    # Prevent double scoring for already-solved challenges
    already_solved = db.session.query(Solve.id).filter_by(user_id=user.id, challenge_id=challenge.id).first()
    if already_solved:
        return jsonify({'success': True, 'correct': True, 'message': 'Already solved', 'new_score': user.score})

    # Support JSON or form body
    submitted_flag = None
    try:
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            submitted_flag = (payload.get('flag') or '').strip()
        if not submitted_flag:
            submitted_flag = (request.form.get('flag') or '').strip()
    except Exception:
        submitted_flag = (request.form.get('flag') or '').strip()

    if not submitted_flag:
        return jsonify({'success': False, 'error': 'Flag is required'}), 400

    try:
        submission = Submission(user_id=user.id, challenge_id=challenge_id, submitted_flag=submitted_flag)
        is_correct = False
        try:
            if challenge.flag_hash and challenge.flag_salt:
                candidate = hashlib.sha256(challenge.flag_salt + submitted_flag.encode()).digest()
                is_correct = secrets.compare_digest(candidate, challenge.flag_hash)
            else:
                correct_flag = fernet.decrypt(challenge.flag_encrypted).decode()
                is_correct = (submitted_flag == correct_flag)
        except Exception:
            is_correct = False

        if is_correct:
            submission.correct = True
            user.score += challenge.points
            db.session.add(Solve(user_id=user.id, challenge_id=challenge.id))
            db.session.add(submission)
            db.session.commit()
            # Realtime
            try:
                socketio.emit('score_update', {'username': user.username, 'score': user.score})
                send_leaderboard_updates()
            except Exception:
                pass
            return jsonify({'success': True, 'correct': True, 'message': f'Correct! +{challenge.points} points', 'new_score': user.score})
        else:
            submission.correct = False
            db.session.add(submission)
            db.session.commit()
            return jsonify({'success': True, 'correct': False, 'message': 'Incorrect flag. Try again.', 'new_score': user.score})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/show_answer/<int:challenge_id>')
def show_answer(challenge_id):
    """Show challenge answer with enhanced error handling"""
    if 'user_id' not in session:
        if request.args.get('format') == 'json':
            return jsonify({'error': 'Not authenticated'}), 401
        return redirect(url_for('login'))

    # Admins should not play
    if session.get('role') == 'admin':
        if request.args.get('format') == 'json':
            return jsonify({'error': 'Admins cannot view answers'}), 403
        flash("Admins cannot view answers.", "error")
        return redirect(url_for('admin_panel'))

    challenge = db.session.get(Challenge, challenge_id)
    if not challenge:
        if request.args.get('format') == 'json':
            return jsonify({'error': 'Challenge not found'}), 404
        flash('Challenge not found.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        # Try to decrypt the flag with enhanced debugging
        print(f"Attempting to decrypt flag for challenge {challenge_id}")
        print(f"Challenge flag_encrypted exists: {bool(challenge.flag_encrypted)}")
        print(f"Challenge flag_encrypted type: {type(challenge.flag_encrypted)}")

        if challenge.flag_encrypted:
            try:
                answer = fernet.decrypt(challenge.flag_encrypted).decode()
                print(f"Successfully decrypted flag: {answer}")
            except Exception as decrypt_error:
                print(f"Fernet decryption failed: {decrypt_error}")
                # Try alternative method - maybe it's stored as string
                try:
                    if isinstance(challenge.flag_encrypted, str):
                        answer = challenge.flag_encrypted
                        print(f"Using flag_encrypted as string: {answer}")
                    else:
                        answer = "Decryption failed"
                except Exception as alt_error:
                    print(f"Alternative method failed: {alt_error}")
                    answer = "Decryption failed"
        else:
            answer = "No flag data available"
            print("No flag_encrypted field found")

        # Log the final answer for debugging
        print(f"Final answer for challenge {challenge_id}: {answer}")

    except Exception as e:
        print(f"Error retrieving answer for challenge {challenge_id}: {e}")
        answer = f"Error: {str(e)}"

        if request.args.get('format') == 'json':
            return jsonify({'error': 'Error retrieving answer', 'details': str(e)}), 500

    # Check if request wants JSON (for enhanced challenge view)
    if request.headers.get('Accept') == 'application/json' or request.args.get('format') == 'json':
        return jsonify({'success': True, 'answer': answer})

    return render_template('show_answer.html', challenge=challenge, answer=answer)

@app.route('/debug/challenges')
def debug_challenges():
    """Debug route to check challenge flags"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    challenges = Challenge.query.limit(5).all()
    debug_info = []

    for challenge in challenges:
        info = {
            'id': challenge.id,
            'title': challenge.title,
            'has_flag_encrypted': bool(challenge.flag_encrypted),
            'flag_encrypted_type': str(type(challenge.flag_encrypted)),
            'flag_encrypted_length': len(challenge.flag_encrypted) if challenge.flag_encrypted else 0,
            'has_flag_hash': bool(challenge.flag_hash),
            'has_flag_salt': bool(challenge.flag_salt)
        }

        # Try to decrypt
        try:
            if challenge.flag_encrypted:
                decrypted = fernet.decrypt(challenge.flag_encrypted).decode()
                info['decrypted_flag'] = decrypted
                info['decryption_success'] = True
            else:
                info['decryption_success'] = False
                info['decrypted_flag'] = None
        except Exception as e:
            info['decryption_success'] = False
            info['decryption_error'] = str(e)
            info['decrypted_flag'] = None

        debug_info.append(info)

    return jsonify({'challenges': debug_info})

@app.route('/scoreboard')
def scoreboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        # Get current user for highlighting
        current_user = db.session.get(User, session['user_id'])
        if not current_user:
            session.clear()
            return redirect(url_for('login'))

        # Get filter parameters
        category_filter = request.args.get('category', 'all')
        time_filter = request.args.get('time', 'all')

        # Use cached data for better performance
        challenge_stats = get_from_cache('challenge_stats', generate_challenge_stats)

        # Get basic stats
        total_users = User.query.filter(User.role != 'admin').count()
        total_challenges = challenge_stats['total_challenges']

        # Count solves for non-admin users only
        total_solves = (
            db.session.query(func.count(Solve.id))
            .join(User, Solve.user_id == User.id)
            .filter(User.role != 'admin')
            .scalar()
        ) or 0

        # Super-optimized scoreboard query with caching
        scoreboard_cache_key = f"scoreboard_{category_filter}_{time_filter}"

        def generate_scoreboard_data():
            # Optimized single query with minimal data transfer
            base_query = db.session.query(
                User.id,
                User.username,
                User.score,
                User.country,
                func.count(Solve.id).label('solve_count'),
                func.max(Solve.timestamp).label('last_solve_time')
            ).filter(User.role != 'admin')

            # Apply time filter at database level for speed
            if time_filter != 'all':
                time_deltas = {
                    'day': timedelta(days=1),
                    'week': timedelta(weeks=1),
                    'month': timedelta(days=30)
                }
                if time_filter in time_deltas:
                    cutoff_time = datetime.utcnow() - time_deltas[time_filter]
                    base_query = base_query.outerjoin(
                        Solve, (Solve.user_id == User.id) & (Solve.timestamp >= cutoff_time)
                    )
                else:
                    base_query = base_query.outerjoin(Solve, Solve.user_id == User.id)
            else:
                base_query = base_query.outerjoin(Solve, Solve.user_id == User.id)

            # Group and order for maximum speed
            users_data = base_query.group_by(
                User.id, User.username, User.score, User.country
            ).order_by(
                User.score.desc(),
                func.max(Solve.timestamp).asc().nullslast(),
                User.username
            ).limit(100).all()  # Limit to top 100 for speed

            return users_data

        users_data = get_from_cache(scoreboard_cache_key, generate_scoreboard_data, timeout=60)

        # Add ranking and format data
        ranked_users = []
        for rank, user_data in enumerate(users_data, 1):
            user_dict = {
                'rank': rank,
                'id': user_data.id,
                'username': user_data.username,
                'score': user_data.score,
                'country': user_data.country,
                'solve_count': user_data.solve_count,
                'last_solve_time': user_data.last_solve_time,
                'is_current_user': user_data.id == current_user.id
            }
            ranked_users.append(user_dict)

        # Calculate average score
        total_score = sum(user['score'] for user in ranked_users)
        avg_score = total_score / len(ranked_users) if ranked_users else 0

        # Get categories for filter
        categories = list(challenge_stats.get('categories', {}).keys())

        # Get recent solves for activity feed
        recent_solves = (
            db.session.query(
                Solve.timestamp,
                User.username,
                Challenge.title,
                Challenge.points,
                Challenge.category
            )
            .join(User, Solve.user_id == User.id)
            .join(Challenge, Solve.challenge_id == Challenge.id)
            .filter(User.role != 'admin')
            .order_by(Solve.timestamp.desc())
            .limit(10)
            .all()
        )

        # Active tournament
        active_tournament = Tournament.query.filter_by(active=True).first()

        return render_template(
            'scoreboard.html',
            users=ranked_users,
            total_users=total_users,
            total_challenges=total_challenges,
            total_solves=total_solves,
            avg_score=avg_score,
            active_tournament=active_tournament,
            current_user=current_user,
            categories=categories,
            category_filter=category_filter,
            time_filter=time_filter,
            recent_solves=recent_solves,
            challenge_stats=challenge_stats
        )

    except Exception as e:
        print(f"Error in scoreboard: {e}")
        flash('Error loading scoreboard', 'error')
        return redirect(url_for('dashboard'))

@app.route('/scoreboard/teams')
def team_scoreboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get active tournament if any
    active_tournament = Tournament.query.filter_by(active=True).first()
    
    # Aggregate team scores as sum of member user scores
    teams = (
        db.session.query(
            Team.id,
            Team.name,
            Team.team_code,
            func.coalesce(func.sum(User.score), 0).label('score'),
            func.count(User.id).label('members')
        )
        .join(TeamMembership, TeamMembership.team_id == Team.id)
        .join(User, User.id == TeamMembership.user_id)
        .group_by(Team.id, Team.name, Team.team_code)
        .order_by(func.coalesce(func.sum(User.score), 0).desc(), Team.name)
        .all()
    )
    
    # Get user's team if any
    user_team = None
    if 'user_id' in session:
        membership = TeamMembership.query.filter_by(user_id=session['user_id']).first()
        if membership:
            user_team = db.session.get(Team, membership.team_id)
    
    return render_template('team_scoreboard.html', teams=teams, active_tournament=active_tournament, user_team=user_team)

@app.route('/teams', methods=['GET', 'POST'])
def teams():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('Team name required', 'error')
            return redirect(url_for('teams'))
        
        # Check if user is already in a team
        existing_membership = TeamMembership.query.filter_by(user_id=session['user_id']).first()
        if existing_membership:
            flash('You are already in a team. Leave your current team first.', 'error')
            return redirect(url_for('teams'))
        
        existing = Team.query.filter_by(name=name).first()
        if existing:
            flash('Team name already exists', 'error')
            return redirect(url_for('teams'))
        
        # Generate unique team code
        team_code = generate_unique_team_code()
        
        team = Team(name=name, team_code=team_code)
        db.session.add(team)
        db.session.flush()  # Get the team ID
        
        # Automatically add creator to team
        membership = TeamMembership(team_id=team.id, user_id=session['user_id'])
        db.session.add(membership)
        db.session.commit()
        
        flash(f'Team "{name}" created with code: {team_code}. You have joined!', 'success')
        
        # Send admin notification email
        # Safe admin notification without dereferencing undefined user variable
        try:
            current_user = db.session.get(User, session['user_id'])
            creator_str = f"{current_user.username} ({current_user.email})" if current_user else "Unknown"
            notify_admin(
                "New Team Created by User",
                f"Team '{name}' has been created with code: {team_code}\n"
                f"Created by: {creator_str}\n"
                f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
        except Exception:
            pass
        
        return redirect(url_for('teams'))
    
    all_teams = Team.query.order_by(Team.name).all()
    my_membership = TeamMembership.query.filter_by(user_id=session['user_id']).first()
    my_team = None
    if my_membership:
        my_team = db.session.get(Team, my_membership.team_id)
    
    # Get team members for each team
    team_members = {}
    for team in all_teams:
        members = (
            db.session.query(User.username, User.score)
            .join(TeamMembership, TeamMembership.user_id == User.id)
            .filter(TeamMembership.team_id == team.id)
            .all()
        )
        team_members[team.id] = members
    
    return render_template('teams.html', teams=all_teams, my_membership=my_membership, my_team=my_team, team_members=team_members)

@app.route('/teams/join', methods=['POST'])
def join_team():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    team_id = int(request.form.get('team_id', 0))
    if not db.session.get(Team, team_id):
        flash('Team not found', 'error')
        return redirect(url_for('teams'))
    existing = TeamMembership.query.filter_by(user_id=session['user_id']).first()
    if existing:
        flash('You are already in a team. Leave current team first.', 'error')
        return redirect(url_for('teams'))
    db.session.add(TeamMembership(team_id=team_id, user_id=session['user_id']))
    db.session.commit()
    flash('Joined team', 'success')
    return redirect(url_for('teams'))

@app.route('/teams/join_by_code', methods=['POST'])
def join_team_by_code():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    team_code = request.form.get('team_code', '').strip().upper()
    if not team_code:
        flash('Team code required', 'error')
        return redirect(url_for('teams'))
    
    # Find team by code
    team = Team.query.filter_by(team_code=team_code).first()
    if not team:
        flash('Invalid team code', 'error')
        return redirect(url_for('teams'))
    
    # Check if user is already in a team
    existing = TeamMembership.query.filter_by(user_id=session['user_id']).first()
    if existing:
        flash('You are already in a team. Leave current team first.', 'error')
        return redirect(url_for('teams'))
    
    # Add user to team
    membership = TeamMembership(team_id=team.id, user_id=session['user_id'])
    db.session.add(membership)
    db.session.commit()
    
    flash(f'Successfully joined team "{team.name}"!', 'success')
    
    # Create notification for team join
    user = db.session.get(User, session['user_id'])
    create_notification(
        user_id=user.id,
        title="👥 Team Joined!",
        message=f"You have successfully joined team '{team.name}'. Welcome to the team!",
        notification_type="team_update",
        related_id=team.id,
        related_type="team",
        priority="normal"
    )
    
    # Send admin notification email
    notify_admin(
        "User Joined Team by Code",
        f"User '{user.username}' has joined team '{team.name}' using team code\n"
        f"Team Code: {team_code}\n"
        f"User Email: {user.email}\n"
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    
    return redirect(url_for('teams'))

@app.route('/teams/leave', methods=['POST'])
def leave_team():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    membership = TeamMembership.query.filter_by(user_id=session['user_id']).first()
    if membership:
        db.session.delete(membership)
        db.session.commit()
        flash('Left team', 'success')
    else:
        flash('You are not in a team', 'error')
    return redirect(url_for('teams'))

@app.route('/tournaments', methods=['GET', 'POST'])
def tournaments():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            description = request.form.get('description', '').strip()
            start = request.form.get('start_time')
            end = request.form.get('end_time')
            max_teams = request.form.get('max_teams', type=int) or 100
            registration_open = request.form.get('registration_open') == 'on'

            if not name:
                flash('Tournament name is required', 'error')
                return redirect(url_for('tournaments'))

            if not start or not end:
                flash('Start and end times are required', 'error')
                return redirect(url_for('tournaments'))

            try:
                start_dt = datetime.fromisoformat(start.replace('T', ' '))
                end_dt = datetime.fromisoformat(end.replace('T', ' '))
            except Exception:
                flash('Invalid date format. Please use the date picker.', 'error')
                return redirect(url_for('tournaments'))

            if start_dt >= end_dt:
                flash('End time must be after start time', 'error')
                return redirect(url_for('tournaments'))

            tour = Tournament(
                name=name,
                description=description or None,
                start_time=start_dt,
                end_time=end_dt,
                max_teams=max_teams,
                registration_open=registration_open,
                active=False
            )

            db.session.add(tour)
            db.session.commit()

            # Send admin notification email
            notify_admin(
                "Tournament Created",
                f"Tournament '{name}' has been created\n"
                f"Description: {description}\n"
                f"Start Time: {start_dt.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"End Time: {end_dt.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Max Teams: {max_teams}\n"
                f"Registration Open: {registration_open}\n"
                f"Created by: Admin\n"
                f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )

            flash('Tournament created successfully!', 'success')
            return redirect(url_for('tournaments'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating tournament: {str(e)}', 'error')
            return redirect(url_for('tournaments'))

    # Get all tournaments with statistics
    tournaments_data = []
    all_tournaments = Tournament.query.order_by(Tournament.start_time.desc()).all()

    for tournament in all_tournaments:
        tournament_info = {
            'tournament': tournament,
            'status': 'Active' if tournament.active else 'Inactive',
            'time_status': 'Upcoming' if tournament.start_time > datetime.utcnow() else
                         'Ongoing' if tournament.end_time > datetime.utcnow() else 'Ended'
        }
        tournaments_data.append(tournament_info)

    return render_template('tournaments.html', tournaments_data=tournaments_data)

@app.route('/tournaments/activate/<int:tournament_id>', methods=['POST'])
def activate_tournament(tournament_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('login'))
    t = Tournament.query.get_or_404(tournament_id)
    t.active = True
    db.session.commit()
    try:
        socketio.emit('tournament_start', {'name': t.name, 'end_time': t.end_time.isoformat()})
    except Exception:
        pass
    
    # Send admin notification email
    notify_admin(
        "Tournament Activated",
        f"Tournament '{t.name}' has been activated\n"
        f"Start Time: {t.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"End Time: {t.end_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Activated by: Admin\n"
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    
    flash('Tournament activated', 'success')
    return redirect(url_for('tournaments'))

@app.route('/tournaments/deactivate/<int:tournament_id>', methods=['POST'])
def deactivate_tournament(tournament_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('login'))
    t = Tournament.query.get_or_404(tournament_id)
    t.active = False
    db.session.commit()
    try:
        socketio.emit('tournament_end', {'name': t.name})
    except Exception:
        pass
    
    # Send admin notification email
    notify_admin(
        "Tournament Deactivated",
        f"Tournament '{t.name}' has been deactivated\n"
        f"Deactivated by: Admin\n"
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    
    flash('Tournament deactivated', 'success')
    return redirect(url_for('tournaments'))

@app.route('/tournament/status')
def tournament_status():
    """Get current tournament status for WebSocket updates"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    active_tournament = Tournament.query.filter_by(active=True).first()
    if not active_tournament:
        return jsonify({'active': False})
    
    now = datetime.utcnow()
    time_remaining = (active_tournament.end_time - now).total_seconds()
    
    return jsonify({
        'active': True,
        'name': active_tournament.name,
        'end_time': active_tournament.end_time.isoformat(),
        'time_remaining': max(0, time_remaining),
        'is_finished': time_remaining <= 0
    })

@app.route('/tournament/leaderboard')
def tournament_leaderboard():
    """Get tournament leaderboard for active tournament"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    active_tournament = Tournament.query.filter_by(active=True).first()
    if not active_tournament:
        flash('No active tournament', 'info')
        return redirect(url_for('team_scoreboard'))
    
    # Get team scores for the tournament period
    teams = (
        db.session.query(
            Team.id, 
            Team.name, 
            Team.team_code,
            func.coalesce(func.sum(User.score), 0).label('score'), 
            func.count(User.id).label('members')
        )
        .join(TeamMembership, TeamMembership.team_id == Team.id)
        .join(User, User.id == TeamMembership.user_id)
        .group_by(Team.id, Team.name, Team.team_code)
        .order_by(func.coalesce(func.sum(User.score), 0).desc(), Team.name)
        .all()
    )
    
    return render_template('tournament_leaderboard.html', 
                         teams=teams, 
                         tournament=active_tournament)

# API endpoints for real-time leaderboard
@app.route('/api/leaderboard/individual')
def api_individual_leaderboard():
    """API endpoint for individual leaderboard data"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    # Optional filters
    category = request.args.get('category', '').strip().lower()
    window = request.args.get('window', '').strip().lower()  # '', 'day', 'week'

    base_query = db.session.query(
        User.username.label('username'),
        func.coalesce(func.sum(Challenge.points), 0).label('score')
    ).join(Solve, Solve.user_id == User.id)
    
    # Time window filter based on solves
    if window in ('day', 'week'):
        since = datetime.utcnow() - (timedelta(days=1) if window == 'day' else timedelta(days=7))
        base_query = base_query.filter(Solve.timestamp >= since)
    
    # Category filter (requires join to Challenge)
    base_query = base_query.join(Challenge, Challenge.id == Solve.challenge_id)
    if category:
        base_query = base_query.filter(Challenge.category == category)
    
    results = (
        base_query
        .filter(User.role != 'admin')
        .group_by(User.id, User.username)
        .order_by(func.coalesce(func.sum(Challenge.points), 0).desc(), User.username)
        .limit(50)
        .all()
    )

    return jsonify([{'username': r.username, 'score': int(r.score or 0)} for r in results])

@app.route('/api/leaderboard/teams')
def api_teams_leaderboard():
    """API endpoint for team leaderboard data"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    category = request.args.get('category', '').strip().lower()
    window = request.args.get('window', '').strip().lower()  # '', 'day', 'week'

    base_query = db.session.query(
        Team.name,
        Team.team_code,
        func.coalesce(func.sum(Challenge.points), 0).label('score'),
        func.count(User.id).label('members')
    ).join(TeamMembership, TeamMembership.team_id == Team.id)
    base_query = base_query.join(User, User.id == TeamMembership.user_id)
    base_query = base_query.join(Solve, Solve.user_id == User.id)
    base_query = base_query.join(Challenge, Challenge.id == Solve.challenge_id)

    # Time window filter based on solves
    if window in ('day', 'week'):
        since = datetime.utcnow() - (timedelta(days=1) if window == 'day' else timedelta(days=7))
        base_query = base_query.filter(Solve.timestamp >= since)

    if category:
        base_query = base_query.filter(Challenge.category == category)

    teams = (
        base_query
        .group_by(Team.id, Team.name, Team.team_code)
        .order_by(func.coalesce(func.sum(Challenge.points), 0).desc(), Team.name)
        .limit(50)
        .all()
    )

    return jsonify([{'name': t.name, 'team_code': t.team_code, 'score': int(t.score or 0), 'members': t.members} for t in teams])

@app.route('/admin/init_sample_challenges', methods=['POST'])
def init_sample_challenges():
    """Initialize 5 basic sample challenges"""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('admin_panel'))

    try:
        # Sample challenges data (5 basic ones)
        sample_challenges = [
            {
                'title': 'Welcome to CTF!',
                'description': 'This is your first challenge! The flag format is flag{...}. Can you find the hidden flag in this message? Hint: Look carefully at the first letter of each word: Find Lovely Amazing Goodies {welcome_to_ctf}',
                'flag': 'flag{welcome_to_ctf}',
                'points': 10,
                'category': 'misc',
                'difficulty': 'easy'
            },
            {
                'title': 'Base64 Basics',
                'description': 'Decode this Base64 string to find the flag: ZmxhZ3tiYXNlNjRfaXNfZWFzeX0=',
                'flag': 'flag{base64_is_easy}',
                'points': 15,
                'category': 'crypto',
                'difficulty': 'easy'
            },
            {
                'title': 'Caesar Cipher',
                'description': 'Julius Caesar used this cipher to protect his messages. Can you decode this message with a shift of 13? synt{pnrfne_pvcure_vf_sha}',
                'flag': 'flag{caesar_cipher_is_fun}',
                'points': 20,
                'category': 'crypto',
                'difficulty': 'easy'
            },
            {
                'title': 'Hidden in Plain Sight',
                'description': 'Sometimes the answer is right in front of you. Inspect this webpage carefully... <!-- flag{inspect_element_ftw} -->',
                'flag': 'flag{inspect_element_ftw}',
                'points': 15,
                'category': 'web',
                'difficulty': 'easy'
            },
            {
                'title': 'Binary Message',
                'description': 'Convert this binary to ASCII: 01100110 01101100 01100001 01100111 01111011 01100010 01101001 01101110 01100001 01110010 01111001 01011111 01101001 01110011 01011111 01100011 01101111 01101111 01101100 01111101',
                'flag': 'flag{binary_is_cool}',
                'points': 25,
                'category': 'crypto',
                'difficulty': 'easy'
            }
        ]

        created_count = 0
        for challenge_data in sample_challenges:
            # Check if challenge already exists
            existing = Challenge.query.filter_by(title=challenge_data['title']).first()
            if existing:
                continue

            # Encrypt the flag
            encrypted_flag = fernet.encrypt(challenge_data['flag'].encode())

            # Create salt and hash for secure flag validation
            salt = secrets.token_bytes(16)
            flag_hash = hashlib.sha256(salt + challenge_data['flag'].encode()).digest()

            # Create challenge
            challenge = Challenge(
                title=challenge_data['title'],
                description=challenge_data['description'],
                flag_encrypted=encrypted_flag,
                flag_salt=salt,
                flag_hash=flag_hash,
                points=challenge_data['points'],
                category=challenge_data['category'],
                difficulty=challenge_data['difficulty'],
                created_at=datetime.utcnow()
            )

            db.session.add(challenge)
            created_count += 1

        db.session.commit()
        flash(f'Successfully created {created_count} sample challenges!', 'success')
        notify_admin('Sample challenges initialized', f'{created_count} sample challenges were created by admin.')

    except Exception as e:
        db.session.rollback()
        flash(f'Error creating sample challenges: {e}', 'error')

    return redirect(url_for('admin_panel'))

@app.route('/admin/create_50_challenges', methods=['POST'])
def create_50_challenges():
    """Create 50 comprehensive CTF challenges"""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('admin_panel'))

    try:
        # Import and run the 50 challenges script
        from create_50_challenges import create_50_challenges as create_challenges_func

        with app.app_context():
            success = create_challenges_func()

        if success:
            flash('Successfully created 50 comprehensive CTF challenges!', 'success')
            notify_admin('50 Challenges Created', '50 comprehensive CTF challenges were created by admin.')
        else:
            flash('Error creating 50 challenges. Check logs for details.', 'error')

    except Exception as e:
        flash(f'Error creating 50 challenges: {e}', 'error')

    return redirect(url_for('admin_panel'))

@app.route('/admin/update_app', methods=['POST'])
def update_app():
    """Run comprehensive app updates"""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('admin_panel'))

    try:
        # Import and run the app updates
        from app_updates import main as run_updates

        # Capture the output (in a real implementation, you'd want better logging)
        import io
        import sys
        from contextlib import redirect_stdout

        output_buffer = io.StringIO()
        with redirect_stdout(output_buffer):
            run_updates()

        output = output_buffer.getvalue()

        # Count successful updates
        success_count = output.count('✅')
        total_updates = output.count('🔄 Running:')

        if success_count > 0:
            flash(f'App update completed! {success_count}/{total_updates} updates successful.', 'success')
            notify_admin('App Updated', f'Comprehensive app update completed with {success_count} successful updates.')
        else:
            flash('App update completed with warnings. Check logs for details.', 'warning')

    except Exception as e:
        flash(f'Error running app updates: {e}', 'error')

    return redirect(url_for('admin_panel'))

@app.route('/admin/app_info')
def app_info():
    """Display comprehensive app information"""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('admin_panel'))

    # Gather comprehensive app information
    app_info = {
        'version': '2.0.0',
        'last_updated': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        'database_stats': {
            'users': User.query.count(),
            'challenges': Challenge.query.count(),
            'teams': Team.query.count(),
            'tournaments': Tournament.query.count(),
            'solves': Solve.query.count(),
            'chat_messages': ChatMessage.query.count(),
            'chat_channels': ChatChannel.query.count()
        },
        'features': [
            'Real-time chat system',
            'Tournament management',
            'Team collaboration',
            'Dynamic challenge generation',
            'Advanced admin panel',
            'Email notifications',
            'User profiles with avatars',
            'Comprehensive leaderboards',
            'Challenge hint system',
            'Export/import functionality'
        ],
        'security_features': [
            'Password hashing',
            'Session management',
            'CSRF protection ready',
            'SQL injection prevention',
            'XSS protection',
            'Encrypted flag storage',
            'Input validation',
            'Role-based access control'
        ]
    }

    return render_template('admin_app_info.html', app_info=app_info)

@app.route('/create_admin_user')
def create_admin_user_route():
    """Emergency route to create admin user - accessible without login"""
    try:
        # Check if admin already exists
        admin = User.query.filter_by(username='admin').first()
        if admin:
            return jsonify({
                'status': 'exists',
                'message': 'Admin user already exists. Try logging in with username: admin, password: admin123'
            })

        # Create admin user
        admin = User(
            username='admin',
            email='admin@ctf.local',
            password_hash=generate_password_hash('admin123'),
            role='admin'
        )

        db.session.add(admin)
        db.session.commit()

        return jsonify({
            'status': 'created',
            'message': 'Admin user created successfully!',
            'username': 'admin',
            'password': 'admin123',
            'note': 'Please change the password after first login'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Error creating admin user: {str(e)}'
        }), 500

@app.route('/reset_admin_password')
def reset_admin_password():
    """Emergency route to reset admin password"""
    try:
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            return jsonify({
                'status': 'not_found',
                'message': 'Admin user not found. Use /create_admin_user first.'
            })

        # Reset password to default
        admin.password_hash = generate_password_hash('admin123')
        db.session.commit()

        return jsonify({
            'status': 'reset',
            'message': 'Admin password reset successfully!',
            'username': 'admin',
            'password': 'admin123',
            'note': 'Please change the password after login'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Error resetting admin password: {str(e)}'
        }), 500

@app.route('/debug/users')
def debug_users():
    """Debug route to see all users in database"""
    try:
        users = User.query.all()
        user_list = []

        for user in users:
            user_list.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'score': user.score
            })

        return jsonify({
            'total_users': len(users),
            'users': user_list,
            'admin_exists': any(user.username == 'admin' for user in users)
        })

    except Exception as e:
        return jsonify({
            'error': f'Database error: {str(e)}'
        }), 500

@app.route('/admin/generate_challenge', methods=['POST'])
def generate_dynamic_challenge():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('admin_panel'))
    kind = request.form.get('kind', 'crypto')
    try:
        if kind == 'crypto':
            desc, flag = generate_crypto_base64_flag()
            points = 10
            title = f"Dynamic Crypto {datetime.utcnow().strftime('%H%M%S')}"
            category, difficulty = 'crypto', 'easy'
            encrypted_flag = fernet.encrypt(flag.encode())
            ch = Challenge(title=title, description=desc, flag_encrypted=encrypted_flag, points=points, category=category, difficulty=difficulty)
            db.session.add(ch)
            db.session.commit()
            flash('Dynamic crypto challenge generated', 'success')
            notify_admin('Dynamic challenge generated', f"A new dynamic crypto challenge '{title}' was generated by Admin with {points} points.")
        elif kind == 'stego':
            desc, path, flag = generate_stego_text_image()
            points = 20
            title = f"Dynamic Stego {datetime.utcnow().strftime('%H%M%S')}"
            category, difficulty = 'forensics', 'medium'
            encrypted_flag = fernet.encrypt(flag.encode())
            ch = Challenge(title=title, description=desc, flag_encrypted=encrypted_flag, points=points, category=category, difficulty=difficulty)
            db.session.add(ch)
            db.session.commit()
            flash('Dynamic stego challenge generated', 'success')
            notify_admin('Dynamic challenge generated', f"A new dynamic stego challenge '{title}' was generated by Admin with {points} points.")
        else:
            flash('Unknown generator kind', 'error')
    except Exception as e:
        db.session.rollback()
        flash(f'Error generating challenge: {e}', 'error')
    return redirect(url_for('admin_panel'))

@app.route('/logout')
def logout():
    # Check if user is already logged out to prevent duplicate emails
    if 'user_id' in session and 'logout_email_sent' not in session:
        user = db.session.get(User, session['user_id'])
        # Only send logout email if not admin and email hasn't been sent
        if user and user.role != 'admin':
            send_email(
                user.email,
                "🚪 You have logged out - CTF Game",
                f"Hello {user.username},\n\nYou have logged out from the CTF platform.\nYour current score is: {user.score} points.\n\nSee you soon!",
                html=f"<p>Hello <strong>{user.username}</strong>,</p><p>You have logged out from the CTF platform.</p><p>Your current score is: <strong>{user.score}</strong> points.</p><p>See you soon!</p>"
            )
            # Mark that logout email has been sent to prevent duplicates
            session['logout_email_sent'] = True
    
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        flag = request.form['flag']
        points = int(request.form['points'])
        category = request.form.get('category', 'misc')
        difficulty = request.form.get('difficulty', 'easy')
        opens_at = request.form.get('opens_at') or None
        closes_at = request.form.get('closes_at') or None
        encrypted_flag = fernet.encrypt(flag.encode())
        salt = secrets.token_bytes(16)
        flag_hash = hashlib.sha256(salt + flag.encode()).digest()
        def parse_dt(v):
            try:
                return datetime.fromisoformat(v) if v else None
            except Exception:
                return None
        challenge = Challenge(
            title=title,
            description=description,
            flag_encrypted=encrypted_flag,
            points=points,
            category=category,
            difficulty=difficulty,
            flag_salt=salt,
            flag_hash=flag_hash,
            opens_at=parse_dt(opens_at),
            closes_at=parse_dt(closes_at),
        )
        db.session.add(challenge)
        db.session.commit()
        trigger_export_async()
        notify_admin(
            "Challenge added",
            f"New challenge added by admin: '{title}' ({points} points)."
        )
        flash("Challenge added successfully.", "success")
    challenges = Challenge.query.all()
    users = User.query.all()
    teams = Team.query.order_by(Team.name).all()
    return render_template('admin.html', challenges=challenges, users=users, teams=teams)

@app.route('/admin/hints/add/<int:challenge_id>', methods=['POST'])
def admin_add_hint(challenge_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('login'))
    text = request.form.get('text', '').strip()
    cost = int(request.form.get('cost', '0') or 0)
    display_order = int(request.form.get('display_order', '0') or 0)
    if not text or cost < 0:
        flash('Hint text required and cost must be >= 0', 'error')
        return redirect(url_for('admin_panel'))
    try:
        ch = Challenge.query.get_or_404(challenge_id)
        hint = Hint(challenge_id=ch.id, text=text, cost=cost, display_order=display_order)
        db.session.add(hint)
        db.session.commit()
        flash('Hint added', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding hint: {e}', 'error')
    return redirect(url_for('admin_panel'))

@app.route('/admin/hints/delete/<int:hint_id>', methods=['POST'])
def admin_delete_hint(hint_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('login'))
    try:
        hint = Hint.query.get_or_404(hint_id)
        db.session.delete(hint)
        db.session.commit()
        flash('Hint deleted', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting hint: {e}', 'error')
    return redirect(url_for('admin_panel'))

@app.route('/hints/reveal/<int:hint_id>', methods=['POST'])
def reveal_hint(hint_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    if user.role == 'admin':
        flash('Admins cannot reveal hints.', 'error')
        return redirect(url_for('admin_panel'))
    hint = Hint.query.get_or_404(hint_id)
    already = UserHint.query.filter_by(user_id=user.id, hint_id=hint.id).first()
    if already:
        flash('Hint already revealed.', 'info')
        return redirect(request.referrer or url_for('dashboard'))
    # Require sufficient points
    if user.score < hint.cost:
        flash('Not enough points to reveal this hint.', 'error')
        return redirect(request.referrer or url_for('dashboard'))
    try:
        user.score = max(0, user.score - hint.cost)
        db.session.add(UserHint(user_id=user.id, hint_id=hint.id))
        db.session.commit()
        
        # Create notification for hint revealed
        create_notification(
            user_id=user.id,
            title="💡 Hint Revealed",
            message=f"You revealed a hint for '{hint.challenge.title}' and lost {hint.cost} points. Your new score is {user.score}.",
            notification_type="hint_used",
            related_id=hint.challenge.id,
            related_type="challenge",
            priority="normal"
        )
        
        try:
            socketio.emit('score_update', {
                'username': user.username,
                'score': user.score
            })
            send_leaderboard_updates()
        except Exception:
            pass
        flash('Hint revealed. Points deducted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error revealing hint: {e}', 'error')
    # Redirect back to dashboard
    return redirect(request.referrer or url_for('dashboard'))






@app.route('/admin/delete/<int:challenge_id>', methods=['POST'])
def delete_challenge(challenge_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    try:
        challenge = Challenge.query.get_or_404(challenge_id)

        # Adjust user scores for those who solved this challenge (use grouped count to avoid loading all rows)
        solve_counts = (
            db.session.query(Solve.user_id, func.count(Solve.id))
            .filter(Solve.challenge_id == challenge_id)
            .group_by(Solve.user_id)
            .all()
        )
        for user_id, count in solve_counts:
            user = db.session.get(User, user_id)
            if user:
                user.score = max(0, user.score - (challenge.points * int(count)))

        # Delete child rows first using bulk deletes to satisfy FK constraints
        Submission.query.filter(Submission.challenge_id == challenge_id).delete(synchronize_session=False)
        Solve.query.filter(Solve.challenge_id == challenge_id).delete(synchronize_session=False)

        # Now delete the challenge itself
        db.session.delete(challenge)
        db.session.commit()
        trigger_export_async()
        notify_admin(
            "Challenge deleted",
            f"Challenge deleted by admin: '{challenge.title}' (id={challenge_id}). User scores adjusted accordingly."
        )
        flash("Challenge deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting challenge: {str(e)}", "error")
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    try:
        user = User.query.get_or_404(user_id)
        if user.role == 'admin':
            flash("Cannot delete admin user.", "error")
            return redirect(url_for('admin_panel'))

        # Delete dependent records to satisfy foreign key constraints
        user_solves = Solve.query.filter_by(user_id=user.id).all()
        for solve in user_solves:
            db.session.delete(solve)

        user_submissions = Submission.query.filter_by(user_id=user.id).all()
        for submission in user_submissions:
            db.session.delete(submission)

        db.session.delete(user)
        db.session.commit()
        trigger_export_async()
        notify_admin(
            "User deleted",
            f"Admin deleted user '{user.username}' (id={user.id})."
        )
        flash("User deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting user: {str(e)}", "error")
    return redirect(url_for('admin_panel'))

@app.route('/admin/edit/<int:challenge_id>', methods=['POST'])
def edit_challenge(challenge_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    try:
        challenge = Challenge.query.get_or_404(challenge_id)
        challenge.title = request.form['edit_title']
        challenge.description = request.form['edit_description']
        challenge.points = int(request.form['edit_points'])
        challenge.category = request.form.get('edit_category', challenge.category or 'misc')
        challenge.difficulty = request.form.get('edit_difficulty', challenge.difficulty or 'easy')
        
        # Update flag if provided
        if 'edit_flag' in request.form and request.form['edit_flag'].strip():
            new_flag = request.form['edit_flag'].strip()
            challenge.flag_encrypted = fernet.encrypt(new_flag.encode())
            salt = secrets.token_bytes(16)
            challenge.flag_salt = salt
            challenge.flag_hash = hashlib.sha256(salt + new_flag.encode()).digest()
        
        # Update time window
        def parse_dt(v):
            try:
                return datetime.fromisoformat(v) if v else None
            except Exception:
                return None
        if 'edit_opens_at' in request.form:
            challenge.opens_at = parse_dt(request.form.get('edit_opens_at'))
        if 'edit_closes_at' in request.form:
            challenge.closes_at = parse_dt(request.form.get('edit_closes_at'))

        db.session.commit()
        trigger_export_async()
        notify_admin(
            "Challenge updated",
            f"Challenge updated by admin: '{challenge.title}' (id={challenge.id})."
        )
        flash("Challenge updated successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating challenge: {str(e)}", "error")
    return redirect(url_for('admin_panel'))

@app.route('/admin/get_flag/<int:challenge_id>')
def get_challenge_flag(challenge_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized access'})
    try:
        challenge = Challenge.query.get_or_404(challenge_id)
        decrypted_flag = fernet.decrypt(challenge.flag_encrypted).decode()
        return jsonify({'success': True, 'flag': decrypted_flag})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def generate_unique_team_code():
    """Generate a unique 6-character team code"""
    while True:
        # Generate a 6-character code with uppercase letters and numbers
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        # Check if code already exists
        if not Team.query.filter_by(team_code=code).first():
            return code

# Team Management Routes
@app.route('/admin/teams')
def admin_teams():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    
    teams = Team.query.all()
    users = User.query.filter(User.role != 'admin').all()
    return render_template('admin_teams.html', teams=teams, users=users)

@app.route('/admin/teams/create', methods=['POST'])
def admin_create_team():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    
    try:
        team_name = request.form['team_name']
        leader_id = request.form.get('leader_id')
        
        # Check if team name already exists
        existing_team = Team.query.filter_by(name=team_name).first()
        if existing_team:
            flash("Team name already exists", "error")
            return redirect(url_for('admin_teams'))
        
        # Generate unique team code
        team_code = generate_unique_team_code()
        
        # Create new team with code
        team = Team(name=team_name, team_code=team_code)
        db.session.add(team)
        db.session.flush()  # Get the team ID
        
        # Add leader if specified
        if leader_id:
            leader = db.session.get(User, leader_id)
            if leader:
                membership = TeamMembership(user_id=leader.id, team_id=team.id, role='leader')
                db.session.add(membership)
        
        db.session.commit()
        flash(f"Team '{team_name}' created successfully with code: {team_code}", "success")
        
        # Send admin notification email
        notify_admin(
            "Team Created by Admin",
            f"Team '{team_name}' has been created with code: {team_code}\n"
            f"Created by: Admin\n"
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error creating team: {str(e)}", "error")
    
    return redirect(url_for('admin_teams'))

@app.route('/admin/teams/<int:team_id>/edit', methods=['POST'])
def admin_edit_team(team_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    
    try:
        team = Team.query.get_or_404(team_id)
        new_name = request.form['team_name']
        
        # Check if new name conflicts with existing team
        existing_team = Team.query.filter_by(name=new_name).first()
        if existing_team and existing_team.id != team_id:
            flash("Team name already exists", "error")
            return redirect(url_for('admin_teams'))
        
        team.name = new_name
        db.session.commit()
        flash(f"Team '{team.name}' updated successfully", "success")
        
        # Send admin notification email
        notify_admin(
            "Team Updated by Admin",
            f"Team '{team.name}' (Code: {team.team_code}) has been updated\n"
            f"Updated by: Admin\n"
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating team: {str(e)}", "error")
    
    return redirect(url_for('admin_teams'))

@app.route('/admin/teams/<int:team_id>/delete', methods=['POST'])
def admin_delete_team(team_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    
    try:
        team = Team.query.get_or_404(team_id)
        team_name = team.name
        
        # Remove all team memberships
        TeamMembership.query.filter_by(team_id=team_id).delete()
        
        # Delete the team
        db.session.delete(team)
        db.session.commit()
        
        flash(f"Team '{team_name}' deleted successfully", "success")
        
        # Send admin notification email
        notify_admin(
            "Team Deleted by Admin",
            f"Team '{team_name}' has been deleted\n"
            f"Deleted by: Admin\n"
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting team: {str(e)}", "error")
    
    return redirect(url_for('admin_teams'))

@app.route('/admin/teams/<int:team_id>/add_member', methods=['POST'])
def admin_add_team_member(team_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    
    try:
        team = Team.query.get_or_404(team_id)
        user_id = request.form['user_id']
        role = request.form.get('role', 'member')
        
        user = db.session.get(User, user_id)
        if not user:
            flash("User not found", "error")
            return redirect(url_for('admin_teams'))
        
        # Check if user is already in a team
        existing_membership = TeamMembership.query.filter_by(user_id=user_id).first()
        if existing_membership:
            flash(f"User '{user.username}' is already in team '{existing_membership.team.name}'", "error")
            return redirect(url_for('admin_teams'))
        
        # Add user to team
        membership = TeamMembership(user_id=user_id, team_id=team_id, role=role)
        db.session.add(membership)
        db.session.commit()
        
        flash(f"User '{user.username}' added to team '{team.name}'", "success")
        
        # Send admin notification email
        notify_admin(
            "Team Member Added by Admin",
            f"User '{user.username}' has been added to team '{team.name}' (Code: {team.team_code})\n"
            f"Role: {role.title()}\n"
            f"Added by: Admin\n"
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error adding team member: {str(e)}", "error")
    
    return redirect(url_for('admin_teams'))

@app.route('/admin/teams/<int:team_id>/remove_member/<int:user_id>', methods=['POST'])
def admin_remove_team_member(team_id, user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    
    try:
        membership = TeamMembership.query.filter_by(team_id=team_id, user_id=user_id).first()
        if not membership:
            flash("Team membership not found", "error")
            return redirect(url_for('admin_teams'))
        
        user = db.session.get(User, user_id)
        team = db.session.get(Team, team_id)
        
        db.session.delete(membership)
        db.session.commit()
        
        flash(f"User '{user.username}' removed from team '{team.name}'", "success")
        
        # Send admin notification email
        notify_admin(
            "Team Member Removed by Admin",
            f"User '{user.username}' has been removed from team '{team.name}' (Code: {team.team_code})\n"
            f"Removed by: Admin\n"
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error removing team member: {str(e)}", "error")
    
    return redirect(url_for('admin_teams'))

# Extra admin capabilities for full team management
@app.route('/admin/teams/<int:team_id>/regenerate_code', methods=['POST'])
def admin_regenerate_team_code(team_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    try:
        team = Team.query.get_or_404(team_id)
        old_code = team.team_code
        new_code = generate_unique_team_code()
        team.team_code = new_code
        db.session.commit()
        flash(f"Team code regenerated: {new_code}", "success")
        notify_admin(
            "Team Code Regenerated",
            f"Team '{team.name}' code changed from {old_code} to {new_code} by Admin."
        )
    except Exception as e:
        db.session.rollback()
        flash(f"Error regenerating code: {e}", "error")
    return redirect(url_for('admin_teams'))

@app.route('/admin/teams/<int:team_id>/set_leader', methods=['POST'])
def admin_set_team_leader(team_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    try:
        user_id = int(request.form['user_id'])
        team = Team.query.get_or_404(team_id)
        # Ensure the user is in this team
        leader_membership = TeamMembership.query.filter_by(team_id=team_id, user_id=user_id).first()
        if not leader_membership:
            flash("User is not a member of this team", "error")
            return redirect(url_for('admin_teams'))
        # Demote other leaders/members to member
        TeamMembership.query.filter_by(team_id=team_id).update({TeamMembership.role: 'member'})
        # Promote selected user
        leader_membership.role = 'leader'
        db.session.commit()
        flash(f"{leader_membership.user.username} is now leader of '{team.name}'", "success")
        notify_admin(
            "Team Leader Set",
            f"User '{leader_membership.user.username}' set as leader for team '{team.name}' (Code: {team.team_code})."
        )
    except Exception as e:
        db.session.rollback()
        flash(f"Error setting leader: {e}", "error")
    return redirect(url_for('admin_teams'))

@app.route('/admin/teams/<int:team_id>/clear_members', methods=['POST'])
def admin_clear_team_members(team_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    try:
        team = Team.query.get_or_404(team_id)
        deleted = TeamMembership.query.filter_by(team_id=team_id).delete()
        db.session.commit()
        flash(f"Cleared {deleted} member(s) from team '{team.name}'", "success")
        notify_admin(
            "Team Members Cleared",
            f"All members removed from team '{team.name}' (Code: {team.team_code}) by Admin."
        )
    except Exception as e:
        db.session.rollback()
        flash(f"Error clearing members: {e}", "error")
    return redirect(url_for('admin_teams'))

@app.route('/admin/teams/<int:team_id>/move_member', methods=['POST'])
def admin_move_team_member(team_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    try:
        user_id = int(request.form['user_id'])
        to_team_id = int(request.form['to_team_id'])
        if to_team_id == team_id:
            flash("User is already in this team", "info")
            return redirect(url_for('admin_teams'))
        to_team = Team.query.get_or_404(to_team_id)
        # Find existing membership regardless of source team to be safe
        membership = TeamMembership.query.filter_by(user_id=user_id).first()
        if not membership:
            flash("User has no team membership", "error")
            return redirect(url_for('admin_teams'))
        # Prevent duplicate membership in target
        existing_in_target = TeamMembership.query.filter_by(user_id=user_id, team_id=to_team_id).first()
        if existing_in_target:
            flash("User already in target team", "info")
            return redirect(url_for('admin_teams'))
        from_team = db.session.get(Team, membership.team_id)
        membership.team_id = to_team_id
        db.session.commit()
        user = db.session.get(User, user_id)
        flash(f"Moved '{user.username}' from '{from_team.name}' to '{to_team.name}'", "success")
        notify_admin(
            "Team Member Moved",
            f"User '{user.username}' moved from team '{from_team.name}' to '{to_team.name}' by Admin."
        )
    except Exception as e:
        db.session.rollback()
        flash(f"Error moving member: {e}", "error")
    return redirect(url_for('admin_teams'))

# Removed tournament rounds management - simplified for core functionality

# Removed chat system - simplified for core functionality

# Removed Docker challenge isolation - simplified for core functionality

# Dynamic Challenge Generation
@app.route('/admin/challenge_templates', methods=['GET', 'POST'])
def manage_challenge_templates():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('admin_panel'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        description_template = request.form.get('description_template')
        flag_template = request.form.get('flag_template')
        points_range = request.form.get('points_range')
        category = request.form.get('category')
        difficulty = request.form.get('difficulty')
        docker_image = request.form.get('docker_image')
        parameters = request.form.get('parameters', '{}')
        
        template = ChallengeTemplate(
            name=name,
            description_template=description_template,
            flag_template=flag_template,
            points_range=points_range,
            category=category,
            difficulty=difficulty,
            docker_image=docker_image,
            parameters=parameters
        )
        db.session.add(template)
        db.session.commit()
        flash('Challenge template created successfully', 'success')
        return redirect(url_for('manage_challenge_templates'))
    
    templates = ChallengeTemplate.query.filter_by(active=True).all()
    return render_template('admin_challenge_templates.html', templates=templates)

@app.route('/admin/challenge_templates/<int:template_id>/generate', methods=['POST'])
def generate_challenge_from_template(template_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    template = ChallengeTemplate.query.get_or_404(template_id)
    
    # Parse parameters
    params = json.loads(template.parameters) if template.parameters else {}
    
    # Generate random values for parameters
    generated_params = {}
    for param_name, param_config in params.items():
        if param_config.get('type') == 'random_string':
            length = param_config.get('length', 8)
            generated_params[param_name] = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        elif param_config.get('type') == 'random_number':
            min_val = param_config.get('min', 1)
            max_val = param_config.get('max', 100)
            generated_params[param_name] = random.randint(min_val, max_val)
        elif param_config.get('type') == 'random_hex':
            length = param_config.get('length', 16)
            generated_params[param_name] = secrets.token_hex(length // 2)
    
    # Generate flag from template
    flag = template.flag_template
    for param_name, value in generated_params.items():
        flag = flag.replace(f'{{{param_name}}}', str(value))
    
    # Generate description from template
    description = template.description_template
    for param_name, value in generated_params.items():
        description = description.replace(f'{{{param_name}}}', str(value))
    
    # Parse points range
    points_min, points_max = map(int, template.points_range.split('-'))
    points = random.randint(points_min, points_max)
    
    # Create dynamic challenge
    dynamic_challenge = DynamicChallenge(
        template_id=template_id,
        user_id=session['user_id'],
        generated_flag=flag,
        parameters_used=json.dumps(generated_params),
        expires_at=datetime.utcnow() + timedelta(days=7)  # 7 day expiry
    )
    db.session.add(dynamic_challenge)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'challenge_id': dynamic_challenge.id,
        'flag': flag,
        'description': description,
        'points': points,
        'parameters': generated_params
    })

# User Progress Analytics
@app.route('/profile/progress')
def user_progress():
    if 'user_id' not in session:
        flash('Please log in to view your progress', 'error')
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    
    # Get progress data for the last 30 days
    end_date = datetime.utcnow().date()
    start_date = end_date - timedelta(days=30)
    
    progress_records = UserProgress.query.filter(
        UserProgress.user_id == user.id,
        UserProgress.date >= start_date,
        UserProgress.date <= end_date
    ).order_by(UserProgress.date).all()
    
    # Get category and difficulty breakdown
    solves = Solve.query.filter_by(user_id=user.id).all()
    challenges = {c.id: c for c in Challenge.query.all()}
    
    category_stats = {}
    difficulty_stats = {}
    
    for solve in solves:
        challenge = challenges.get(solve.challenge_id)
        if challenge:
            category_stats[challenge.category] = category_stats.get(challenge.category, 0) + 1
            difficulty_stats[challenge.difficulty] = difficulty_stats.get(challenge.difficulty, 0) + 1
    
    return render_template('user_progress.html', 
                         user=user, 
                         progress_records=progress_records,
                         category_stats=category_stats,
                         difficulty_stats=difficulty_stats)

@app.route('/api/profile/progress_data')
def api_user_progress_data():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = db.session.get(User, session['user_id'])
    
    # Get last 30 days of progress
    end_date = datetime.utcnow().date()
    start_date = end_date - timedelta(days=30)
    
    progress_records = UserProgress.query.filter(
        UserProgress.user_id == user.id,
        UserProgress.date >= start_date,
        UserProgress.date <= end_date
    ).order_by(UserProgress.date).all()
    
    # Prepare data for charts
    dates = [record.date.isoformat() for record in progress_records]
    points = [record.points_earned for record in progress_records]
    solves = [record.challenges_solved for record in progress_records]
    
    return jsonify({
        'dates': dates,
        'points': points,
        'solves': solves
    })

# Profile Management Routes
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('Please log in to view your profile', 'error')
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    if not user:
        flash('User not found', 'error')
        session.clear()
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            print(f"Profile update request for user {user.username}")

            # Update basic profile information
            old_values = {
                'first_name': user.first_name,
                'last_name': user.last_name,
                'bio': user.bio,
                'country': user.country,
                'timezone': user.timezone,
                'gender': user.gender,
                'date_of_birth': user.date_of_birth,
                'profile_picture': user.profile_picture
            }

            user.first_name = request.form.get('first_name', '').strip() or None
            user.last_name = request.form.get('last_name', '').strip() or None
            user.bio = request.form.get('bio', '').strip() or None
            user.country = request.form.get('country', '').strip() or None
            user.timezone = request.form.get('timezone', '').strip() or None
            user.gender = request.form.get('gender', '').strip() or None

            print(f"Updated fields: first_name={user.first_name}, last_name={user.last_name}")

            # Handle date of birth
            dob_str = request.form.get('date_of_birth', '').strip()
            if dob_str:
                try:
                    user.date_of_birth = datetime.strptime(dob_str, '%Y-%m-%d').date()
                    print(f"Updated date_of_birth: {user.date_of_birth}")
                except ValueError:
                    flash('Invalid date format for date of birth', 'error')
                    return redirect(url_for('profile'))
            else:
                user.date_of_birth = None

            # Handle profile picture upload with enhanced error handling
            picture_updated = False
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and file.filename and file.filename.strip():
                    print(f"Processing profile picture: {file.filename}")

                    try:
                        # Check file type
                        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'}
                        file_extension = None

                        if '.' in file.filename:
                            file_extension = file.filename.rsplit('.', 1)[1].lower()

                        if not file_extension or file_extension not in allowed_extensions:
                            flash('Invalid file type. Please upload PNG, JPG, JPEG, GIF, WebP, or BMP files only.', 'error')
                            return redirect(url_for('profile'))

                        # Check file size first (limit to 5MB)
                        file.seek(0, 2)  # Seek to end
                        file_size = file.tell()
                        file.seek(0)  # Reset to beginning

                        if file_size > 5 * 1024 * 1024:  # 5MB limit
                            flash('File too large. Please upload an image smaller than 5MB.', 'error')
                            return redirect(url_for('profile'))

                        if file_size == 0:
                            flash('Empty file. Please select a valid image.', 'error')
                            return redirect(url_for('profile'))

                        # Create uploads directory if it doesn't exist
                        upload_dir = os.path.join(app.instance_path, 'profile_pictures')
                        os.makedirs(upload_dir, exist_ok=True)
                        print(f"Upload directory: {upload_dir}")

                        # Remove old profile picture if exists
                        if user.profile_picture:
                            old_filepath = os.path.join(upload_dir, user.profile_picture)
                            if os.path.exists(old_filepath):
                                try:
                                    os.remove(old_filepath)
                                    print(f"Removed old profile picture: {old_filepath}")
                                except Exception as e:
                                    print(f"Could not remove old picture: {e}")

                        # Generate unique filename with timestamp
                        timestamp = int(time.time())
                        filename = f"profile_{user.id}_{timestamp}.{file_extension}"
                        filepath = os.path.join(upload_dir, filename)

                        # Ensure filename is unique (in case of rapid uploads)
                        counter = 1
                        while os.path.exists(filepath):
                            filename = f"profile_{user.id}_{timestamp}_{counter}.{file_extension}"
                            filepath = os.path.join(upload_dir, filename)
                            counter += 1

                        # Save file with error handling
                        try:
                            file.save(filepath)
                            print(f"Saved profile picture to: {filepath}")

                            # Verify file was saved correctly
                            if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
                                raise Exception("File was not saved correctly")

                            # Update user profile picture path
                            user.profile_picture = filename
                            picture_updated = True
                            print(f"Updated profile_picture field: {user.profile_picture}")

                        except Exception as save_error:
                            print(f"Error saving file: {save_error}")
                            flash('Error saving profile picture. Please try again.', 'error')
                            return redirect(url_for('profile'))

                    except Exception as upload_error:
                        print(f"Error processing profile picture upload: {upload_error}")
                        flash('Error processing profile picture. Please try again.', 'error')
                        return redirect(url_for('profile'))

            # Check what changed
            changes = []
            for field, old_value in old_values.items():
                new_value = getattr(user, field)
                if old_value != new_value:
                    changes.append(f"{field}: '{old_value}' -> '{new_value}'")

            if changes:
                print(f"Changes detected: {changes}")
            else:
                print("No changes detected")

            # Commit changes to database
            db.session.commit()
            print("Database commit successful")

            # Clear cache to ensure fresh data
            clear_cache('leaderboard')

            success_message = 'Profile updated successfully!'
            if picture_updated:
                success_message += ' Profile picture uploaded!'

            flash(success_message, 'success')
            return redirect(url_for('profile'))

        except Exception as e:
            db.session.rollback()
            print(f"Error updating profile: {str(e)}")
            import traceback
            traceback.print_exc()
            flash(f'Error updating profile: {str(e)}', 'error')

    # Get additional data for template
    try:
        # Get solve count
        solves_count = len([sub for sub in user.submissions if sub.correct]) if hasattr(user, 'submissions') else 0

        # Get team info
        team_name = None
        team_role = None
        if hasattr(user, 'team_membership') and user.team_membership:
            team_name = user.team_membership.team.name
            team_role = user.team_membership.role

        return render_template('profile.html',
                             user=user,
                             solves_count=solves_count,
                             team_name=team_name,
                             team_role=team_role)
    except Exception as e:
        print(f"Error preparing profile data: {e}")
        return render_template('profile.html',
                             user=user,
                             solves_count=0,
                             team_name=None,
                             team_role=None)

@app.route('/profile/picture/<filename>')
def profile_picture(filename):
    """Serve profile pictures with enhanced error handling and fallbacks"""
    try:
        # Create upload directory if it doesn't exist
        upload_dir = os.path.join(app.instance_path, 'profile_pictures')
        os.makedirs(upload_dir, exist_ok=True)

        # Sanitize filename
        if not filename or '..' in filename or '/' in filename:
            print(f"Invalid filename: {filename}")
            return redirect(url_for('static', filename='images/default-avatar.svg'))

        filepath = os.path.join(upload_dir, filename)

        # Security check: ensure the file exists and is in the correct directory
        if not os.path.exists(filepath):
            print(f"Profile picture not found: {filepath}")
            # Return a default avatar instead of 404
            return redirect(url_for('static', filename='images/default-avatar.svg'))

        # Verify the file is in the correct directory (security)
        try:
            if not os.path.commonpath([upload_dir, filepath]) == upload_dir:
                print(f"Security violation: file outside upload directory")
                return redirect(url_for('static', filename='images/default-avatar.svg'))
        except ValueError:
            print(f"Path security check failed for: {filepath}")
            return redirect(url_for('static', filename='images/default-avatar.svg'))

        # Check file size (prevent serving huge files)
        file_size = os.path.getsize(filepath)
        if file_size > 10 * 1024 * 1024:  # 10MB limit
            print(f"File too large: {filepath} ({file_size} bytes)")
            return redirect(url_for('static', filename='images/default-avatar.svg'))

        # Serve the file with proper caching headers
        response = send_from_directory(upload_dir, filename)
        response.cache_control.max_age = 3600  # Cache for 1 hour
        response.cache_control.public = True
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    except Exception as e:
        print(f"Error serving profile picture {filename}: {e}")
        # Return default avatar on error
        return redirect(url_for('static', filename='images/default-avatar.svg'))

@app.route('/profile/picture/delete', methods=['POST'])
def delete_profile_picture():
    """Delete user's profile picture with enhanced error handling"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.profile_picture:
            # Remove file from filesystem
            upload_dir = os.path.join(app.instance_path, 'profile_pictures')
            filepath = os.path.join(upload_dir, user.profile_picture)

            # Try to remove file, but don't fail if file doesn't exist
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                    print(f"Deleted profile picture file: {filepath}")
                except Exception as file_error:
                    print(f"Could not delete file {filepath}: {file_error}")
                    # Continue anyway - remove from database

            # Remove from database
            old_picture = user.profile_picture
            user.profile_picture = None
            db.session.commit()

            print(f"Removed profile picture '{old_picture}' from user {user.username}")
            return jsonify({
                'success': True,
                'message': 'Profile picture deleted successfully',
                'reload': True  # Signal frontend to reload
            })
        else:
            return jsonify({'error': 'No profile picture to delete'}), 400

    except Exception as e:
        db.session.rollback()
        print(f"Error deleting profile picture: {e}")
        return jsonify({'error': f'Error deleting profile picture: {str(e)}'}), 500

@app.route('/profile/picture/default')
def default_profile_picture():
    """Serve default profile picture"""
    try:
        # Try to serve from static files first
        return redirect(url_for('static', filename='images/default-avatar.png'))
    except:
        # If static file doesn't exist, create a simple SVG avatar
        svg_content = '''<svg width="150" height="150" xmlns="http://www.w3.org/2000/svg">
            <rect width="150" height="150" fill="#e0e0e0"/>
            <circle cx="75" cy="60" r="25" fill="#bdbdbd"/>
            <path d="M30 120 Q75 100 120 120 L120 150 L30 150 Z" fill="#bdbdbd"/>
            <text x="75" y="140" text-anchor="middle" font-family="Arial" font-size="12" fill="#757575">No Image</text>
        </svg>'''

        response = make_response(svg_content)
        response.headers['Content-Type'] = 'image/svg+xml'
        response.cache_control.max_age = 86400  # Cache for 24 hours
        return response

@app.route('/admin/users/<int:user_id>/profile')
def admin_view_user_profile(user_id):
    """Admin route to view any user's profile"""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('admin_panel'))

    try:
        user = User.query.get_or_404(user_id)

        # Get additional user data
        solves_count = len([sub for sub in user.submissions if sub.correct]) if hasattr(user, 'submissions') else 0

        team_name = None
        team_role = None
        if hasattr(user, 'team_membership') and user.team_membership:
            team_name = user.team_membership.team.name
            team_role = user.team_membership.role

        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'score': user.score,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'date_of_birth': user.date_of_birth.isoformat() if user.date_of_birth else None,
            'gender': user.gender,
            'country': user.country,
            'timezone': user.timezone,
            'bio': user.bio,
            'profile_picture': user.profile_picture,
            'current_streak': user.current_streak,
            'longest_streak': user.longest_streak,
            'last_solve_date': user.last_solve_date.isoformat() if user.last_solve_date else None,
            'solves_count': solves_count,
            'team_name': team_name,
            'team_role': team_role
        }

        return jsonify({
            'success': True,
            'user': user_data
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error fetching user profile: {str(e)}'
        }), 500

@app.route('/profile/test')
def test_profile():
    """Test route to check profile functionality"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Test data
        test_data = {
            'user_id': user.id,
            'username': user.username,
            'profile_fields': {
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'bio': user.bio,
                'country': user.country,
                'timezone': user.timezone,
                'gender': user.gender,
                'date_of_birth': user.date_of_birth.isoformat() if user.date_of_birth else None,
                'profile_picture': user.profile_picture,
                'score': user.score,
                'current_streak': user.current_streak,
                'longest_streak': user.longest_streak
            },
            'profile_picture_url': url_for('profile_picture', filename=user.profile_picture) if user.profile_picture else None,
            'upload_directory': os.path.join(app.instance_path, 'profile_pictures'),
            'upload_directory_exists': os.path.exists(os.path.join(app.instance_path, 'profile_pictures'))
        }

        return jsonify({
            'success': True,
            'message': 'Profile test successful',
            'data': test_data
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Profile test failed: {str(e)}'
        }), 500

@app.route('/profile/picture/test')
def test_profile_picture():
    """Test profile picture functionality"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Test upload directory
        upload_dir = os.path.join(app.instance_path, 'profile_pictures')
        upload_dir_exists = os.path.exists(upload_dir)

        # Try to create directory if it doesn't exist
        if not upload_dir_exists:
            try:
                os.makedirs(upload_dir, exist_ok=True)
                upload_dir_created = True
            except Exception as e:
                upload_dir_created = False
                upload_dir_error = str(e)
        else:
            upload_dir_created = True
            upload_dir_error = None

        # Check if user has profile picture
        has_profile_picture = bool(user.profile_picture)
        profile_picture_path = None
        profile_picture_exists = False

        if has_profile_picture:
            profile_picture_path = os.path.join(upload_dir, user.profile_picture)
            profile_picture_exists = os.path.exists(profile_picture_path)

        # Test data
        test_results = {
            'user_id': user.id,
            'username': user.username,
            'upload_directory': upload_dir,
            'upload_directory_exists': upload_dir_exists,
            'upload_directory_created': upload_dir_created,
            'upload_directory_error': upload_dir_error,
            'has_profile_picture': has_profile_picture,
            'profile_picture_filename': user.profile_picture,
            'profile_picture_path': profile_picture_path,
            'profile_picture_exists': profile_picture_exists,
            'profile_picture_url': url_for('profile_picture', filename=user.profile_picture) if user.profile_picture else None,
            'default_avatar_url': url_for('static', filename='images/default-avatar.svg'),
            'instance_path': app.instance_path,
            'static_folder': app.static_folder
        }

        return jsonify({
            'success': True,
            'message': 'Profile picture test completed',
            'results': test_results
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Profile picture test failed: {str(e)}'
        }), 500

# Notification system routes
@app.route('/notifications')
def notifications():
    """Show user notifications page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    # Get user's notifications, ordered by newest first
    notifications = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).all()
    
    return render_template('notifications.html', user=user, notifications=notifications)

@app.route('/api/notifications')
def api_notifications():
    """API endpoint to get user notifications"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Get unread notifications count
    unread_count = Notification.query.filter_by(user_id=user.id, read=False).count()
    
    # Get recent notifications (last 10)
    recent_notifications = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).limit(10).all()
    
    notifications_data = []
    for notif in recent_notifications:
        notifications_data.append({
            'id': notif.id,
            'title': notif.title,
            'message': notif.message,
            'type': notif.notification_type,
            'read': notif.read,
            'created_at': notif.created_at.strftime('%Y-%m-%d %H:%M:%S') if notif.created_at else None,
            'priority': notif.priority
        })
    
    return jsonify({
        'unread_count': unread_count,
        'notifications': notifications_data
    })

@app.route('/api/notifications/mark_read/<int:notification_id>', methods=['POST'])
def mark_notification_read(notification_id):
    """Mark a notification as read"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    notification = Notification.query.filter_by(id=notification_id, user_id=user.id).first()
    if not notification:
        return jsonify({'error': 'Notification not found'}), 404
    
    notification.read = True
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/notifications/mark_all_read', methods=['POST'])
def mark_all_notifications_read():
    """Mark all user notifications as read"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    Notification.query.filter_by(user_id=user.id, read=False).update({'read': True})
    db.session.commit()
    
    return jsonify({'success': True})

def create_notification(user_id, title, message, notification_type, related_id=None, related_type=None, priority='normal'):
    """Helper function to create notifications"""
    try:
        notification = Notification(
            user_id=user_id,
            title=title,
            message=message,
            notification_type=notification_type,
            related_id=related_id,
            related_type=related_type,
            priority=priority
        )
        db.session.add(notification)
        db.session.commit()
        
        # Emit WebSocket notification to user
        socketio.emit('new_notification', {
            'id': notification.id,
            'title': notification.title,
            'message': notification.message,
            'type': notification.notification_type,
            'priority': notification.priority,
            'created_at': notification.created_at.strftime('%Y-%m-%d %H:%M:%S') if notification.created_at else None
        }, room=f'user_{user_id}')
        
        return notification
    except Exception as e:
        print(f"Error creating notification: {e}")
        db.session.rollback()
        return None

# Chat system routes
@app.route('/chat')
def chat():
    """Show the chat page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    # Ensure default chat channel exists
    default_channel = ChatChannel.query.filter_by(id=1).first()
    if not default_channel:
        default_channel = ChatChannel(
            id=1,
            name='General',
            description='General chat channel',
            channel_type='public'
        )
        db.session.add(default_channel)
        db.session.commit()
    
    # Get recent chat messages with caching for better performance
    cache_key = f"chat_messages_1"

    def generate_chat_messages():
        messages = ChatMessage.query.filter_by(channel_id=1)\
            .order_by(ChatMessage.timestamp.desc())\
            .limit(30).all()  # Reduced to 30 for faster loading
        messages.reverse()  # Show oldest first
        return messages

    recent_messages = get_from_cache(cache_key, generate_chat_messages, timeout=10)  # 10 second cache

    # Get online users count (simplified)
    online_users_count = 1  # Will be enhanced with WebSocket tracking

    return render_template('chat.html',
                         user=user,
                         recent_messages=recent_messages,
                         online_users=online_users_count,
                         channel_name='General')

@app.route('/api/chat/messages')
def api_chat_messages():
    """API endpoint to get chat messages"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Get recent messages with caching and optimization
    limit = min(int(request.args.get('limit', 50)), 100)  # Max 100 messages
    cache_key = f"chat_api_messages_{limit}"

    def generate_api_messages():
        # Optimized query with join to get user data in one query
        messages = db.session.query(
            ChatMessage.id,
            ChatMessage.content,
            ChatMessage.timestamp,
            ChatMessage.user_id,
            User.username
        ).join(User, ChatMessage.user_id == User.id)\
         .filter(ChatMessage.channel_id == 1)\
         .order_by(ChatMessage.timestamp.desc())\
         .limit(limit).all()

        messages = list(reversed(messages))  # Show oldest first

        messages_data = []
        for msg in messages:
            messages_data.append({
                'id': msg.id,
                'username': msg.username,
                'message': msg.content,
                'created_at': msg.timestamp.strftime('%H:%M') if msg.timestamp else '',
                'user_id': msg.user_id,
                'is_own': msg.user_id == session['user_id'],
                'timestamp': msg.timestamp.isoformat() if msg.timestamp else ''
            })

        return messages_data

    messages_data = get_from_cache(cache_key, generate_api_messages, timeout=5)  # 5 second cache

    return jsonify({
        'success': True,
        'messages': messages_data,
        'count': len(messages_data)
    })

@app.route('/api/chat/send', methods=['POST'])
def api_send_message():
    """API endpoint to send a chat message"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    message_text = data.get('message', '').strip()
    
    if not message_text:
        return jsonify({'error': 'Message cannot be empty'}), 400
    
    if len(message_text) > 500:
        return jsonify({'error': 'Message too long (max 500 characters)'}), 400
    
    try:
        # Create chat message
        chat_message = ChatMessage(
            user_id=user.id,
            channel_id=1,  # Default channel ID
            content=message_text,
            message_type='text',
            timestamp=datetime.utcnow()
        )
        db.session.add(chat_message)
        db.session.commit()
        
        # Emit WebSocket message to all users
        socketio.emit('new_chat_message', {
            'id': chat_message.id,
            'username': user.username,
            'message': message_text,
            'created_at': chat_message.timestamp.strftime('%H:%M') if chat_message.timestamp else '',
            'user_id': user.id,
            'is_own': False
        })
        
        return jsonify({
            'success': True,
            'message': {
                'id': chat_message.id,
                'username': user.username,
                'message': message_text,
                'created_at': chat_message.timestamp.strftime('%H:%M') if chat_message.timestamp else '',
                'user_id': user.id,
                'is_own': True
            }
        })
        
    except Exception as e:
        print(f"Error sending chat message: {e}")
        db.session.rollback()
        return jsonify({'error': 'Failed to send message'}), 500

# WebSocket handlers for new features
@socketio.on('join_chat')
def handle_join_chat(data=None):
    """Handle client joining chat channel"""
    if 'user_id' not in session:
        return
    
    user_id = session['user_id']
    user = User.query.get(user_id)
    if user:
        join_room('chat_room')
        emit('user_joined_chat', {
            'username': user.username,
            'message': f'{user.username} joined the chat'
        }, room='chat_room')

@socketio.on('leave_chat')
def handle_leave_chat(data=None):
    """Handle client leaving chat channel"""
    if 'user_id' not in session:
        return
    
    user_id = session['user_id']
    user = User.query.get(user_id)
    if user:
        emit('user_left_chat', {
            'username': user.username,
            'message': f'{user.username} left the chat'
        }, room='chat_room')
        leave_room('chat_room')

@socketio.on('typing')
def handle_typing():
    """Handle user typing notification"""
    if 'user_id' not in session:
        return
    
    user_id = session['user_id']
    user = User.query.get(user_id)
    if user:
        emit('user_typing', {
            'userId': user.id,
            'username': user.username
        }, room='chat_room', include_self=False)

@socketio.on('stop_typing')
def handle_stop_typing():
    """Handle user stopped typing notification"""
    if 'user_id' not in session:
        return
    
    user_id = session['user_id']
    user = User.query.get(user_id)
    if user:
        emit('user_stopped_typing', {
            'userId': user.id,
            'username': user.username
        }, room='chat_room', include_self=False)

@socketio.on('join_notifications')
def handle_join_notifications():
    """Handle client joining notifications room"""
    if 'user_id' in session:
        join_room(f'user_{session["user_id"]}')
        emit('notifications_joined', {'user_id': session['user_id']})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    if 'user_id' in session:
        leave_room(f'user_{session["user_id"]}')
    print('Client disconnected')

# Background task to update user progress
def update_user_progress():
    """Update user progress records daily"""
    with app.app_context():
        today = datetime.utcnow().date()
        
        # Get all users
        users = User.query.all()
        
        for user in users:
            # Check if progress record exists for today
            existing_progress = UserProgress.query.filter_by(
                user_id=user.id,
                date=today
            ).first()
            
            if not existing_progress:
                # Get today's solves
                today_start = datetime.combine(today, datetime.min.time())
                today_end = datetime.combine(today, datetime.max.time())
                
                today_solves = Solve.query.filter(
                    Solve.user_id == user.id,
                    Solve.timestamp >= today_start,
                    Solve.timestamp <= today_end
                ).all()
                
                # Calculate today's stats
                challenges_solved = len(today_solves)
                # Build a local cache of challenge id -> points to avoid NameError
                challenge_points = {c.id: c.points for c in Challenge.query.all()}
                points_earned = sum(challenge_points.get(s.challenge_id, 0) for s in today_solves)
                
                # Get hints used today
                hints_used = UserHint.query.filter(
                    UserHint.user_id == user.id,
                    UserHint.revealed_at >= today_start,
                    UserHint.revealed_at <= today_end
                ).count()
                
                # Create progress record
                progress = UserProgress(
                    user_id=user.id,
                    date=today,
                    challenges_solved=challenges_solved,
                    points_earned=points_earned,
                    hints_used=hints_used,
                    time_spent_minutes=0  # Could be calculated from session data
                )
                db.session.add(progress)
        
        db.session.commit()

# Background progress updater function (will be started in main)
def start_progress_updater():
    """Start background task for updating user progress"""
    def progress_worker():
        while True:
            try:
                with app.app_context():
                    update_user_progress()
                time.sleep(86400)  # Run once per day
            except Exception as e:
                print(f"Error updating progress: {e}")
                time.sleep(3600)  # Wait 1 hour on error
    
    if not app.config.get('PROGRESS_UPDATER_STARTED'):
        progress_thread = threading.Thread(target=progress_worker, daemon=True)
        progress_thread.start()
        app.config['PROGRESS_UPDATER_STARTED'] = True

# Ultra-fast API endpoints for maximum speed
@app.route('/api/fast/dashboard')
def api_fast_dashboard():
    """Ultra-fast dashboard API endpoint"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        user_id = session['user_id']
        cache_key = f"fast_dashboard_{user_id}"

        def generate_fast_dashboard():
            # Minimal query for maximum speed
            user = db.session.query(User.id, User.username, User.score).filter_by(id=user_id).first()
            if not user:
                return None

            # Get challenge count and solved count in one query
            challenge_stats = db.session.query(
                func.count(Challenge.id).label('total'),
                func.count(Solve.id).label('solved')
            ).outerjoin(
                Solve, (Challenge.id == Solve.challenge_id) & (Solve.user_id == user_id)
            ).first()

            return {
                'user': {'id': user.id, 'username': user.username, 'score': user.score},
                'challenges': {'total': challenge_stats.total, 'solved': challenge_stats.solved},
                'progress': round((challenge_stats.solved / challenge_stats.total * 100) if challenge_stats.total > 0 else 0, 1)
            }

        data = get_from_cache(cache_key, generate_fast_dashboard, timeout=30)

        if data:
            g.cache_hit = True
            return jsonify({'success': True, 'data': data})
        else:
            return jsonify({'error': 'Failed to load dashboard data'}), 500

    except Exception as e:
        return jsonify({'error': f'Dashboard API error: {str(e)}'}), 500

@app.route('/api/fast/leaderboard')
def api_fast_leaderboard():
    """Ultra-fast leaderboard API endpoint"""
    try:
        limit = min(int(request.args.get('limit', 10)), 50)  # Max 50 for speed
        cache_key = f"fast_leaderboard_{limit}"

        def generate_fast_leaderboard():
            # Minimal query for top users
            users = db.session.query(
                User.username, User.score
            ).filter(
                User.role != 'admin'
            ).order_by(
                User.score.desc()
            ).limit(limit).all()

            return [{'username': u.username, 'score': u.score, 'rank': i+1}
                   for i, u in enumerate(users)]

        data = get_from_cache(cache_key, generate_fast_leaderboard, timeout=30)
        g.cache_hit = True
        return jsonify({'success': True, 'leaderboard': data})

    except Exception as e:
        return jsonify({'error': f'Leaderboard API error: {str(e)}'}), 500

@app.route('/api/fast/user-stats')
def api_fast_user_stats():
    """Ultra-fast user statistics API endpoint"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        user_id = session['user_id']
        cache_key = f"fast_user_stats_{user_id}"

        def generate_user_stats():
            # Single optimized query for user stats
            user_stats = db.session.query(
                User.username,
                User.score,
                User.country,
                func.count(Solve.id).label('total_solves'),
                func.count(func.distinct(Challenge.category)).label('categories_solved')
            ).outerjoin(
                Solve, Solve.user_id == User.id
            ).outerjoin(
                Challenge, Challenge.id == Solve.challenge_id
            ).filter(
                User.id == user_id
            ).group_by(User.id, User.username, User.score, User.country).first()

            if not user_stats:
                return None

            # Get user rank efficiently
            rank = db.session.query(func.count(User.id)).filter(
                User.score > user_stats.score,
                User.role != 'admin'
            ).scalar() + 1

            return {
                'username': user_stats.username,
                'score': user_stats.score,
                'country': user_stats.country,
                'total_solves': user_stats.total_solves,
                'categories_solved': user_stats.categories_solved,
                'rank': rank
            }

        data = get_from_cache(cache_key, generate_user_stats, timeout=60)

        if data:
            g.cache_hit = True
            return jsonify({'success': True, 'stats': data})
        else:
            return jsonify({'error': 'Failed to load user stats'}), 500

    except Exception as e:
        return jsonify({'error': f'User stats API error: {str(e)}'}), 500

@app.route('/api/fast/recent-activity')
def api_fast_recent_activity():
    """Ultra-fast recent activity API endpoint"""
    try:
        limit = min(int(request.args.get('limit', 10)), 20)  # Max 20 for speed
        cache_key = f"fast_recent_activity_{limit}"

        def generate_recent_activity():
            # Optimized query for recent solves
            recent_solves = db.session.query(
                Solve.timestamp,
                User.username,
                Challenge.title,
                Challenge.points,
                Challenge.category
            ).join(User, Solve.user_id == User.id)\
             .join(Challenge, Solve.challenge_id == Challenge.id)\
             .filter(User.role != 'admin')\
             .order_by(Solve.timestamp.desc())\
             .limit(limit).all()

            activity_list = []
            for solve in recent_solves:
                activity_list.append({
                    'username': solve.username,
                    'challenge': solve.title,
                    'points': solve.points,
                    'category': solve.category,
                    'time_ago': (datetime.utcnow() - solve.timestamp).total_seconds() if solve.timestamp else 0
                })

            return activity_list

        data = get_from_cache(cache_key, generate_recent_activity, timeout=30)
        g.cache_hit = True
        return jsonify({'success': True, 'activity': data})

    except Exception as e:
        return jsonify({'error': f'Recent activity API error: {str(e)}'}), 500

@app.route('/api/fast/challenge/<int:challenge_id>')
def api_fast_challenge(challenge_id):
    """Ultra-fast challenge data API endpoint"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        user_id = session['user_id']
        cache_key = f"fast_challenge_{challenge_id}_{user_id}"

        def generate_challenge_api_data():
            # Optimized single query for challenge data
            challenge_data = db.session.query(
                Challenge.id,
                Challenge.title,
                Challenge.description,
                Challenge.points,
                Challenge.category,
                Challenge.difficulty,
                Challenge.opens_at,
                Challenge.closes_at
            ).filter_by(id=challenge_id).first()

            if not challenge_data:
                return None

            # Check if solved
            is_solved = db.session.query(Solve.id).filter_by(
                user_id=user_id,
                challenge_id=challenge_id
            ).first() is not None

            # Get hints
            hints = db.session.query(
                Hint.id,
                Hint.text,
                Hint.cost,
                Hint.display_order
            ).filter_by(challenge_id=challenge_id).order_by(Hint.display_order).all()

            # Get revealed hints
            revealed_hints = set(
                h.hint_id for h in db.session.query(UserHint.hint_id).filter_by(user_id=user_id).all()
            )

            return {
                'id': challenge_data.id,
                'title': challenge_data.title,
                'description': challenge_data.description,
                'points': challenge_data.points,
                'category': challenge_data.category,
                'difficulty': challenge_data.difficulty,
                'is_solved': is_solved,
                'hints': [{
                    'id': h.id,
                    'text': h.text,
                    'cost': h.cost,
                    'display_order': h.display_order,
                    'revealed': h.id in revealed_hints
                } for h in hints]
            }

        data = get_from_cache(cache_key, generate_challenge_api_data, timeout=30)

        if data:
            g.cache_hit = True
            return jsonify({'success': True, 'challenge': data})
        else:
            return jsonify({'error': 'Challenge not found'}), 404

    except Exception as e:
        return jsonify({'error': f'Challenge API error: {str(e)}'}), 500



@app.route('/admin/optimize_performance', methods=['POST'])
def optimize_performance():
    """Run performance optimizations"""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('admin_panel'))

    try:
        optimizations_run = []

        # Clear cache
        clear_cache()
        optimizations_run.append("Cache cleared")

        # Clean up old chat messages (keep last 500 per channel)
        try:
            channels = db.session.query(ChatMessage.channel_id).distinct().all()
            total_cleaned = 0

            for (channel_id,) in channels:
                total_messages = ChatMessage.query.filter_by(channel_id=channel_id).count()
                if total_messages > 500:
                    old_messages = ChatMessage.query.filter_by(channel_id=channel_id)\
                        .order_by(ChatMessage.id.asc())\
                        .limit(total_messages - 500).all()

                    for msg in old_messages:
                        db.session.delete(msg)

                    total_cleaned += len(old_messages)

            if total_cleaned > 0:
                optimizations_run.append(f"Cleaned {total_cleaned} old chat messages")
        except Exception as e:
            optimizations_run.append(f"Chat cleanup skipped: {e}")

        # Remove users with score 0 and no activity (older than 7 days)
        try:
            cutoff_time = datetime.utcnow() - timedelta(days=7)
            # Since we don't have created_at or email_verified, skip this optimization
            optimizations_run.append("User cleanup skipped (no timestamp fields)")
        except Exception as e:
            optimizations_run.append(f"User cleanup skipped: {e}")

        db.session.commit()

        # Pre-warm cache
        get_from_cache('leaderboard', generate_leaderboard_data)
        get_from_cache('challenge_stats', generate_challenge_stats)
        optimizations_run.append("Cache pre-warmed")

        flash(f'Performance optimization completed! Applied: {", ".join(optimizations_run)}', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Error during optimization: {e}', 'error')

    return redirect(url_for('admin_panel'))

@app.route('/admin/speed_optimize', methods=['POST'])
def speed_optimize():
    """Run aggressive speed optimizations"""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('admin_panel'))

    try:
        optimizations_run = []

        # Clear all caches for fresh start
        clear_cache()
        optimizations_run.append("All caches cleared")

        # Create database indexes for speed
        try:
            index_commands = [
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_role_score ON \"user\"(role, score DESC);",
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_solve_user_challenge ON solve(user_id, challenge_id);",
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_solve_timestamp_desc ON solve(timestamp DESC);",
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_challenge_category_points ON challenge(category, points DESC);",
            ]

            for command in index_commands:
                try:
                    db.engine.execute(command)
                    optimizations_run.append(f"Database index created")
                except Exception:
                    pass  # Index may already exist

        except Exception as e:
            optimizations_run.append(f"Database optimization skipped: {str(e)[:50]}")

        # Pre-warm critical caches
        try:
            get_from_cache('leaderboard', generate_leaderboard_data, timeout=60)
            get_from_cache('challenge_stats', generate_challenge_stats, timeout=180)
            optimizations_run.append("Critical caches pre-warmed")
        except Exception as e:
            optimizations_run.append(f"Cache warming failed: {str(e)[:50]}")

        # Clean up old data for speed
        try:
            # Remove old chat messages (keep last 200 per channel)
            channels = db.session.query(ChatMessage.channel_id).distinct().all()
            total_cleaned = 0

            for (channel_id,) in channels:
                total_messages = ChatMessage.query.filter_by(channel_id=channel_id).count()
                if total_messages > 200:
                    old_messages = ChatMessage.query.filter_by(channel_id=channel_id)\
                        .order_by(ChatMessage.id.asc())\
                        .limit(total_messages - 200).all()

                    for msg in old_messages:
                        db.session.delete(msg)

                    total_cleaned += len(old_messages)

            if total_cleaned > 0:
                optimizations_run.append(f"Cleaned {total_cleaned} old messages")

            db.session.commit()

        except Exception as e:
            optimizations_run.append(f"Data cleanup failed: {str(e)[:50]}")

        # Get cache statistics
        cache_stats = get_cache_stats()
        optimizations_run.append(f"Cache entries: {cache_stats['entries']}")

        flash(f'Speed optimization completed! Applied: {", ".join(optimizations_run)}', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Error during speed optimization: {e}', 'error')

    return redirect(url_for('admin_panel'))

if __name__ == "__main__":
    try:
        print("Starting CTF application...")
        
        # Ensure tables exist in the configured database
        with app.app_context():
            print("Creating database tables...")
            db.create_all()
            print("Database tables created successfully")
        
        # Start background tasks
        print("Starting background tasks...")
        start_tournament_timer()
        start_progress_updater()
        print("Background tasks started successfully")
        
        print(f"Starting Flask-SocketIO server on port {Config.PORT}...")
        socketio.run(app, host='0.0.0.0', debug=Config.DEBUG, port=Config.PORT)
        
    except Exception as e:
        print(f"Error starting application: {e}")
        import traceback
        traceback.print_exc()