from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os
import time
from datetime import datetime, timedelta
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

mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize database with app
db.init_app(app)
Migrate(app, db)

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
    challenges = Challenge.query.filter(
        (Challenge.opens_at.is_(None) | (Challenge.opens_at <= now)) &
        (Challenge.closes_at.is_(None) | (Challenge.closes_at > now))
    ).all()
    solved_ids = {sub.challenge_id for sub in user.submissions if sub.correct}
    total_players = User.query.filter(User.role != 'admin').count()
    total_challenges = Challenge.query.count()
    total_solves = Solve.query.count() if 'Solve' in globals() else 0
    max_score = db.session.query(db.func.sum(Challenge.points)).scalar() or 0
    
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
    """Enhanced challenge view with improved UI and hint system"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    if user.role == 'admin':
        flash("Admins cannot play the game.", "error")
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
    
    # Check if user has solved this challenge
    solved_ids = {sub.challenge_id for sub in user.submissions if sub.correct}
    is_solved = challenge.id in solved_ids
    
    # Get revealed hints for this user
    revealed_hint_ids = set(h.hint_id for h in UserHint.query.filter_by(user_id=session['user_id']).all())
    
    # Get message from flash or session
    message = None
    if request.args.get('message'):
        message = request.args.get('message')
    
    return render_template(
        'challenge_enhanced.html',
        challenge=challenge,
        solved_ids=solved_ids,
        revealed_hint_ids=revealed_hint_ids,
        message=message,
        user=user
    )

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
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Admins should not play
    if session.get('role') == 'admin':
        flash("Admins cannot view answers.", "error")
        return redirect(url_for('admin_panel'))
    challenge = db.session.get(Challenge, challenge_id)
    if not challenge:
        flash('Challenge not found.', 'danger')
        return redirect(url_for('dashboard'))
    answer = fernet.decrypt(challenge.flag_encrypted).decode()
    
    # Check if request wants JSON (for enhanced challenge view)
    if request.headers.get('Accept') == 'application/json' or request.args.get('format') == 'json':
        return jsonify({'answer': answer})
    
    return render_template('show_answer.html', challenge=challenge, answer=answer)

@app.route('/scoreboard')
def scoreboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get current user for highlighting
    current_user = db.session.get(User, session['user_id'])
    
    # Count only non-admin users for total players
    total_users = User.query.filter(User.role != 'admin').count()
    total_challenges = Challenge.query.count()
    
    # Count solves for non-admin users only to avoid including admin activity
    total_solves = (
        db.session.query(func.count(Solve.id))
        .join(User, Solve.user_id == User.id)
        .filter(User.role != 'admin')
        .scalar()
    ) or 0
    
    # Get only non-admin users and their solve/score info
    users_data = (
        db.session.query(
            User.username,
            func.count(Solve.id).label('solve_count'),
            func.coalesce(func.sum(Challenge.points), 0).label('score')
        )
        .filter(User.role != 'admin')  # Exclude admin users
        .outerjoin(Solve, Solve.user_id == User.id)
        .outerjoin(Challenge, Challenge.id == Solve.challenge_id)
        .group_by(User.id, User.username)
        .order_by(func.coalesce(func.sum(Challenge.points), 0).desc(), User.username)
        .all()
    )
    
    # Calculate average score
    total_score = sum(user.score for user in users_data)
    avg_score = total_score / len(users_data) if users_data else 0
    
    # Active tournament (for navigation hints)
    active_tournament = Tournament.query.filter_by(active=True).first()

    return render_template(
        'scoreboard.html',
        users=users_data,
        total_users=total_users,
        total_challenges=total_challenges,
        total_solves=total_solves,
        avg_score=avg_score,
        active_tournament=active_tournament,
        current_user=current_user
    )

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
        name = request.form.get('name', 'Tournament')
        start = request.form.get('start_time')
        end = request.form.get('end_time')
        try:
            start_dt = datetime.fromisoformat(start)
            end_dt = datetime.fromisoformat(end)
        except Exception:
            flash('Invalid date format. Use ISO format: YYYY-MM-DDTHH:MM:SS', 'error')
            return redirect(url_for('tournaments'))
        tour = Tournament(name=name, start_time=start_dt, end_time=end_dt, active=False)
        db.session.add(tour)
        db.session.commit()
        
        # Send admin notification email
        notify_admin(
            "Tournament Created",
            f"Tournament '{name}' has been created\n"
            f"Start Time: {start_dt.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"End Time: {end_dt.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Created by: Admin\n"
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        
        flash('Tournament created', 'success')
        return redirect(url_for('tournaments'))
    all_t = Tournament.query.order_by(Tournament.start_time.desc()).all()
    return render_template('tournaments.html', tournaments=all_t)

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
            role='admin',
            created_at=datetime.utcnow(),
            email_verified=True,
            total_points=0
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
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'email_verified': user.email_verified
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
    
    if request.method == 'POST':
        try:
            # Update basic profile information
            user.first_name = request.form.get('first_name', '').strip()
            user.last_name = request.form.get('last_name', '').strip()
            user.bio = request.form.get('bio', '').strip()
            user.country = request.form.get('country', '').strip()
            user.timezone = request.form.get('timezone', '').strip()
            user.gender = request.form.get('gender', '').strip()
            
            # Handle date of birth
            dob_str = request.form.get('date_of_birth', '').strip()
            if dob_str:
                try:
                    user.date_of_birth = datetime.strptime(dob_str, '%Y-%m-%d').date()
                except ValueError:
                    flash('Invalid date format for date of birth', 'error')
                    return redirect(url_for('profile'))
            
            # Handle profile picture upload
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and file.filename:
                    # Check file type
                    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
                    if '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
                        # Create uploads directory if it doesn't exist
                        upload_dir = os.path.join(app.instance_path, 'profile_pictures')
                        os.makedirs(upload_dir, exist_ok=True)
                        
                        # Generate unique filename
                        filename = f"profile_{user.id}_{int(time.time())}.{file.filename.rsplit('.', 1)[1].lower()}"
                        filepath = os.path.join(upload_dir, filename)
                        
                        # Save file
                        file.save(filepath)
                        
                        # Update user profile picture path
                        user.profile_picture = filename
                        
                        flash('Profile picture updated successfully!', 'success')
                    else:
                        flash('Invalid file type. Please upload PNG, JPG, JPEG, or GIF files only.', 'error')
                        return redirect(url_for('profile'))
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'error')
    
    return render_template('profile.html', user=user)

@app.route('/profile/picture/<filename>')
def profile_picture(filename):
    """Serve profile pictures"""
    if 'user_id' not in session:
        return '', 404
    
    upload_dir = os.path.join(app.instance_path, 'profile_pictures')
    return send_from_directory(upload_dir, filename)

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
    
    # Get recent chat messages (last 50)
    recent_messages = ChatMessage.query.order_by(ChatMessage.timestamp.desc()).limit(50).all()
    recent_messages.reverse()  # Show oldest first
    
    return render_template('chat.html', user=user, recent_messages=recent_messages)

@app.route('/api/chat/messages')
def api_chat_messages():
    """API endpoint to get chat messages"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Get recent messages (last 100)
    messages = ChatMessage.query.order_by(ChatMessage.timestamp.desc()).limit(100).all()
    messages.reverse()  # Show oldest first
    
    messages_data = []
    for msg in messages:
        messages_data.append({
            'id': msg.id,
            'username': msg.user.username,
            'message': msg.content,
            'created_at': msg.timestamp.strftime('%H:%M') if msg.timestamp else '',
            'user_id': msg.user_id,
            'is_own': msg.user_id == session['user_id']
        })
    
    return jsonify({'messages': messages_data})

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