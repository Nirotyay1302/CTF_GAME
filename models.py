from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.sql import func

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    role = db.Column(db.String(20), default='user')
    score = db.Column(db.Integer, default=0)
    
    # Profile fields
    first_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    gender = db.Column(db.String(20), nullable=True)  # male, female, other
    profile_picture = db.Column(db.String(255), nullable=True)  # Path to profile picture
    bio = db.Column(db.Text, nullable=True)
    country = db.Column(db.String(100), nullable=True)
    timezone = db.Column(db.String(50), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    # Relationships
    submissions = db.relationship('Submission', back_populates='user', lazy=True)
    solves = db.relationship('Solve', back_populates='user', lazy=True)
    team_membership = db.relationship('TeamMembership', back_populates='user', uselist=False, lazy=True)
    notifications = db.relationship('Notification', back_populates='user', lazy=True)
    chat_messages = db.relationship('ChatMessage', back_populates='user', lazy=True)
    hints_purchased = db.relationship('UserHint', back_populates='user', lazy=True)
    progress_records = db.relationship('UserProgress', back_populates='user', lazy=True)

    # Streak tracking
    last_solve_date = db.Column(db.Date, nullable=True)
    current_streak = db.Column(db.Integer, default=0)
    longest_streak = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<User {self.username}>'

    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def full_name(self):
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.username

class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    flag_encrypted = db.Column(db.LargeBinary, nullable=False)
    points = db.Column(db.Integer, default=10)
    category = db.Column(db.String(50), default='misc')
    difficulty = db.Column(db.String(20), default='easy')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    opens_at = db.Column(db.DateTime, nullable=True)
    closes_at = db.Column(db.DateTime, nullable=True)
    # Security: salted hash for validation without decrypting the flag
    flag_salt = db.Column(db.LargeBinary, nullable=True)
    flag_hash = db.Column(db.LargeBinary, nullable=True)
    # Optional per-challenge docker image for isolated instances
    docker_image = db.Column(db.String(200), nullable=True)
    # Hints available for this challenge
    hints = db.relationship('Hint', backref='challenge', lazy=True, cascade='all, delete-orphan')

class Solve(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    solved_at = db.Column(db.DateTime, default=datetime.utcnow)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Keep for compatibility

    # Relationships
    challenge = db.relationship('Challenge', backref='solves', lazy=True)
    user = db.relationship('User', back_populates='solves')

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80))
    action = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    submitted_flag = db.Column(db.String(150), nullable=False)
    is_correct = db.Column(db.Boolean, default=False)
    correct = db.Column(db.Boolean, default=False)  # Keep for compatibility
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Keep for compatibility

    # Relationships
    challenge = db.relationship('Challenge', backref='submissions', lazy=True)
    user = db.relationship('User', back_populates='submissions')

# Team play models
class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    team_code = db.Column(db.String(10), unique=True, nullable=False)  # Unique team code for joining
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Members in this team
    memberships = db.relationship('TeamMembership', backref='team', lazy=True, cascade='all, delete-orphan')

class TeamMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='member')
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    user = db.relationship('User', back_populates='team_membership')

# Tournament/season models
class Tournament(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    active = db.Column(db.Boolean, default=False)

# Achievements & streaks
class Achievement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)  # e.g., FIRST_BLOOD
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(255), nullable=False)

class UserAchievement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    achievement_id = db.Column(db.Integer, db.ForeignKey('achievement.id'), nullable=False)
    awarded_at = db.Column(db.DateTime, default=datetime.utcnow)

# Per-session container instance
class UserChallengeInstance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    container_id = db.Column(db.String(64), nullable=True)  # Docker container ID
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='running')  # running, stopped, expired
    port_mappings = db.Column(db.Text, nullable=True)  # JSON string of port mappings

# Tournament rounds and brackets
class TournamentRound(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.id'), nullable=False)
    name = db.Column(db.String(50), nullable=False)  # e.g., "Qualifiers", "Quarter Finals"
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    challenge_pool = db.Column(db.Text, nullable=True)  # JSON array of challenge IDs
    max_teams = db.Column(db.Integer, nullable=True)  # Max teams that advance
    round_type = db.Column(db.String(20), default='elimination')  # elimination, points, bracket
    active = db.Column(db.Boolean, default=False)
    tournament = db.relationship('Tournament', backref=db.backref('rounds', lazy=True, cascade="all, delete-orphan"))

class TournamentBracket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.id'), nullable=False)
    round_id = db.Column(db.Integer, db.ForeignKey('tournament_round.id'), nullable=False)
    team1_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=True)
    team2_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=True)
    winner_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=True)
    match_time = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, active, completed
    score1 = db.Column(db.Integer, default=0)
    score2 = db.Column(db.Integer, default=0)

# Discord-style chat system
class ChatChannel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    channel_type = db.Column(db.String(20), default='public')  # public, team, admin
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=True)  # For team channels
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    room = db.Column(db.String(50), default='general')  # general, team, admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', back_populates='chat_messages')

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else 'Unknown',
            'content': self.content,
            'room': self.room,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# Dynamic challenge generation
class ChallengeTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description_template = db.Column(db.Text, nullable=False)  # Jinja2 template
    flag_template = db.Column(db.String(200), nullable=False)  # e.g., "flag{user}_{random_hex}"
    points_range = db.Column(db.String(20), nullable=False)  # e.g., "10-50"
    category = db.Column(db.String(50), default='misc')
    difficulty = db.Column(db.String(20), default='easy')
    docker_image = db.Column(db.String(200), nullable=True)
    parameters = db.Column(db.Text, nullable=True)  # JSON of available parameters
    active = db.Column(db.Boolean, default=True)

class DynamicChallenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    template_id = db.Column(db.Integer, db.ForeignKey('challenge_template.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Who generated it
    generated_flag = db.Column(db.String(200), nullable=False)
    parameters_used = db.Column(db.Text, nullable=True)  # JSON of actual parameters
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    solved = db.Column(db.Boolean, default=False)
    solved_at = db.Column(db.DateTime, nullable=True)
    template = db.relationship('ChallengeTemplate', backref=db.backref('generated_challenges', lazy=True))

# User progress analytics
class UserProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    challenges_solved = db.Column(db.Integer, default=0)
    points_earned = db.Column(db.Integer, default=0)
    hints_used = db.Column(db.Integer, default=0)
    time_spent_minutes = db.Column(db.Integer, default=0)
    category_breakdown = db.Column(db.Text, nullable=True)  # JSON of solves per category
    difficulty_breakdown = db.Column(db.Text, nullable=True)  # JSON of solves per difficulty
    user = db.relationship('User', back_populates='progress_records')

# Docker container management
class DockerInstance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    container_id = db.Column(db.String(64), nullable=False)
    image_name = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default='running')  # running, stopped, error
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_health_check = db.Column(db.DateTime, nullable=True)
    port_mappings = db.Column(db.Text, nullable=True)  # JSON of port mappings
    resource_usage = db.Column(db.Text, nullable=True)  # JSON of CPU/memory usage
    challenge = db.relationship('Challenge', backref=db.backref('docker_instances', lazy=True, cascade="all, delete-orphan"))

# Notifications system
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), default='info')  # info, success, warning, error
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    user = db.relationship('User', back_populates='notifications')

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'message': self.message,
            'type': self.type,
            'read': self.read,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# Note: ChatMessage is already defined above, using that one

# User hints purchased
class UserHint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    hint_id = db.Column(db.Integer, db.ForeignKey('hint.id'), nullable=False)
    purchased_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    hint = db.relationship('Hint', backref='purchases', lazy=True)
    user = db.relationship('User', back_populates='hints_purchased')

# Hints for challenges
class Hint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)  # Changed from 'text' to 'content'
    cost = db.Column(db.Integer, nullable=False, default=5)
    display_order = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# UserHint and Notification are already defined above


