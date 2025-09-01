"""
Initialize sample data for the CTF application
"""

from ctf_app_full import app, db, encrypt_flag
from models import User, Challenge, Team, Hint
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
import secrets

def create_sample_users():
    """Create sample users"""
    users = [
        {
            'username': 'admin',
            'email': 'admin@ctf.local',
            'password': 'admin123',
            'role': 'admin',
            'first_name': 'Admin',
            'last_name': 'User'
        },
        {
            'username': 'alice',
            'email': 'alice@example.com',
            'password': 'password123',
            'role': 'user',
            'first_name': 'Alice',
            'last_name': 'Smith'
        },
        {
            'username': 'bob',
            'email': 'bob@example.com',
            'password': 'password123',
            'role': 'user',
            'first_name': 'Bob',
            'last_name': 'Johnson'
        },
        {
            'username': 'charlie',
            'email': 'charlie@example.com',
            'password': 'password123',
            'role': 'user',
            'first_name': 'Charlie',
            'last_name': 'Brown'
        }
    ]
    
    created_users = []
    for user_data in users:
        existing_user = User.query.filter_by(username=user_data['username']).first()
        if not existing_user:
            # Set is_player=False for admin accounts
            is_player = user_data['role'] != 'admin'
            user = User(
                username=user_data['username'],
                email=user_data['email'],
                password_hash=generate_password_hash(user_data['password']),
                role=user_data['role'],
                first_name=user_data['first_name'],
                last_name=user_data['last_name'],
                score=0,
                is_player=is_player
            )
            db.session.add(user)
            created_users.append(user)
            print(f"Created user: {user_data['username']}")
        else:
            print(f"User already exists: {user_data['username']}")
            created_users.append(existing_user)
    
    return created_users

def create_sample_challenges():
    """Create sample challenges"""
    challenges = [
        {
            'title': 'Welcome to CTF',
            'description': 'Find the flag hidden in the source code of this page.',
            'flag': 'CTF{welcome_to_the_game}',
            'points': 50,
            'category': 'misc',
            'difficulty': 'easy'
        },
        {
            'title': 'Basic Web',
            'description': 'Inspect the HTTP headers to find the flag.',
            'flag': 'CTF{http_headers_are_fun}',
            'points': 100,
            'category': 'web',
            'difficulty': 'easy'
        },
        {
            'title': 'Caesar Cipher',
            'description': 'Decode this message: PGS{pnrfne_pvgure_vf_rnfl}',
            'flag': 'CTF{caesar_cipher_is_easy}',
            'points': 75,
            'category': 'crypto',
            'difficulty': 'easy'
        },
        {
            'title': 'SQL Injection',
            'description': 'Find a way to bypass the login form using SQL injection.',
            'flag': 'CTF{sql_injection_master}',
            'points': 200,
            'category': 'web',
            'difficulty': 'medium'
        },
        {
            'title': 'Buffer Overflow',
            'description': 'Exploit the buffer overflow vulnerability to get the flag.',
            'flag': 'CTF{buffer_overflow_pwned}',
            'points': 300,
            'category': 'pwn',
            'difficulty': 'hard'
        },
        {
            'title': 'Reverse Engineering',
            'description': 'Analyze the binary to find the hidden flag.',
            'flag': 'CTF{reverse_engineering_pro}',
            'points': 250,
            'category': 'reverse',
            'difficulty': 'medium'
        },
        {
            'title': 'Digital Forensics',
            'description': 'Examine the memory dump to recover the flag.',
            'flag': 'CTF{forensics_detective}',
            'points': 180,
            'category': 'forensics',
            'difficulty': 'medium'
        },
        {
            'title': 'Steganography',
            'description': 'The flag is hidden in this image using steganography.',
            'flag': 'CTF{hidden_in_plain_sight}',
            'points': 150,
            'category': 'steganography',
            'difficulty': 'medium'
        },
        {
            'title': 'OSINT Challenge',
            'description': 'Use open source intelligence to find information about the target.',
            'flag': 'CTF{osint_investigation_complete}',
            'points': 120,
            'category': 'osint',
            'difficulty': 'easy'
        },
        {
            'title': 'Advanced Crypto',
            'description': 'Break this advanced encryption scheme to get the flag.',
            'flag': 'CTF{advanced_crypto_broken}',
            'points': 400,
            'category': 'crypto',
            'difficulty': 'expert'
        }
    ]
    
    created_challenges = []
    for challenge_data in challenges:
        existing_challenge = Challenge.query.filter_by(title=challenge_data['title']).first()
        if not existing_challenge:
            challenge = Challenge(
                title=challenge_data['title'],
                description=challenge_data['description'],
                flag_encrypted=encrypt_flag(challenge_data['flag']),
                points=challenge_data['points'],
                category=challenge_data['category'],
                difficulty=challenge_data['difficulty'],
                created_at=datetime.utcnow()
            )
            db.session.add(challenge)
            created_challenges.append(challenge)
            print(f"Created challenge: {challenge_data['title']}")
        else:
            print(f"Challenge already exists: {challenge_data['title']}")
            created_challenges.append(existing_challenge)
    
    return created_challenges

def create_sample_teams():
    """Create sample teams"""
    teams = [
        {
            'name': 'Team Alpha',
            'team_code': 'ALPHA123'
        },
        {
            'name': 'Team Beta',
            'team_code': 'BETA456'
        },
        {
            'name': 'Team Gamma',
            'team_code': 'GAMMA789'
        }
    ]
    
    created_teams = []
    for team_data in teams:
        existing_team = Team.query.filter_by(name=team_data['name']).first()
        if not existing_team:
            team = Team(
                name=team_data['name'],
                team_code=team_data['team_code'],
                created_at=datetime.utcnow()
            )
            db.session.add(team)
            created_teams.append(team)
            print(f"Created team: {team_data['name']}")
        else:
            print(f"Team already exists: {team_data['name']}")
            created_teams.append(existing_team)
    
    return created_teams

def create_sample_hints(challenges):
    """Create sample hints for challenges"""
    hints_data = [
        {
            'challenge_title': 'Welcome to CTF',
            'content': 'Look at the HTML source code of the page.',
            'cost': 10
        },
        {
            'challenge_title': 'Basic Web',
            'content': 'Use browser developer tools to inspect network requests.',
            'cost': 15
        },
        {
            'challenge_title': 'Caesar Cipher',
            'content': 'Try shifting each letter by 13 positions (ROT13).',
            'cost': 20
        },
        {
            'challenge_title': 'SQL Injection',
            'content': 'Try using single quotes to break out of the SQL query.',
            'cost': 30
        },
        {
            'challenge_title': 'Buffer Overflow',
            'content': 'Look for functions that don\'t check buffer boundaries.',
            'cost': 50
        }
    ]
    
    created_hints = []
    for hint_data in hints_data:
        challenge = next((c for c in challenges if c.title == hint_data['challenge_title']), None)
        if challenge:
            existing_hint = Hint.query.filter_by(
                challenge_id=challenge.id,
                content=hint_data['content']
            ).first()
            
            if not existing_hint:
                hint = Hint(
                    challenge_id=challenge.id,
                    content=hint_data['content'],
                    cost=hint_data['cost']
                )
                db.session.add(hint)
                created_hints.append(hint)
                print(f"Created hint for: {hint_data['challenge_title']}")
            else:
                print(f"Hint already exists for: {hint_data['challenge_title']}")
                created_hints.append(existing_hint)
    
    return created_hints

def initialize_sample_data():
    """Initialize all sample data"""
    print("🚀 Initializing sample data...")
    
    with app.app_context():
        # Create tables
        db.create_all()
        print("✅ Database tables created")
        
        # Create sample data
        users = create_sample_users()
        challenges = create_sample_challenges()
        teams = create_sample_teams()
        hints = create_sample_hints(challenges)
        
        # Commit all changes
        try:
            db.session.commit()
            print("✅ Sample data committed to database")
            
            print(f"\n📊 Summary:")
            print(f"   Users: {len(users)}")
            print(f"   Challenges: {len(challenges)}")
            print(f"   Teams: {len(teams)}")
            print(f"   Hints: {len(hints)}")
            
            print(f"\n🔑 Login credentials:")
            print(f"   Admin: admin / admin123")
            print(f"   User: alice / password123")
            print(f"   User: bob / password123")
            print(f"   User: charlie / password123")
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error committing sample data: {e}")
            raise

if __name__ == '__main__':
    initialize_sample_data()
