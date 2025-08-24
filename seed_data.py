#!/usr/bin/env python3
"""
Seed data for HUNTING-CTF
Creates sample challenges and users for testing
"""

import os
import sys
from datetime import datetime

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app, db, encrypt_flag
from models import User, Challenge, Solve
from werkzeug.security import generate_password_hash

def create_sample_challenges():
    """Create sample challenges for the CTF"""
    
    challenges = [
        {
            'title': 'Welcome to CTF',
            'description': 'Find the flag hidden in this simple challenge. The flag is: CTF{welcome_to_hunting_ctf}',
            'category': 'misc',
            'difficulty': 'easy',
            'points': 50,
            'flag': 'CTF{welcome_to_hunting_ctf}',
            'active': True
        },
        {
            'title': 'Basic Cryptography',
            'description': 'Decode this ROT13 cipher: PGS{pelcgb_vf_sha}',
            'category': 'crypto',
            'difficulty': 'easy',
            'points': 100,
            'flag': 'CTF{crypto_is_fun}',
            'active': True
        },
        {
            'title': 'Web Security 101',
            'description': 'Find the hidden flag in the HTML source code of this webpage.',
            'category': 'web',
            'difficulty': 'easy',
            'points': 150,
            'flag': 'CTF{view_source_is_useful}',
            'active': True
        },
        {
            'title': 'SQL Injection Basics',
            'description': 'Exploit this vulnerable login form to find the flag.',
            'category': 'web',
            'difficulty': 'medium',
            'points': 200,
            'flag': 'CTF{sql_injection_master}',
            'active': True
        },
        {
            'title': 'Binary Analysis',
            'description': 'Reverse engineer this binary to find the hidden flag.',
            'category': 'reverse',
            'difficulty': 'medium',
            'points': 250,
            'flag': 'CTF{reverse_engineering_rocks}',
            'active': True
        },
        {
            'title': 'Network Forensics',
            'description': 'Analyze this network capture to find the transmitted flag.',
            'category': 'forensics',
            'difficulty': 'medium',
            'points': 300,
            'flag': 'CTF{packet_analysis_expert}',
            'active': True
        },
        {
            'title': 'Advanced Cryptography',
            'description': 'Break this custom encryption algorithm to recover the flag.',
            'category': 'crypto',
            'difficulty': 'hard',
            'points': 400,
            'flag': 'CTF{advanced_crypto_solved}',
            'active': True
        },
        {
            'title': 'Buffer Overflow',
            'description': 'Exploit this buffer overflow vulnerability to get the flag.',
            'category': 'pwn',
            'difficulty': 'hard',
            'points': 450,
            'flag': 'CTF{buffer_overflow_pwned}',
            'active': True
        },
        {
            'title': 'Steganography Challenge',
            'description': 'Find the flag hidden in this image using steganography techniques.',
            'category': 'forensics',
            'difficulty': 'medium',
            'points': 200,
            'flag': 'CTF{hidden_in_plain_sight}',
            'active': True
        },
        {
            'title': 'Expert Level Pwn',
            'description': 'This is the ultimate pwn challenge. Good luck!',
            'category': 'pwn',
            'difficulty': 'expert',
            'points': 500,
            'flag': 'CTF{ultimate_pwn_master}',
            'active': True
        }
    ]
    
    created_count = 0
    for challenge_data in challenges:
        # Check if challenge already exists
        existing = Challenge.query.filter_by(title=challenge_data['title']).first()
        if existing:
            print(f"Challenge '{challenge_data['title']}' already exists, skipping...")
            continue
        
        # Encrypt the flag
        encrypted_flag = encrypt_flag(challenge_data['flag'])
        
        # Create challenge
        challenge = Challenge(
            title=challenge_data['title'],
            description=challenge_data['description'],
            category=challenge_data['category'],
            difficulty=challenge_data['difficulty'],
            points=challenge_data['points'],
            flag_encrypted=encrypted_flag,
            active=challenge_data['active'],
            created_at=datetime.utcnow()
        )
        
        db.session.add(challenge)
        created_count += 1
        print(f"Created challenge: {challenge_data['title']}")
    
    if created_count > 0:
        db.session.commit()
        print(f"✅ Created {created_count} new challenges")
    else:
        print("✅ All challenges already exist")

def create_sample_users():
    """Create sample users for testing"""
    
    users = [
        {
            'username': 'admin',
            'email': 'admin@ctf.local',
            'password': 'admin123',
            'role': 'admin'
        },
        {
            'username': 'alice',
            'email': 'alice@example.com',
            'password': 'password123',
            'role': 'user'
        },
        {
            'username': 'bob',
            'email': 'bob@example.com',
            'password': 'password123',
            'role': 'user'
        },
        {
            'username': 'charlie',
            'email': 'charlie@example.com',
            'password': 'password123',
            'role': 'user'
        }
    ]
    
    created_count = 0
    for user_data in users:
        # Check if user already exists
        existing = User.query.filter_by(username=user_data['username']).first()
        if existing:
            print(f"User '{user_data['username']}' already exists, skipping...")
            continue
        
        # Create user
        user = User(
            username=user_data['username'],
            email=user_data['email'],
            password_hash=generate_password_hash(user_data['password']),
            role=user_data['role'],
            created_at=datetime.utcnow()
        )
        
        db.session.add(user)
        created_count += 1
        print(f"Created user: {user_data['username']}")
    
    if created_count > 0:
        db.session.commit()
        print(f"✅ Created {created_count} new users")
    else:
        print("✅ All users already exist")

def create_sample_solves():
    """Create some sample solves for demonstration"""
    
    # Get users and challenges
    alice = User.query.filter_by(username='alice').first()
    bob = User.query.filter_by(username='bob').first()
    
    if not alice or not bob:
        print("Sample users not found, skipping solve creation")
        return
    
    # Get some easy challenges
    easy_challenges = Challenge.query.filter_by(difficulty='easy').limit(3).all()
    
    created_count = 0
    for i, challenge in enumerate(easy_challenges):
        # Alice solves all easy challenges
        if not Solve.query.filter_by(user_id=alice.id, challenge_id=challenge.id).first():
            solve = Solve(
                user_id=alice.id,
                challenge_id=challenge.id,
                solved_at=datetime.utcnow()
            )
            db.session.add(solve)
            created_count += 1
            print(f"Alice solved: {challenge.title}")
        
        # Bob solves first two easy challenges
        if i < 2 and not Solve.query.filter_by(user_id=bob.id, challenge_id=challenge.id).first():
            solve = Solve(
                user_id=bob.id,
                challenge_id=challenge.id,
                solved_at=datetime.utcnow()
            )
            db.session.add(solve)
            created_count += 1
            print(f"Bob solved: {challenge.title}")
    
    if created_count > 0:
        db.session.commit()
        print(f"✅ Created {created_count} sample solves")
    else:
        print("✅ Sample solves already exist")

def main():
    """Main function to seed the database"""
    print("🌱 Seeding HUNTING-CTF database...")
    
    with app.app_context():
        # Create all tables
        db.create_all()
        print("✅ Database tables created/verified")
        
        # Create sample data
        create_sample_users()
        create_sample_challenges()
        create_sample_solves()
        
        print("🎉 Database seeding completed!")
        
        # Print summary
        total_users = User.query.count()
        total_challenges = Challenge.query.count()
        total_solves = Solve.query.count()
        
        print(f"\n📊 Database Summary:")
        print(f"   Users: {total_users}")
        print(f"   Challenges: {total_challenges}")
        print(f"   Solves: {total_solves}")
        
        print(f"\n🔑 Login Credentials:")
        print(f"   Admin: admin / admin123")
        print(f"   User: alice / password123")
        print(f"   User: bob / password123")

if __name__ == '__main__':
    main()
