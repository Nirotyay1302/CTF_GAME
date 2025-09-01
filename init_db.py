#!/usr/bin/env python3
"""
Initialize the database for HUNTING-CTF
Creates all tables and adds sample data
"""

import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app, db
from models import User, Challenge, Solve, Hint
from werkzeug.security import generate_password_hash
from datetime import datetime

def init_database():
    """Initialize the database with tables and sample data"""
    print("🔧 Initializing HUNTING-CTF database...")
    
    with app.app_context():
        try:
            # Drop all tables first (clean slate)
            print("🗑️ Dropping existing tables...")
            db.drop_all()

            # Create all tables with new schema
            print("🏗️ Creating database tables with enhanced schema...")
            db.create_all()
            print("✅ Database tables created successfully with hint and answer features!")
            
            # Create admin user
            print("👤 Creating admin user...")
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                role='admin',
                is_player=False,  # Admin is not a player
                is_active=True,
                score=0,
                created_at=datetime.utcnow(),
                last_login=datetime.utcnow()
            )
            db.session.add(admin)
            
            # Create regular users
            print("👤 Creating regular users...")
            user1 = User(
                username='player1',
                email='player1@example.com',
                password_hash=generate_password_hash('securepass1'),
                role='user',
                is_player=True,  # Regular users are players
                is_active=True,
                score=0,
                created_at=datetime.utcnow(),
                last_login=datetime.utcnow()
            )
            db.session.add(user1)
            
            user2 = User(
                username='player2',
                email='player2@example.com',
                password_hash=generate_password_hash('securepass2'),
                role='user',
                is_player=True,  # Regular users are players
                is_active=True,
                score=0,
                created_at=datetime.utcnow(),
                last_login=datetime.utcnow()
            )
            db.session.add(user2)
            
            # Add test user mentioned in the summary
            test_user = User(
                username='testuser',
                email='testuser@example.com',
                password_hash=generate_password_hash('password123'),
                role='user',
                is_player=True,
                is_active=True,
                score=0,
                created_at=datetime.utcnow(),
                last_login=datetime.utcnow()
            )
            db.session.add(test_user)
            
            # Create sample challenges
            print("🧩 Creating sample challenges...")
            
            challenges = [
                {
                    'title': 'Welcome Challenge',
                    'description': 'Welcome to HUNTING-CTF! The flag is: CTF{welcome_to_hunting_ctf}',
                    'category': 'misc',
                    'difficulty': 'easy',
                    'points': 50,
                    'flag': 'CTF{welcome_to_hunting_ctf}',
                    'answer_explanation': 'This is a welcome challenge to get you started. The flag is provided in the description.',
                    'solution_steps': 'Simply copy the flag from the description and submit it.'
                },
                {
                    'title': 'Basic Web Challenge',
                    'description': 'Find the flag hidden in the HTML source code.',
                    'category': 'web',
                    'difficulty': 'easy',
                    'points': 100,
                    'flag': 'CTF{view_source_rocks}',
                    'answer_explanation': 'Web developers often leave comments in HTML source code that contain sensitive information.',
                    'solution_steps': 'Right-click on the page and select "View Page Source" to examine the HTML code.'
                },
                {
                    'title': 'Simple Crypto',
                    'description': 'Decode this ROT13: PGS{pelcgb_vf_sha}',
                    'category': 'crypto',
                    'difficulty': 'easy',
                    'points': 150,
                    'flag': 'CTF{crypto_is_fun}',
                    'answer_explanation': 'ROT13 is a simple letter substitution cipher that replaces a letter with the 13th letter after it in the alphabet.',
                    'solution_steps': 'Use an online ROT13 decoder or manually shift each letter 13 positions.'
                },
                {
                    'title': 'SQL Injection',
                    'description': 'Find the flag using SQL injection techniques.',
                    'category': 'web',
                    'difficulty': 'medium',
                    'points': 200,
                    'flag': 'CTF{sql_injection_master}',
                    'answer_explanation': 'SQL injection is a code injection technique used to attack data-driven applications.',
                    'solution_steps': 'Try common SQL injection payloads like \'OR 1=1--\' in the login form.'
                },
                {
                    'title': 'Binary Analysis',
                    'description': 'Reverse engineer this binary to find the flag.',
                    'category': 'reverse',
                    'difficulty': 'hard',
                    'points': 300,
                    'flag': 'CTF{reverse_engineering_pro}',
                    'answer_explanation': 'Reverse engineering involves analyzing a binary file to understand its functionality.',
                    'solution_steps': 'Use tools like Ghidra or IDA Pro to disassemble the binary and analyze the code.'
                },
                {
                    'title': 'Network Packet Analysis',
                    'description': 'Analyze the provided PCAP file to find the hidden flag.',
                    'category': 'forensics',
                    'difficulty': 'medium',
                    'points': 250,
                    'flag': 'CTF{packet_analysis_expert}',
                    'answer_explanation': 'Network packets can contain hidden information in various protocols.',
                    'solution_steps': 'Use Wireshark to analyze the PCAP file, focusing on HTTP traffic and looking for unusual patterns.'
                },
                {
                    'title': 'Steganography Challenge',
                    'description': 'Find the hidden message in the provided image.',
                    'category': 'stego',
                    'difficulty': 'medium',
                    'points': 200,
                    'flag': 'CTF{hidden_in_plain_sight}',
                    'answer_explanation': 'Steganography is the practice of concealing messages within other non-secret data or a physical object.',
                    'solution_steps': 'Use tools like steghide, zsteg, or exiftool to analyze the image and extract hidden data.'
                },
                {
                    'title': 'Command Injection',
                    'description': 'Exploit the command injection vulnerability to find the flag.',
                    'category': 'web',
                    'difficulty': 'hard',
                    'points': 350,
                    'flag': 'CTF{command_injection_vulnerability}',
                    'answer_explanation': 'Command injection is a security vulnerability that allows an attacker to execute arbitrary commands on the host operating system.',
                    'solution_steps': 'Try injecting commands using characters like ; | & to execute additional commands.'
                },
                {
                    'title': 'XSS Challenge',
                    'description': 'Exploit the Cross-Site Scripting vulnerability to steal the admin\'s cookie.',
                    'category': 'web',
                    'difficulty': 'medium',
                    'points': 250,
                    'flag': 'CTF{xss_vulnerability_exploited}',
                    'answer_explanation': 'Cross-Site Scripting (XSS) allows attackers to inject client-side scripts into web pages viewed by other users.',
                    'solution_steps': 'Inject JavaScript code that sends the document.cookie to your server.'
                },
                {
                    'title': 'Buffer Overflow',
                    'description': 'Exploit the buffer overflow vulnerability to get the flag.',
                    'category': 'pwn',
                    'difficulty': 'hard',
                    'points': 400,
                    'flag': 'CTF{buffer_overflow_mastered}',
                    'answer_explanation': 'Buffer overflow occurs when a program writes more data to a buffer than it can hold.',
                    'solution_steps': 'Create a payload that overflows the buffer and overwrites the return address to gain control of the program flow.'
                }
            ]
            
            for challenge_data in challenges:
                # For simplicity, store flag as plain text in local development
                # In production, you'd encrypt it
                challenge = Challenge(
                    title=challenge_data['title'],
                    description=challenge_data['description'],
                    category=challenge_data['category'],
                    difficulty=challenge_data['difficulty'],
                    points=challenge_data['points'],
                    flag_encrypted=challenge_data['flag'].encode(),  # Simple encoding for local dev
                    answer_explanation=challenge_data.get('answer_explanation', ''),
                    solution_steps=challenge_data.get('solution_steps', ''),
                    created_at=datetime.utcnow()
                )
                db.session.add(challenge)
                
                # Add hints for each challenge
                if challenge_data['difficulty'] == 'easy':
                    # Add one hint for easy challenges
                    hint = Hint(
                        challenge=challenge,
                        content=f"Hint for {challenge_data['title']}: Look carefully at the challenge description.",
                        cost=5,
                        display_order=1
                    )
                    db.session.add(hint)
                elif challenge_data['difficulty'] == 'medium':
                    # Add two hints for medium challenges
                    hint1 = Hint(
                        challenge=challenge,
                        content=f"First hint for {challenge_data['title']}: Think about the category of this challenge.",
                        cost=10,
                        display_order=1
                    )
                    db.session.add(hint1)
                    
                    hint2 = Hint(
                        challenge=challenge,
                        content=f"Second hint for {challenge_data['title']}: Try using common tools for this category.",
                        cost=15,
                        display_order=2
                    )
                    db.session.add(hint2)
                elif challenge_data['difficulty'] == 'hard':
                    # Add three hints for hard challenges
                    hint1 = Hint(
                        challenge=challenge,
                        content=f"First hint for {challenge_data['title']}: Start by analyzing the problem carefully.",
                        cost=15,
                        display_order=1
                    )
                    db.session.add(hint1)
                    
                    hint2 = Hint(
                        challenge=challenge,
                        content=f"Second hint for {challenge_data['title']}: Consider using specialized tools for this type of challenge.",
                        cost=20,
                        display_order=2
                    )
                    db.session.add(hint2)
                    
                    hint3 = Hint(
                        challenge=challenge,
                        content=f"Final hint for {challenge_data['title']}: The key to solving this challenge is to focus on {challenge_data['category']} techniques.",
                        cost=25,
                        display_order=3
                    )
                    db.session.add(hint3)
            
            # Commit all changes
            db.session.commit()
            print("✅ Sample data created successfully!")
            
            # Print summary
            total_users = User.query.count()
            total_challenges = Challenge.query.count()
            total_hints = Hint.query.count()
            
            print(f"\n🎉 Database initialization completed!")
            print(f"📊 Summary:")
            print(f"   👥 Users: {total_users}")
            print(f"   🧩 Challenges: {total_challenges}")
            print(f"   💡 Hints: {total_hints}")
            print(f"\n🔑 Login Credentials:")
            print(f"   Admin: admin / admin123")
            print(f"   Player 1: player1 / securepass1")
            print(f"   Player 2: player2 / securepass2")
            print(f"   Test User: testuser / password123")
            print(f"\n🌐 Access your CTF at: http://localhost:5000")
            
        except Exception as e:
            print(f"❌ Error initializing database: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    return True

if __name__ == '__main__':
    success = init_database()
    if success:
        print("\n✅ Ready to run your CTF application!")
        print("Run: python app.py")
    else:
        print("\n❌ Database initialization failed!")
        sys.exit(1)
