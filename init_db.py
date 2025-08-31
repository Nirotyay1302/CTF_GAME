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
from models import User, Challenge, Solve
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
                email='admin@ctf.local',
                password_hash=generate_password_hash('admin123'),
                role='admin',
                created_at=datetime.utcnow()
            )
            db.session.add(admin)
            
            # Create a test user
            print("👤 Creating test user...")
            test_user = User(
                username='testuser',
                email='test@example.com',
                password_hash=generate_password_hash('password123'),
                role='user',
                created_at=datetime.utcnow()
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
                    'flag': 'CTF{welcome_to_hunting_ctf}'
                },
                {
                    'title': 'Basic Web Challenge',
                    'description': 'Find the flag hidden in the HTML source code.',
                    'category': 'web',
                    'difficulty': 'easy',
                    'points': 100,
                    'flag': 'CTF{view_source_rocks}'
                },
                {
                    'title': 'Simple Crypto',
                    'description': 'Decode this ROT13: PGS{pelcgb_vf_sha}',
                    'category': 'crypto',
                    'difficulty': 'easy',
                    'points': 150,
                    'flag': 'CTF{crypto_is_fun}'
                },
                {
                    'title': 'SQL Injection',
                    'description': 'Find the flag using SQL injection techniques.',
                    'category': 'web',
                    'difficulty': 'medium',
                    'points': 200,
                    'flag': 'CTF{sql_injection_master}'
                },
                {
                    'title': 'Binary Analysis',
                    'description': 'Reverse engineer this binary to find the flag.',
                    'category': 'reverse',
                    'difficulty': 'hard',
                    'points': 300,
                    'flag': 'CTF{reverse_engineering_pro}'
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
                    created_at=datetime.utcnow()
                )
                db.session.add(challenge)
            
            # Commit all changes
            db.session.commit()
            print("✅ Sample data created successfully!")
            
            # Print summary
            total_users = User.query.count()
            total_challenges = Challenge.query.count()
            
            print(f"\n🎉 Database initialization completed!")
            print(f"📊 Summary:")
            print(f"   👥 Users: {total_users}")
            print(f"   🧩 Challenges: {total_challenges}")
            print(f"\n🔑 Login Credentials:")
            print(f"   Admin: admin / admin123")
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
