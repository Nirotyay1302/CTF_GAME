#!/usr/bin/env python3
"""
Initialize the CTF database with sample challenges
"""

import os
import sys
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import secrets
import hashlib

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from CTF_GAME import app, db
from models import Challenge, User
from config import Config

# Use the same encryption key setup as the main app
FERNET_KEY = os.getenv('FERNET_KEY')
if not FERNET_KEY:
    # Use persistent local key file for dev; avoids committing secrets
    instance_path = os.path.join(os.path.dirname(__file__), 'instance')
    os.makedirs(instance_path, exist_ok=True)
    key_path = os.path.join(instance_path, 'fernet.key')
    if os.path.exists(key_path):
        with open(key_path, 'rb') as fh:
            FERNET_KEY = fh.read().strip()
    else:
        generated = Fernet.generate_key()
        with open(key_path, 'wb') as fh:
            fh.write(generated)
        FERNET_KEY = generated
fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)

def create_sample_challenges():
    """Create sample challenges for the CTF game"""
    
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
            'difficulty': 'medium'
        },
        {
            'title': 'SQL Injection Basics',
            'description': 'Find the flag in this vulnerable login form. Try some basic SQL injection techniques. The flag is hidden in the users table. Hint: Try \' OR 1=1 --',
            'flag': 'flag{sql_injection_works}',
            'points': 30,
            'category': 'web',
            'difficulty': 'medium'
        },
        {
            'title': 'Reverse Engineering',
            'description': 'This program checks if your input is correct. Can you figure out what the correct input should be? The flag format is flag{correct_input}. Hint: The program expects "reverse_me" as input.',
            'flag': 'flag{reverse_me}',
            'points': 35,
            'category': 'reverse',
            'difficulty': 'medium'
        },
        {
            'title': 'Network Analysis',
            'description': 'Analyze this network traffic capture. The flag is transmitted in plain text. Look for HTTP traffic containing the flag.',
            'flag': 'flag{network_forensics}',
            'points': 40,
            'category': 'forensics',
            'difficulty': 'hard'
        },
        {
            'title': 'Buffer Overflow',
            'description': 'This program has a buffer overflow vulnerability. Can you exploit it to get the flag? The flag is stored in memory at address 0x08048000.',
            'flag': 'flag{buffer_overflow_pwned}',
            'points': 50,
            'category': 'pwn',
            'difficulty': 'hard'
        },
        {
            'title': 'Advanced Cryptography',
            'description': 'This message was encrypted using AES-256. The key is hidden in the challenge description. Can you find it? Key hint: The key is the MD5 hash of "ctf_challenge_2024".',
            'flag': 'flag{advanced_crypto_master}',
            'points': 60,
            'category': 'crypto',
            'difficulty': 'hard'
        }
    ]
    
    print("Creating sample challenges...")
    
    for challenge_data in sample_challenges:
        # Check if challenge already exists
        existing = Challenge.query.filter_by(title=challenge_data['title']).first()
        if existing:
            print(f"Challenge '{challenge_data['title']}' already exists, skipping...")
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
        print(f"Added challenge: {challenge_data['title']} ({challenge_data['points']} points)")
    
    try:
        db.session.commit()
        print(f"\n✅ Successfully created {len(sample_challenges)} challenges!")
        print("\nChallenge Summary:")
        print("-" * 50)
        
        # Display summary
        challenges = Challenge.query.all()
        categories = {}
        difficulties = {}
        total_points = 0
        
        for challenge in challenges:
            categories[challenge.category] = categories.get(challenge.category, 0) + 1
            difficulties[challenge.difficulty] = difficulties.get(challenge.difficulty, 0) + 1
            total_points += challenge.points
        
        print(f"Total Challenges: {len(challenges)}")
        print(f"Total Points Available: {total_points}")
        print(f"Categories: {dict(categories)}")
        print(f"Difficulties: {dict(difficulties)}")
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error creating challenges: {e}")
        return False
    
    return True

def main():
    """Main function to initialize challenges"""
    print("🎯 CTF Challenge Initializer")
    print("=" * 40)
    
    with app.app_context():
        # Check if database tables exist
        try:
            db.create_all()
            print("✅ Database tables verified/created")
        except Exception as e:
            print(f"❌ Error with database: {e}")
            return
        
        # Check if any challenges already exist
        existing_count = Challenge.query.count()
        if existing_count > 0:
            print(f"⚠️  Found {existing_count} existing challenges")
            response = input("Do you want to add more challenges? (y/n): ").lower()
            if response != 'y':
                print("Exiting...")
                return
        
        # Create sample challenges
        success = create_sample_challenges()
        
        if success:
            print("\n🎉 Challenge initialization complete!")
            print("You can now log into your CTF game and see the challenges.")
        else:
            print("\n❌ Challenge initialization failed!")

if __name__ == "__main__":
    main()
