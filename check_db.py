#!/usr/bin/env python3

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app, db
from models import Challenge, Hint

def check_database():
    with app.app_context():
        challenge_count = Challenge.query.count()
        hint_count = Hint.query.count()
        
        print(f"Total challenges: {challenge_count}")
        print(f"Total hints: {hint_count}")
        
        # Get challenge categories
        categories = db.session.query(Challenge.category).distinct().all()
        print(f"\nChallenge categories: {[cat[0] for cat in categories]}")
        
        # Get challenge difficulties
        difficulties = db.session.query(Challenge.difficulty).distinct().all()
        print(f"Challenge difficulties: {[diff[0] for diff in difficulties]}")

if __name__ == '__main__':
    check_database()