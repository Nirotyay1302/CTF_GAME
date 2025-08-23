#!/usr/bin/env python3
"""
Professional database setup and migration script for CTF application
"""

import os
import sys
from datetime import datetime
from sqlalchemy import text, Index
from flask_migrate import init, migrate, upgrade

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from CTF_GAME import app, db
from models import *

def create_database_indexes():
    """Create optimized database indexes for better performance"""
    print("Creating database indexes...")

    with app.app_context():
        try:
            # Get database type
            database_url = app.config['SQLALCHEMY_DATABASE_URI']

            # Define indexes based on database type
            if 'mysql' in database_url:
                # MySQL doesn't support IF NOT EXISTS for indexes
                indexes = [
                    'CREATE INDEX idx_user_username ON user(username)',
                    'CREATE INDEX idx_user_email ON user(email)',
                    'CREATE INDEX idx_user_score ON user(score DESC)',
                    'CREATE INDEX idx_user_role ON user(role)',
                    'CREATE INDEX idx_challenge_category ON challenge(category)',
                    'CREATE INDEX idx_challenge_difficulty ON challenge(difficulty)',
                    'CREATE INDEX idx_challenge_points ON challenge(points)',
                    'CREATE INDEX idx_challenge_created_at ON challenge(created_at)',
                    'CREATE INDEX idx_solve_user_id ON solve(user_id)',
                    'CREATE INDEX idx_solve_challenge_id ON solve(challenge_id)',
                    'CREATE INDEX idx_solve_timestamp ON solve(timestamp DESC)',
                    'CREATE INDEX idx_solve_user_challenge ON solve(user_id, challenge_id)',
                    'CREATE INDEX idx_submission_user_id ON submission(user_id)',
                    'CREATE INDEX idx_submission_challenge_id ON submission(challenge_id)',
                    'CREATE INDEX idx_submission_timestamp ON submission(timestamp DESC)',
                    'CREATE INDEX idx_submission_correct ON submission(correct)',
                    'CREATE INDEX idx_team_name ON team(name)',
                    'CREATE INDEX idx_team_code ON team(team_code)',
                    'CREATE INDEX idx_team_membership_user_id ON team_membership(user_id)',
                    'CREATE INDEX idx_team_membership_team_id ON team_membership(team_id)',
                    'CREATE INDEX idx_notification_user_id ON notification(user_id)',
                    'CREATE INDEX idx_notification_read ON notification(read)',
                    'CREATE INDEX idx_notification_created_at ON notification(created_at DESC)',
                    'CREATE INDEX idx_chat_message_channel_id ON chat_message(channel_id)',
                    'CREATE INDEX idx_chat_message_user_id ON chat_message(user_id)',
                    'CREATE INDEX idx_chat_message_timestamp ON chat_message(timestamp DESC)'
                ]
            else:
                # PostgreSQL and SQLite support IF NOT EXISTS
                indexes = [
                    'CREATE INDEX IF NOT EXISTS idx_user_username ON user(username)',
                    'CREATE INDEX IF NOT EXISTS idx_user_email ON user(email)',
                    'CREATE INDEX IF NOT EXISTS idx_user_score ON user(score DESC)',
                    'CREATE INDEX IF NOT EXISTS idx_user_role ON user(role)',
                    'CREATE INDEX IF NOT EXISTS idx_challenge_category ON challenge(category)',
                    'CREATE INDEX IF NOT EXISTS idx_challenge_difficulty ON challenge(difficulty)',
                    'CREATE INDEX IF NOT EXISTS idx_challenge_points ON challenge(points)',
                    'CREATE INDEX IF NOT EXISTS idx_challenge_created_at ON challenge(created_at)',
                    'CREATE INDEX IF NOT EXISTS idx_solve_user_id ON solve(user_id)',
                    'CREATE INDEX IF NOT EXISTS idx_solve_challenge_id ON solve(challenge_id)',
                    'CREATE INDEX IF NOT EXISTS idx_solve_timestamp ON solve(timestamp DESC)',
                    'CREATE INDEX IF NOT EXISTS idx_solve_user_challenge ON solve(user_id, challenge_id)',
                    'CREATE INDEX IF NOT EXISTS idx_submission_user_id ON submission(user_id)',
                    'CREATE INDEX IF NOT EXISTS idx_submission_challenge_id ON submission(challenge_id)',
                    'CREATE INDEX IF NOT EXISTS idx_submission_timestamp ON submission(timestamp DESC)',
                    'CREATE INDEX IF NOT EXISTS idx_submission_correct ON submission(correct)',
                    'CREATE INDEX IF NOT EXISTS idx_team_name ON team(name)',
                    'CREATE INDEX IF NOT EXISTS idx_team_code ON team(team_code)',
                    'CREATE INDEX IF NOT EXISTS idx_team_membership_user_id ON team_membership(user_id)',
                    'CREATE INDEX IF NOT EXISTS idx_team_membership_team_id ON team_membership(team_id)',
                    'CREATE INDEX IF NOT EXISTS idx_notification_user_id ON notification(user_id)',
                    'CREATE INDEX IF NOT EXISTS idx_notification_read ON notification(read)',
                    'CREATE INDEX IF NOT EXISTS idx_notification_created_at ON notification(created_at DESC)',
                    'CREATE INDEX IF NOT EXISTS idx_chat_message_channel_id ON chat_message(channel_id)',
                    'CREATE INDEX IF NOT EXISTS idx_chat_message_user_id ON chat_message(user_id)',
                    'CREATE INDEX IF NOT EXISTS idx_chat_message_timestamp ON chat_message(timestamp DESC)'
                ]

            # Execute index creation
            created_count = 0
            for index_sql in indexes:
                try:
                    db.session.execute(text(index_sql))
                    created_count += 1
                except Exception as e:
                    # Index might already exist, which is fine
                    if 'already exists' in str(e).lower() or 'duplicate' in str(e).lower():
                        created_count += 1
                    else:
                        print(f"⚠️ Warning creating index: {e}")

            db.session.commit()
            print(f"✅ Database indexes processed ({created_count}/{len(indexes)} successful)")
            return True

        except Exception as e:
            print(f"❌ Error creating indexes: {e}")
            db.session.rollback()
            return False

def optimize_database_settings():
    """Optimize database settings for performance"""
    print("Optimizing database settings...")
    
    with app.app_context():
        try:
            # Get database type
            database_url = app.config['SQLALCHEMY_DATABASE_URI']
            
            if 'mysql' in database_url:
                # MySQL optimizations
                db.session.execute(text('SET SESSION sql_mode = "STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO"'))
                db.session.execute(text('SET SESSION innodb_lock_wait_timeout = 50'))
                
            elif 'postgresql' in database_url:
                # PostgreSQL optimizations
                db.session.execute(text('SET statement_timeout = 30000'))  # 30 seconds
                db.session.execute(text('SET lock_timeout = 10000'))       # 10 seconds
                
            db.session.commit()
            print("✅ Database settings optimized")
            return True
            
        except Exception as e:
            print(f"⚠️ Database optimization warning: {e}")
            return False

def create_admin_user():
    """Create default admin user if none exists"""
    print("Checking for admin user...")
    
    with app.app_context():
        try:
            admin = User.query.filter_by(role='admin').first()
            if not admin:
                from werkzeug.security import generate_password_hash
                
                admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
                admin_email = os.environ.get('ADMIN_EMAIL', 'admin@ctf.local')
                admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
                
                admin = User(
                    username=admin_username,
                    email=admin_email,
                    password_hash=generate_password_hash(admin_password),
                    role='admin'
                )
                
                db.session.add(admin)
                db.session.commit()
                
                print(f"✅ Admin user created: {admin_username}")
                print(f"   Email: {admin_email}")
                print(f"   Password: {admin_password}")
                print("   ⚠️ CHANGE THE DEFAULT PASSWORD IMMEDIATELY!")
                return True
            else:
                print(f"✅ Admin user already exists: {admin.username}")
                return True
                
        except Exception as e:
            print(f"❌ Error creating admin user: {e}")
            db.session.rollback()
            return False

def cleanup_database():
    """Clean up old and unnecessary data"""
    print("Cleaning up database...")
    
    with app.app_context():
        try:
            # Clean old submissions (keep only last 1000 per user)
            db.session.execute(text('''
                DELETE FROM submission 
                WHERE id NOT IN (
                    SELECT id FROM (
                        SELECT id FROM submission 
                        ORDER BY user_id, timestamp DESC 
                        LIMIT 1000
                    ) AS keep_submissions
                )
            '''))
            
            # Clean old notifications (keep only last 100 per user)
            db.session.execute(text('''
                DELETE FROM notification 
                WHERE id NOT IN (
                    SELECT id FROM (
                        SELECT id FROM notification 
                        ORDER BY user_id, created_at DESC 
                        LIMIT 100
                    ) AS keep_notifications
                )
            '''))
            
            db.session.commit()
            print("✅ Database cleanup completed")
            return True
            
        except Exception as e:
            print(f"⚠️ Database cleanup warning: {e}")
            db.session.rollback()
            return False

def verify_database_integrity():
    """Verify database integrity and relationships"""
    print("Verifying database integrity...")
    
    with app.app_context():
        try:
            # Check for orphaned records
            orphaned_solves = db.session.execute(text('''
                SELECT COUNT(*) FROM solve s 
                LEFT JOIN user u ON s.user_id = u.id 
                LEFT JOIN challenge c ON s.challenge_id = c.id 
                WHERE u.id IS NULL OR c.id IS NULL
            ''')).scalar()
            
            orphaned_submissions = db.session.execute(text('''
                SELECT COUNT(*) FROM submission s 
                LEFT JOIN user u ON s.user_id = u.id 
                LEFT JOIN challenge c ON s.challenge_id = c.id 
                WHERE u.id IS NULL OR c.id IS NULL
            ''')).scalar()
            
            if orphaned_solves > 0:
                print(f"⚠️ Found {orphaned_solves} orphaned solve records")
            
            if orphaned_submissions > 0:
                print(f"⚠️ Found {orphaned_submissions} orphaned submission records")
            
            if orphaned_solves == 0 and orphaned_submissions == 0:
                print("✅ Database integrity verified")
            
            return True
            
        except Exception as e:
            print(f"❌ Error verifying database integrity: {e}")
            return False

def main():
    """Main database setup function"""
    print("🗄️ CTF Database Setup & Optimization")
    print("=" * 50)
    
    with app.app_context():
        # Create all tables
        print("Creating database tables...")
        try:
            db.create_all()
            print("✅ Database tables created/verified")
        except Exception as e:
            print(f"❌ Error creating tables: {e}")
            return False
        
        # Run all setup tasks
        tasks = [
            ("Database Indexes", create_database_indexes),
            ("Database Settings", optimize_database_settings),
            ("Admin User", create_admin_user),
            ("Database Cleanup", cleanup_database),
            ("Integrity Check", verify_database_integrity)
        ]
        
        success_count = 0
        for task_name, task_func in tasks:
            print(f"\n🔄 {task_name}...")
            if task_func():
                success_count += 1
        
        print(f"\n🎉 Database setup completed!")
        print(f"✅ {success_count}/{len(tasks)} tasks successful")
        
        if success_count == len(tasks):
            print("🚀 Database is ready for production!")
        else:
            print("⚠️ Some tasks had warnings - check logs above")
        
        return success_count == len(tasks)

if __name__ == "__main__":
    main()
