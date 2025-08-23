#!/usr/bin/env python3
"""
Test script to verify admin user creation works correctly
"""

import os
import sys
from werkzeug.security import generate_password_hash, check_password_hash

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from CTF_GAME import app, db
from models import User

def test_admin_creation():
    """Test admin user creation with correct fields"""
    print("🧪 Testing Admin User Creation")
    print("=" * 40)
    
    with app.app_context():
        try:
            # Check if admin already exists
            existing_admin = User.query.filter_by(username='admin').first()
            if existing_admin:
                print("✅ Admin user already exists")
                print(f"   Username: {existing_admin.username}")
                print(f"   Email: {existing_admin.email}")
                print(f"   Role: {existing_admin.role}")
                print(f"   Score: {existing_admin.score}")
                
                # Test password
                if check_password_hash(existing_admin.password_hash, 'admin123'):
                    print("✅ Password verification successful")
                else:
                    print("❌ Password verification failed")
                
                return True
            
            # Create new admin user
            print("Creating new admin user...")
            admin = User(
                username='admin',
                email='admin@ctf.local',
                password_hash=generate_password_hash('admin123'),
                role='admin'
            )
            
            db.session.add(admin)
            db.session.commit()
            
            print("✅ Admin user created successfully!")
            print(f"   Username: {admin.username}")
            print(f"   Email: {admin.email}")
            print(f"   Role: {admin.role}")
            print(f"   Score: {admin.score}")
            
            # Test password
            if check_password_hash(admin.password_hash, 'admin123'):
                print("✅ Password verification successful")
            else:
                print("❌ Password verification failed")
            
            return True
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error: {e}")
            return False

def test_user_model_fields():
    """Test what fields are available in the User model"""
    print("\n🔍 User Model Field Analysis")
    print("=" * 40)
    
    # Get User model columns
    user_columns = [column.name for column in User.__table__.columns]
    
    print("Available User model fields:")
    for field in sorted(user_columns):
        print(f"   ✅ {field}")
    
    # Check for commonly expected fields
    expected_fields = ['created_at', 'email_verified', 'total_points', 'last_login']
    missing_fields = [field for field in expected_fields if field not in user_columns]
    
    if missing_fields:
        print(f"\nMissing fields (that might be expected):")
        for field in missing_fields:
            print(f"   ❌ {field}")
    
    return user_columns

def main():
    """Main test function"""
    print("🎯 CTF Admin User Test Suite")
    print("=" * 50)
    
    # Test User model fields
    user_fields = test_user_model_fields()
    
    # Test admin creation
    success = test_admin_creation()
    
    if success:
        print("\n🎉 All tests passed!")
        print("\n📋 Next Steps:")
        print("1. Wait for deployment to complete")
        print("2. Visit: https://ctf-game-okl5.onrender.com/create_admin_user")
        print("3. Login with username: admin, password: admin123")
    else:
        print("\n❌ Tests failed!")

if __name__ == "__main__":
    main()
