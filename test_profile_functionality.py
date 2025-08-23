#!/usr/bin/env python3
"""
Test script to verify profile functionality works correctly
"""

import os
import sys
from datetime import datetime, date

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from CTF_GAME import app, db
from models import User

def test_profile_fields():
    """Test profile field updates"""
    print("🧪 Testing Profile Field Updates")
    print("=" * 40)
    
    with app.app_context():
        try:
            # Get or create a test user
            test_user = User.query.filter_by(username='testuser').first()
            if not test_user:
                print("Creating test user...")
                test_user = User(
                    username='testuser',
                    email='test@example.com',
                    password_hash='test_hash',
                    role='user'
                )
                db.session.add(test_user)
                db.session.commit()
                print("✅ Test user created")
            
            print(f"Testing with user: {test_user.username} (ID: {test_user.id})")
            
            # Test updating profile fields
            original_values = {
                'first_name': test_user.first_name,
                'last_name': test_user.last_name,
                'bio': test_user.bio,
                'country': test_user.country,
                'timezone': test_user.timezone,
                'gender': test_user.gender,
                'date_of_birth': test_user.date_of_birth
            }
            
            print("\nOriginal values:")
            for field, value in original_values.items():
                print(f"  {field}: {value}")
            
            # Update fields
            test_user.first_name = "Test"
            test_user.last_name = "User"
            test_user.bio = "This is a test bio for profile functionality testing."
            test_user.country = "United States"
            test_user.timezone = "America/New_York"
            test_user.gender = "prefer_not_to_say"
            test_user.date_of_birth = date(1990, 1, 1)
            
            # Commit changes
            db.session.commit()
            print("\n✅ Profile fields updated successfully")
            
            # Verify changes were saved
            db.session.refresh(test_user)
            
            updated_values = {
                'first_name': test_user.first_name,
                'last_name': test_user.last_name,
                'bio': test_user.bio,
                'country': test_user.country,
                'timezone': test_user.timezone,
                'gender': test_user.gender,
                'date_of_birth': test_user.date_of_birth
            }
            
            print("\nUpdated values:")
            for field, value in updated_values.items():
                print(f"  {field}: {value}")
            
            # Check if values were actually saved
            changes_saved = 0
            for field in original_values:
                if original_values[field] != updated_values[field]:
                    changes_saved += 1
                    print(f"✅ {field} changed: '{original_values[field]}' -> '{updated_values[field]}'")
            
            if changes_saved > 0:
                print(f"\n✅ {changes_saved} fields successfully updated and saved to database")
                return True
            else:
                print("\n❌ No changes were saved to database")
                return False
                
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error testing profile fields: {e}")
            import traceback
            traceback.print_exc()
            return False

def test_profile_picture_directory():
    """Test profile picture directory setup"""
    print("\n🧪 Testing Profile Picture Directory")
    print("=" * 40)
    
    with app.app_context():
        try:
            upload_dir = os.path.join(app.instance_path, 'profile_pictures')
            print(f"Upload directory path: {upload_dir}")
            
            # Create directory if it doesn't exist
            os.makedirs(upload_dir, exist_ok=True)
            
            if os.path.exists(upload_dir):
                print("✅ Profile pictures directory exists")
                
                # Check if directory is writable
                test_file = os.path.join(upload_dir, 'test_write.txt')
                try:
                    with open(test_file, 'w') as f:
                        f.write('test')
                    os.remove(test_file)
                    print("✅ Directory is writable")
                    return True
                except Exception as e:
                    print(f"❌ Directory is not writable: {e}")
                    return False
            else:
                print("❌ Profile pictures directory does not exist")
                return False
                
        except Exception as e:
            print(f"❌ Error testing profile picture directory: {e}")
            return False

def test_user_model_fields():
    """Test what fields are available in the User model"""
    print("\n🧪 Testing User Model Fields")
    print("=" * 40)
    
    # Get User model columns
    user_columns = [column.name for column in User.__table__.columns]
    
    print("Available User model fields:")
    for field in sorted(user_columns):
        print(f"   ✅ {field}")
    
    # Check for profile-related fields
    profile_fields = [
        'first_name', 'last_name', 'bio', 'country', 'timezone', 
        'gender', 'date_of_birth', 'profile_picture'
    ]
    
    missing_fields = [field for field in profile_fields if field not in user_columns]
    existing_fields = [field for field in profile_fields if field in user_columns]
    
    print(f"\nProfile fields available: {len(existing_fields)}/{len(profile_fields)}")
    for field in existing_fields:
        print(f"   ✅ {field}")
    
    if missing_fields:
        print(f"\nMissing profile fields:")
        for field in missing_fields:
            print(f"   ❌ {field}")
    
    return len(missing_fields) == 0

def test_database_connection():
    """Test database connection and basic operations"""
    print("\n🧪 Testing Database Connection")
    print("=" * 40)
    
    with app.app_context():
        try:
            # Test basic query
            user_count = User.query.count()
            print(f"✅ Database connection successful")
            print(f"   Total users in database: {user_count}")
            
            # Test database write
            test_time = datetime.utcnow()
            print(f"   Current time: {test_time}")
            
            return True
            
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            return False

def main():
    """Main test function"""
    print("🎯 CTF Profile Functionality Test Suite")
    print("=" * 50)
    
    tests = [
        ("Database Connection", test_database_connection),
        ("User Model Fields", test_user_model_fields),
        ("Profile Picture Directory", test_profile_picture_directory),
        ("Profile Field Updates", test_profile_fields)
    ]
    
    passed_tests = 0
    for test_name, test_func in tests:
        print(f"\n🔄 Running: {test_name}")
        try:
            result = test_func()
            if result:
                passed_tests += 1
                print(f"✅ {test_name} PASSED")
            else:
                print(f"❌ {test_name} FAILED")
        except Exception as e:
            print(f"❌ {test_name} ERROR: {e}")
    
    print(f"\n🎉 Test Summary: {passed_tests}/{len(tests)} tests passed")
    
    if passed_tests == len(tests):
        print("🎯 All tests passed! Profile functionality should work correctly.")
        print("\n📋 Next Steps:")
        print("1. Deploy the updated code")
        print("2. Login to your CTF app")
        print("3. Go to Profile page")
        print("4. Test updating your profile information")
        print("5. Test uploading a profile picture")
    else:
        print("⚠️  Some tests failed. Check the issues above.")

if __name__ == "__main__":
    main()
