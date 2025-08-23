#!/usr/bin/env python3
"""
Simple database setup script for CTF Application
"""

import mysql.connector
from mysql.connector import Error
import os

def setup_database():
    """Setup MySQL database and user for CTF application"""
    
    # Configuration
    mysql_host = 'localhost'
    mysql_user = 'ctfuser'
    mysql_password = 'ctfpass123'
    mysql_db = 'ctfdb'
    
    # Try different connection methods
    connection_methods = [
        # Try without password first
        {'user': 'root', 'password': ''},
        # Try common default passwords
        {'user': 'root', 'password': 'root'},
        {'user': 'root', 'password': 'password'},
        {'user': 'root', 'password': 'admin'},
        # Try with the user we want to create
        {'user': mysql_user, 'password': mysql_password}
    ]
    
    connection = None
    root_connection = None
    
    # Try to find a working connection
    for method in connection_methods:
        try:
            print(f"🔍 Trying to connect as {method['user']}...")
            connection = mysql.connector.connect(
                host=mysql_host,
                user=method['user'],
                password=method['password']
            )
            if connection.is_connected():
                print(f"✅ Connected as {method['user']}")
                if method['user'] == 'root':
                    root_connection = connection
                    break
                else:
                    # We're connected as the user we want to create
                    print("✅ Already connected as target user!")
                    return True
        except Error as e:
            print(f"❌ Failed to connect as {method['user']}: {e}")
            continue
    
    if not root_connection:
        print("❌ Could not establish root connection to MySQL")
        print("\nPlease try one of these solutions:")
        print("1. Reset MySQL root password:")
        print("   - Stop MySQL service")
        print("   - Start MySQL with --skip-grant-tables")
        print("   - Connect and reset password")
        print("2. Create the database manually:")
        print(f"   - Connect to MySQL as root")
        print(f"   - Run: CREATE DATABASE {mysql_db} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
        print(f"   - Run: CREATE USER '{mysql_user}'@'localhost' IDENTIFIED BY '{mysql_password}';")
        print(f"   - Run: GRANT ALL PRIVILEGES ON {mysql_db}.* TO '{mysql_user}'@'localhost';")
        print(f"   - Run: FLUSH PRIVILEGES;")
        return False
    
    try:
        cursor = root_connection.cursor()
        
        # Create database if it doesn't exist
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{mysql_db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        print(f"✅ Database '{mysql_db}' created/verified successfully")
        
        # Create user if it doesn't exist
        cursor.execute(f"CREATE USER IF NOT EXISTS '{mysql_user}'@'%' IDENTIFIED BY '{mysql_password}'")
        print(f"✅ User '{mysql_user}' created/verified successfully")
        
        # Grant privileges to user
        cursor.execute(f"GRANT ALL PRIVILEGES ON `{mysql_db}`.* TO '{mysql_user}'@'%'")
        cursor.execute(f"GRANT ALL PRIVILEGES ON `{mysql_db}`.* TO '{mysql_user}'@'localhost'")
        print(f"✅ Privileges granted to '{mysql_user}' for database '{mysql_db}'")
        
        # Flush privileges
        cursor.execute("FLUSH PRIVILEGES")
        print("✅ Privileges flushed successfully")
        
        cursor.close()
        root_connection.close()
        print("✅ Database setup completed successfully!")
        
        return True
        
    except Error as e:
        print(f"❌ Error setting up database: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Setting up MySQL database for CTF Application...")
    setup_database()
