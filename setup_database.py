#!/usr/bin/env python3
"""
Database setup script for CTF Application
This script will create the MySQL database and user if they don't exist
"""

import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv

load_dotenv()

def setup_database():
    """Setup MySQL database and user for CTF application"""
    
    # Get configuration from environment or use defaults
    mysql_root_password = os.getenv('MYSQL_ROOT_PASSWORD', '')
    mysql_host = os.getenv('MYSQL_HOST', 'localhost')
    mysql_user = os.getenv('MYSQL_USER', 'ctfuser')
    mysql_password = os.getenv('MYSQL_PASSWORD', 'ctfpass123')
    mysql_db = os.getenv('MYSQL_DB', 'ctfdb')
    
    try:
        # Connect as root to create database and user
        if mysql_root_password:
            connection = mysql.connector.connect(
                host=mysql_host,
                user='root',
                password=mysql_root_password
            )
        else:
            # Try to connect without password (for development)
            connection = mysql.connector.connect(
                host=mysql_host,
                user='root'
            )
        
        if connection.is_connected():
            cursor = connection.cursor()
            
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
            connection.close()
            print("✅ Database setup completed successfully!")
            
            return True
            
    except Error as e:
        print(f"❌ Error setting up database: {e}")
        print("\nTroubleshooting tips:")
        print("1. Make sure MySQL server is running")
        print("2. Check if you have root access to MySQL")
        print("3. Set MYSQL_ROOT_PASSWORD environment variable if required")
        print("4. For development, you can also manually create the database:")
        print(f"   - Connect to MySQL as root")
        print(f"   - Run: CREATE DATABASE {mysql_db} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
        print(f"   - Run: CREATE USER '{mysql_user}'@'localhost' IDENTIFIED BY '{mysql_password}';")
        print(f"   - Run: GRANT ALL PRIVILEGES ON {mysql_db}.* TO '{mysql_user}'@'localhost';")
        print(f"   - Run: FLUSH PRIVILEGES;")
        return False

if __name__ == "__main__":
    print("🚀 Setting up MySQL database for CTF Application...")
    setup_database()
