#!/usr/bin/env python3
"""
Startup script for CTF Application
This script will:
1. Setup the MySQL database if needed
2. Initialize the database tables
3. Start the Flask application
"""

import os
import sys
import subprocess
from pathlib import Path

def check_mysql_connection():
    """Check if MySQL is accessible"""
    try:
        import mysql.connector
        from config import Config
        
        connection = mysql.connector.connect(
            host=Config.MYSQL_HOST,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD,
            database=Config.MYSQL_DB
        )
        connection.close()
        return True
    except Exception as e:
        print(f"❌ MySQL connection failed: {e}")
        return False

def setup_database():
    """Setup the database using the setup script"""
    print("🔧 Setting up database...")
    try:
        result = subprocess.run([sys.executable, "setup_database.py"], 
                              capture_output=True, text=True, check=True)
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Database setup failed: {e}")
        print(e.stderr)
        return False

def main():
    """Main startup function"""
    print("🚀 Starting CTF Application...")
    
    # Check if we're in the right directory
    if not Path("CTF_GAME.py").exists():
        print("❌ Error: CTF_GAME.py not found. Please run this script from the CTF_APP directory.")
        sys.exit(1)
    
    # Check MySQL connection
    if not check_mysql_connection():
        print("🔧 Attempting to setup database...")
        if not setup_database():
            print("❌ Failed to setup database. Please check MySQL installation and try again.")
            sys.exit(1)
        
        # Check connection again
        if not check_mysql_connection():
            print("❌ Database setup completed but connection still failed.")
            print("Please check your MySQL configuration and try again.")
            sys.exit(1)
    
    print("✅ Database connection successful!")
    print("🚀 Starting Flask application...")
    
    # Start the main application
    try:
        subprocess.run([sys.executable, "CTF_GAME.py"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Application failed to start: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n👋 Application stopped by user")

if __name__ == "__main__":
    main()
