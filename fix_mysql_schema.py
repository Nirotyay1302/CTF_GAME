#!/usr/bin/env python3
"""
MySQL Schema Fix Script
This script directly adds missing columns to the MySQL database.
"""

import os
import sys
from sqlalchemy import create_engine, text, inspect
import sqlalchemy.exc

# Load environment variables from .env file if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("Loaded environment variables from .env file")
except ImportError:
    print("python-dotenv not installed, skipping .env loading")

# Get database URL from environment or use default MySQL connection
database_url = os.environ.get('DATABASE_URL', 'mysql+pymysql://ctfuser:ctfpass123@localhost/ctfdb')
print(f"Using database: {database_url}")

# Create engine
engine = create_engine(database_url)

def check_column_exists(table_name, column_name):
    """Check if a column exists in a table"""
    inspector = inspect(engine)
    columns = inspector.get_columns(table_name)
    return any(col['name'] == column_name for col in columns)

def add_column(table_name, column_name, column_type):
    """Add a column to a table"""
    with engine.connect() as connection:
        try:
            connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))
            connection.commit()
            print(f"Column '{column_name}' added successfully to '{table_name}'")
            return True
        except Exception as e:
            connection.rollback()
            print(f"Error adding column: {e}")
            return False

def check_and_add_column(table_name, column_name, column_type):
    """Check if a column exists in a table and add it if it doesn't"""
    if check_column_exists(table_name, column_name):
        print(f"Column '{column_name}' already exists in '{table_name}'")
        return True
    else:
        print(f"Column '{column_name}' does not exist in '{table_name}', adding it...")
        return add_column(table_name, column_name, column_type)

# Main execution
try:
    # Check database dialect
    dialect = engine.dialect.name
    print(f"Current database dialect: {dialect}")
    
    print(f"Running schema check on {dialect} database...")
    
    # Specifically check and add the is_player column to the user table
    check_and_add_column('user', 'is_player', 'BOOLEAN DEFAULT 1')
    
    # Also check and add the is_template column to the challenge table
    check_and_add_column('challenge', 'is_template', 'BOOLEAN DEFAULT 0')
    
    # Check and add the solved_at column to the solve table
    check_and_add_column('solve', 'solved_at', 'DATETIME DEFAULT CURRENT_TIMESTAMP')
    
    # Check and add the answer_explanation column to the challenge table
    check_and_add_column('challenge', 'answer_explanation', 'TEXT NULL')
    
    # Check and add the solution_steps column to the challenge table
    check_and_add_column('challenge', 'solution_steps', 'TEXT NULL')
    
    print(f"\n{dialect.capitalize()} database schema check completed successfully.")
    
except Exception as e:
    print(f"Error fixing database schema: {e}")