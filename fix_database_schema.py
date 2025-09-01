from main import app, db
from sqlalchemy import text, inspect
import sqlalchemy.exc
from datetime import datetime
from models import User, Challenge, Solve, Submission, Team, TeamMembership, Tournament, Hint, UserHint, Notification, ChatMessage, Friend

def get_column_type_str(column):
    """Convert SQLAlchemy column type to SQL string representation"""
    if hasattr(column.type, 'python_type'):
        python_type = column.type.python_type
        if python_type == bool:
            return 'BOOLEAN DEFAULT 0'
        elif python_type == int:
            return 'INTEGER DEFAULT 0'
        elif python_type == float:
            return 'FLOAT DEFAULT 0'
        elif python_type == str:
            # Get the length if it's a string with length
            if hasattr(column.type, 'length') and column.type.length:
                return f'VARCHAR({column.type.length}) DEFAULT \'\''
            else:
                return 'TEXT DEFAULT \'\''
        elif python_type == datetime:
            return 'DATETIME'
    
    # Default fallback
    return 'TEXT'

def check_and_add_column(table_name, column_name, column_type):
    """Check if a column exists in a table and add it if it doesn't"""
    inspector = inspect(db.engine)
    columns = [col['name'] for col in inspector.get_columns(table_name)]
    
    if column_name not in columns:
        print(f"Adding missing column '{column_name}' to table '{table_name}'")
        
        # Different syntax based on dialect
        dialect = db.engine.dialect.name
        if dialect == 'mysql':
            db.session.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))
        elif dialect == 'sqlite':
            db.session.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))
        else:
            print(f"Unsupported database dialect: {dialect}")
            return False
        
        db.session.commit()
        print(f"Column '{column_name}' added successfully to '{table_name}'")
        return True
    else:
        print(f"Column '{column_name}' already exists in '{table_name}'")
        return True

def check_model_columns(model_class):
    """Check all columns in a model against the database"""
    table_name = model_class.__tablename__
    print(f"\nChecking columns for table '{table_name}'...")
    
    for column_name, column in model_class.__table__.columns.items():
        # Skip primary key columns as they should already exist
        if column.primary_key:
            continue
            
        column_type = get_column_type_str(column)
        check_and_add_column(table_name, column_name, column_type)

with app.app_context():
    try:
        # Check all models
        models = [User, Challenge, Solve, Submission, Team, TeamMembership, 
                 Tournament, Hint, UserHint, Notification, ChatMessage, Friend]
        
        for model in models:
            try:
                check_model_columns(model)
            except Exception as e:
                print(f"Error checking model {model.__name__}: {e}")
        
        print("\nDatabase schema check completed successfully.")
    except Exception as e:
        db.session.rollback()
        print(f"Error fixing database schema: {e}")