from main import app, db
from sqlalchemy import text
import sqlalchemy.exc

with app.app_context():
    # Add the is_player column to the user table if it doesn't exist
    try:
        # Check if we're using MySQL or SQLite
        dialect = db.engine.dialect.name
        
        if dialect == 'mysql':
            # MySQL syntax
            db.session.execute(text("ALTER TABLE user ADD COLUMN is_player BOOLEAN DEFAULT 1"))
            db.session.commit()
            print("Column 'is_player' added successfully to the user table in MySQL.")
        elif dialect == 'sqlite':
            # For SQLite, check if column exists first
            try:
                # Try to select from the column to see if it exists
                db.session.execute(text("SELECT is_player FROM user LIMIT 1"))
                print("Column 'is_player' already exists in SQLite database.")
            except sqlalchemy.exc.OperationalError:
                # Column doesn't exist, so add it
                db.session.execute(text("ALTER TABLE user ADD COLUMN is_player BOOLEAN DEFAULT 1"))
                db.session.commit()
                print("Column 'is_player' added successfully to the user table in SQLite.")
        else:
            print(f"Unsupported database dialect: {dialect}")
    except Exception as e:
        db.session.rollback()
        print(f"Error adding column: {e}")