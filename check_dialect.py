from main import app, db
from sqlalchemy import text

with app.app_context():
    dialect = db.engine.dialect.name
    print(f'Current database dialect: {dialect}')
    
    # Check if we're connected to MySQL
    if dialect == 'mysql':
        # Check if is_player column exists in user table
        try:
            result = db.session.execute(text("SELECT is_player FROM user LIMIT 1"))
            print("Column 'is_player' exists in MySQL database.")
        except Exception as e:
            print(f"Error checking column: {e}")
            print("Adding 'is_player' column to MySQL database...")
            try:
                db.session.execute(text("ALTER TABLE user ADD COLUMN is_player BOOLEAN DEFAULT 1"))
                db.session.commit()
                print("Column 'is_player' added successfully to MySQL database.")
            except Exception as e:
                db.session.rollback()
                print(f"Error adding column: {e}")