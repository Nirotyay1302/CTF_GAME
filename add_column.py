from main import app, db
from sqlalchemy import text

with app.app_context():
    # Add the is_template column to the challenge table if it doesn't exist
    try:
        db.session.execute(text("ALTER TABLE challenge ADD COLUMN is_template BOOLEAN DEFAULT 0"))
        db.session.commit()
        print("Column 'is_template' added successfully to the challenge table.")
    except Exception as e:
        db.session.rollback()
        print(f"Error adding column: {e}")