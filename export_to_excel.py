import os
import pandas as pd
from datetime import datetime
from flask import current_app
from sqlalchemy import create_engine
from models import db, User, Challenge, Solve, Submission, Team, TeamMembership, Tournament, Achievement, UserAchievement

def export_all_to_excel():
    """Export all relevant database tables to an Excel file."""
    try:
        # Ensure we're in an application context
        if current_app._get_current_object() is None:
            raise RuntimeError("This function must be called within an application context")
        
        # Get database URI from app config
        db_uri = current_app.config['SQLALCHEMY_DATABASE_URI']
        engine = create_engine(db_uri)

        # Create a timestamp for the filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"CTF_GAME_{timestamp}.xlsx"
        
        # Create Excel writer
        writer = pd.ExcelWriter(filename, engine='xlsxwriter')
        
        # Export Users
        users_df = pd.read_sql_query("SELECT * FROM user", engine)
        # Remove sensitive information
        if 'password_hash' in users_df.columns:
            users_df = users_df.drop(columns=['password_hash'])
        users_df.to_excel(writer, sheet_name='Users', index=False)
        
        # Export Challenges
        challenges_df = pd.read_sql_query("SELECT * FROM challenge", engine)
        # Remove encrypted flags for security
        if 'flag_encrypted' in challenges_df.columns:
            challenges_df = challenges_df.drop(columns=['flag_encrypted', 'flag_salt', 'flag_hash'])
        challenges_df.to_excel(writer, sheet_name='Challenges', index=False)
        
        # Export Solves
        solves_df = pd.read_sql_query("SELECT * FROM solve", engine)
        solves_df.to_excel(writer, sheet_name='Solves', index=False)
        
        # Export Submissions
        submissions_df = pd.read_sql_query("SELECT * FROM submission", engine)
        submissions_df.to_excel(writer, sheet_name='Submissions', index=False)
        
        # Export Teams
        teams_df = pd.read_sql_query("SELECT * FROM team", engine)
        teams_df.to_excel(writer, sheet_name='Teams', index=False)
        
        # Export Team Memberships
        team_memberships_df = pd.read_sql_query("SELECT * FROM team_membership", engine)
        team_memberships_df.to_excel(writer, sheet_name='TeamMemberships', index=False)
        
        # Export Tournaments
        tournaments_df = pd.read_sql_query("SELECT * FROM tournament", engine)
        tournaments_df.to_excel(writer, sheet_name='Tournaments', index=False)
        
        # Export Achievements
        achievements_df = pd.read_sql_query("SELECT * FROM achievement", engine)
        achievements_df.to_excel(writer, sheet_name='Achievements', index=False)
        
        # Export User Achievements
        user_achievements_df = pd.read_sql_query("SELECT * FROM user_achievement", engine)
        user_achievements_df.to_excel(writer, sheet_name='UserAchievements', index=False)
        
        # Save the Excel file
        writer.close()
        
        print(f"[EXPORT] Successfully exported data to {filename}")
        return filename
    except Exception as e:
        print(f"[EXPORT ERROR] Failed to export data: {e}")
        return None

if __name__ == "__main__":
    # This allows the script to be run directly for testing
    from CTF_GAME import app
    with app.app_context():
        export_all_to_excel()