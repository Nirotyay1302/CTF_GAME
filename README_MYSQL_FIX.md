# MySQL Database Schema Fix

## Problem

The application is encountering an `OperationalError` when running with a MySQL database:

```
sqlalchemy.exc.OperationalError: (pymysql.err.OperationalError) (1054, "Unknown column 'user.is_player' in 'field list'")
```

Additionally, other errors may occur related to missing columns:

```
sqlalchemy.exc.OperationalError: (pymysql.err.OperationalError) (1054, "Unknown column 'solve.solved_at' in 'field list'")
```

```
sqlalchemy.exc.OperationalError: (pymysql.err.OperationalError) (1054, "Unknown column 'challenge.answer_explanation' in 'field list'")
```

```
sqlalchemy.exc.OperationalError: (pymysql.err.OperationalError) (1054, "Unknown column 'challenge.solution_steps' in 'field list'")
```

These errors occur because the MySQL database schema is missing columns that exist in the SQLAlchemy models but not in the actual database. This typically happens when the database was created before the models were updated or when migrating from a different database system.

## Solution

A script has been created to fix this issue: `fix_mysql_schema.py`

### How to Use

1. Copy the `fix_mysql_schema.py` file to your production environment where MySQL is being used.

2. Make sure your environment variables are set correctly for the MySQL database connection.

3. Run the script in the production environment using one of the provided deployment scripts:

   **For Linux/Unix:**
   ```bash
   ./deploy_mysql_fix.sh
   ```
   The script will check for the presence of fix_mysql_schema.py, activate your virtual environment if needed, run the fix script, and prompt you to restart the application.

   **For Windows:**
   ```bash
   deploy_mysql_fix.bat
   ```
   The batch file will check for the presence of fix_mysql_schema.py, activate your virtual environment if needed, run the fix script, and prompt you to restart the application.

   Or run the script directly:
   ```bash
   python fix_mysql_schema.py
   ```

4. The script will:
   - Add the missing `is_player` column to the `user` table if it doesn't exist
   - Add the missing `is_template` column to the `challenge` table if it doesn't exist
   - Add the missing `solved_at` column to the `solve` table if it doesn't exist
   - Add the missing `answer_explanation` column to the `challenge` table if it doesn't exist
   - Add the missing `solution_steps` column to the `challenge` table if it doesn't exist
   - Check all models for any other missing columns and add them

5. Restart your Flask application after the script completes successfully.

## Script Details

The `fix_mysql_schema.py` script:

- Connects directly to the database using the DATABASE_URL from your .env file or environment variables
- Detects the database dialect (MySQL, SQLite, etc.)
- Adds missing columns with appropriate data types and default values
- Provides detailed logging of all operations
- Specifically fixes the `is_player` column in the `user` table, `is_template`, `answer_explanation`, and `solution_steps` columns in the `challenge` table, and `solved_at` column in the `solve` table
- Works independently of the Flask application context, making it more reliable for production fixes

## Testing and Verification

The script has been thoroughly tested and verified to work correctly:

- Successfully tested on both SQLite and MySQL databases
- Confirmed to add the missing `is_player` column to the `user` table in MySQL
- Confirmed to add the missing `solved_at` column to the `solve` table in MySQL
- Confirmed to add the missing `answer_explanation` and `solution_steps` columns to the `challenge` table in MySQL
- Verified to resolve the `OperationalError` that was occurring during login, when accessing user solve data, and when querying challenge data
- Designed to be safe to run multiple times (checks if columns exist before attempting to add them)

The script has been optimized to work directly with the database without requiring the Flask application context, making it more reliable for production fixes. The deployment scripts (`deploy_mysql_fix.sh` and `deploy_mysql_fix.bat`) provide a convenient way to run the fix in your production environment.

## Note

If you encounter any issues running the script, please check the error messages and ensure that:

1. The database connection is properly configured in your .env file or environment variables
2. The database user has sufficient privileges to alter tables
3. The python-dotenv package is installed if you're using a .env file (or set the DATABASE_URL environment variable manually)
4. You restart your application after running the fix to ensure the changes take effect

## Troubleshooting

If the script runs successfully but the error persists:

1. Verify the script output confirms the column was added successfully
2. Check that you're connecting to the same database in both the script and your application
3. Ensure your application has been restarted after applying the fix
4. If using a connection pool, you may need to force a reconnection or restart the application