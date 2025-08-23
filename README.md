# CTF Application

A comprehensive Capture The Flag (CTF) platform built with Flask, featuring dynamic challenges, team management, tournaments, and real-time updates.

## Features

- **User Management**: Registration, authentication, and role-based access control
- **Dynamic Challenges**: Auto-generated crypto and steganography challenges
- **Team System**: Create teams, join with codes, and compete together
- **Tournaments**: Time-based competitions with leaderboards
- **Real-time Updates**: WebSocket-based live scoreboards and notifications
- **Admin Panel**: Comprehensive challenge and user management
- **Achievement System**: Track user progress and award achievements

- **Hint System**: Cost-based hints for challenges

## Prerequisites

- Python 3.8+
- MySQL 8.0+
- Virtual environment (recommended)

## Quick Start

### 1. Clone and Setup

```bash
git clone <your-repo>
cd CTF_APP
python -m venv .venv
.venv\Scripts\activate  # Windows
# or
source .venv/bin/activate  # Linux/Mac
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Setup MySQL Database

#### Option A: Automatic Setup (Recommended)
```bash
python setup_database.py
```

#### Option B: Manual Setup
```sql
CREATE DATABASE ctfdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'ctfuser'@'localhost' IDENTIFIED BY 'ctfpass123';
GRANT ALL PRIVILEGES ON ctfdb.* TO 'ctfuser'@'localhost';
FLUSH PRIVILEGES;
```

### 4. Start the Application

```bash
python start_app.py
```

Or directly:
```bash
python CTF_GAME.py
```

The application will be available at `http://localhost:5000`

## Configuration

Create a `.env` file in the root directory:

```env
# Flask Configuration
SECRET_KEY=your_super_secret_key_here
FLASK_DEBUG=1
FLASK_RUN_PORT=5000

# Database Configuration
MYSQL_USER=ctfuser
MYSQL_PASSWORD=ctfpass123
MYSQL_HOST=localhost
MYSQL_DB=ctfdb

# Email Configuration (Optional)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password

# File Upload Configuration
MAX_UPLOAD_MB=10
```

## Database Models

- **User**: User accounts with roles and scores
- **Challenge**: CTF challenges with encrypted flags
- **Team**: Team management and membership
- **Tournament**: Time-based competitions
- **Achievement**: User achievements and progress tracking


## API Endpoints

- `/` - Home page
- `/signup` - User registration
- `/login` - User authentication
- `/dashboard` - User dashboard
- `/challenge/<id>` - Challenge view
- `/admin` - Admin panel
- `/teams` - Team management
- `/tournaments` - Tournament management
- `/scoreboard` - Leaderboards

## Admin Features

- Create and manage challenges
- Manage user accounts and teams
- Monitor system activity
- Generate dynamic challenges
- Configure tournaments

## Development

### Running Tests
```bash
python -m pytest tests/
```

### Database Migrations
```bash
flask db init
flask db migrate -m "Description"
flask db upgrade
```

### Adding New Challenge Types
1. Add function to `dynamic_challenges.py`
2. Update challenge generation logic
3. Add to challenge templates

## Production Deployment

1. Set `FLASK_DEBUG=0`
2. Use strong `SECRET_KEY`
3. Configure production MySQL server
4. Set up reverse proxy (nginx)
5. Use production WSGI server (gunicorn)

## Troubleshooting

### MySQL Connection Issues
- Ensure MySQL service is running
- Check user credentials and privileges
- Verify database exists and is accessible

### Import Errors
- Activate virtual environment
- Install all requirements: `pip install -r requirements.txt`
- Check Python version compatibility

### Permission Issues
- Ensure proper file permissions
- Check MySQL user privileges
- Verify port availability

## License

[Your License Here]

## Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request