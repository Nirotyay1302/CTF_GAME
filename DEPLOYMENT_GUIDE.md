# CTF Application Deployment Guide

## Production Deployment Checklist

### 1. Environment Variables
Set these environment variables in production:

```bash
# Security
SECRET_KEY=your_super_secure_secret_key_here
FLASK_DEBUG=0

# Database (choose one)
DATABASE_URL=postgresql://user:pass@host:port/dbname  # For PostgreSQL
# OR
DATABASE_URL=mysql+pymysql://user:pass@host:port/dbname  # For MySQL

# Email Configuration (optional)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
ADMIN_EMAIL=admin@yourdomain.com

# Encryption Key (optional - will auto-generate if not set)
FERNET_KEY=your_fernet_key_here
```

### 2. Database Setup
- Create a production database (PostgreSQL or MySQL recommended)
- Run migrations: `flask db upgrade`
- Initialize challenges: `python init_challenges.py`

### 3. Web Server
Use a production WSGI server like Gunicorn:

```bash
# Install gunicorn (already in requirements.txt)
pip install gunicorn

# Run with gunicorn
gunicorn --bind 0.0.0.0:8000 --workers 4 app:app
```

### 4. Reverse Proxy
Configure nginx or Apache as a reverse proxy:

```nginx
server {
    listen 80;
    server_name yourdomain.com;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /static {
        alias /path/to/your/app/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

### 5. Security Considerations
- Use HTTPS in production
- Set strong SECRET_KEY
- Configure firewall rules
- Regular database backups
- Monitor application logs

### 6. Performance Optimization
- Enable database connection pooling
- Use Redis for caching (optional)
- Configure CDN for static files
- Monitor resource usage

## Local Development

### Quick Start
1. Clone the repository
2. Create virtual environment: `python -m venv .venv`
3. Activate: `.venv\Scripts\activate` (Windows) or `source .venv/bin/activate` (Linux/Mac)
4. Install dependencies: `pip install -r requirements.txt`
5. Copy `.env.example` to `.env` and configure
6. Run: `python app.py`

### Database Options
- **SQLite**: Default for local development (no setup required)
- **MySQL**: Set MYSQL_* environment variables
- **PostgreSQL**: Set DATABASE_URL environment variable

## Troubleshooting

### Common Issues
1. **Database Connection Failed**: Check credentials and database server status
2. **Import Errors**: Ensure all dependencies are installed (`pip install -r requirements.txt`)
3. **Permission Errors**: Check file permissions for instance/ directory
4. **Port Already in Use**: Change PORT environment variable or kill existing process

### Logs
- Application logs are printed to console
- Check database connection status at startup
- Monitor HTTP request logs for errors

## Features

### Core Features
- User registration and authentication
- Challenge management system
- Team-based competition
- Real-time scoring and leaderboards
- Admin panel for management
- Email notifications
- WebSocket support for live updates

### Challenge Categories
- Web Security
- Cryptography
- Forensics
- Reverse Engineering
- Binary Exploitation (PWN)
- Miscellaneous

### Admin Features
- User management
- Challenge creation and editing
- Tournament management
- System monitoring
- Data export to Excel

## Support
For issues or questions, check the application logs and ensure all dependencies are properly installed.
