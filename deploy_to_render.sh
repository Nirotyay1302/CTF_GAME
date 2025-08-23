#!/bin/bash
set -e

# Professional Render.com Deployment Script for CTF Application
# This script prepares and deploys your CTF app to Render.com

echo "🚀 CTF Application - Render.com Deployment"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if git is installed
    if ! command -v git &> /dev/null; then
        error "Git is not installed. Please install Git first."
        exit 1
    fi
    
    # Check if we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        warning "Not in a Git repository. Initializing..."
        git init
        git add .
        git commit -m "Initial commit - CTF Application"
    fi
    
    # Check if render.yaml exists
    if [[ ! -f render.yaml ]]; then
        error "render.yaml not found. This file is required for Render deployment."
        exit 1
    fi
    
    success "Prerequisites check passed"
}

# Validate application files
validate_files() {
    log "Validating application files..."
    
    required_files=(
        "requirements.txt"
        "wsgi.py"
        "CTF_GAME.py"
        "models.py"
        "render.yaml"
        "render_config.py"
    )
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            error "Required file missing: $file"
            exit 1
        fi
    done
    
    success "All required files present"
}

# Test application locally
test_application() {
    log "Testing application locally..."
    
    # Check if Python is available
    if ! command -v python3 &> /dev/null; then
        error "Python 3 is not installed"
        exit 1
    fi
    
    # Test imports
    python3 -c "
import sys
try:
    from CTF_GAME import app
    print('✅ CTF_GAME imports successfully')
except Exception as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
    
try:
    from render_config import RenderConfig
    print('✅ Render configuration imports successfully')
except Exception as e:
    print(f'❌ Render config error: {e}')
    sys.exit(1)
"
    
    if [[ $? -eq 0 ]]; then
        success "Application tests passed"
    else
        error "Application tests failed"
        exit 1
    fi
}

# Generate environment variables template
generate_env_template() {
    log "Generating environment variables template..."
    
    cat > render_env_vars.txt << 'EOF'
# Environment Variables for Render.com Deployment
# Copy these to your Render service environment variables

# Required Variables (MUST be set)
SECRET_KEY=<generate-random-32-char-string>
DATABASE_URL=<automatically-set-by-render-database>
ADMIN_EMAIL=<your-admin-email>
ADMIN_PASSWORD=<secure-admin-password>

# Email Configuration (Required for notifications)
MAIL_USERNAME=<your-gmail-address>
MAIL_PASSWORD=<your-gmail-app-password>
MAIL_DEFAULT_SENDER=<your-gmail-address>

# Optional Variables (have defaults)
FLASK_ENV=production
WTF_CSRF_ENABLED=1
SESSION_COOKIE_SECURE=1
LOG_LEVEL=INFO
WORKERS=4
WORKER_CLASS=gevent
COMPRESS_LEVEL=6

# How to generate SECRET_KEY:
# python3 -c "import secrets; print(secrets.token_hex(32))"

# How to get Gmail App Password:
# 1. Enable 2FA on your Gmail account
# 2. Go to Google Account settings
# 3. Security > App passwords
# 4. Generate app password for "Mail"
EOF
    
    success "Environment variables template created: render_env_vars.txt"
}

# Prepare for deployment
prepare_deployment() {
    log "Preparing for deployment..."
    
    # Create .gitignore if it doesn't exist
    if [[ ! -f .gitignore ]]; then
        cat > .gitignore << 'EOF'
# Environment files
.env
.env.local
.env.production

# Python
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
env/
venv/
.venv/
pip-log.txt
pip-delete-this-directory.txt

# Database
*.db
*.sqlite
*.sqlite3
instance/

# Logs
logs/
*.log

# Uploads
uploads/
!uploads/.gitkeep

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Backup files
backups/
*.bak
EOF
        success "Created .gitignore file"
    fi
    
    # Create uploads directory with .gitkeep
    mkdir -p uploads
    touch uploads/.gitkeep
    
    # Create logs directory with .gitkeep
    mkdir -p logs
    touch logs/.gitkeep
    
    # Create instance directory with .gitkeep
    mkdir -p instance
    touch instance/.gitkeep
    
    success "Deployment preparation completed"
}

# Commit changes
commit_changes() {
    log "Committing changes to Git..."
    
    # Add all files
    git add .
    
    # Check if there are changes to commit
    if git diff --staged --quiet; then
        log "No changes to commit"
    else
        git commit -m "Prepare for Render.com deployment - $(date)"
        success "Changes committed to Git"
    fi
}

# Display deployment instructions
show_deployment_instructions() {
    echo ""
    echo "🎯 RENDER.COM DEPLOYMENT INSTRUCTIONS"
    echo "====================================="
    echo ""
    echo "1. 📁 PUSH TO GITHUB:"
    echo "   git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git"
    echo "   git branch -M main"
    echo "   git push -u origin main"
    echo ""
    echo "2. 🌐 CREATE RENDER ACCOUNT:"
    echo "   - Go to https://render.com"
    echo "   - Sign up with GitHub account"
    echo "   - Connect your GitHub repository"
    echo ""
    echo "3. 🗄️ CREATE DATABASE:"
    echo "   - In Render dashboard, click 'New +'"
    echo "   - Select 'PostgreSQL'"
    echo "   - Name: ctf-database"
    echo "   - Plan: Free (or Starter for production)"
    echo "   - Region: Oregon"
    echo "   - Click 'Create Database'"
    echo ""
    echo "4. 🚀 CREATE WEB SERVICE:"
    echo "   - Click 'New +' > 'Web Service'"
    echo "   - Connect your GitHub repository"
    echo "   - Name: ctf-game"
    echo "   - Runtime: Python 3"
    echo "   - Build Command: pip install -r requirements.txt && python database_setup.py"
    echo "   - Start Command: gunicorn --bind 0.0.0.0:\$PORT --workers 4 --worker-class gevent wsgi:application"
    echo "   - Plan: Free (or Starter for production)"
    echo ""
    echo "5. ⚙️ SET ENVIRONMENT VARIABLES:"
    echo "   - In your web service settings, go to 'Environment'"
    echo "   - Add variables from render_env_vars.txt"
    echo "   - DATABASE_URL will be auto-set when you connect the database"
    echo ""
    echo "6. 🔗 CONNECT DATABASE:"
    echo "   - In web service settings, go to 'Environment'"
    echo "   - Add environment variable:"
    echo "     Key: DATABASE_URL"
    echo "     Value: Select your PostgreSQL database"
    echo ""
    echo "7. 🎉 DEPLOY:"
    echo "   - Click 'Create Web Service'"
    echo "   - Wait for deployment to complete"
    echo "   - Your app will be available at: https://your-service-name.onrender.com"
    echo ""
    echo "📋 IMPORTANT NOTES:"
    echo "- Free tier sleeps after 15 minutes of inactivity"
    echo "- Upgrade to Starter plan (\$7/month) for always-on service"
    echo "- Database free tier has 1GB storage limit"
    echo "- Set up custom domain in service settings"
    echo ""
    echo "🔧 TROUBLESHOOTING:"
    echo "- Check build logs if deployment fails"
    echo "- Verify all environment variables are set"
    echo "- Ensure DATABASE_URL is connected"
    echo "- Check application logs for runtime errors"
    echo ""
    echo "📞 SUPPORT:"
    echo "- Render docs: https://render.com/docs"
    echo "- Check render_env_vars.txt for required variables"
    echo "- Test locally before deploying"
}

# Main deployment function
main() {
    log "Starting Render.com deployment preparation"
    
    # Run all preparation steps
    check_prerequisites
    validate_files
    test_application
    generate_env_template
    prepare_deployment
    commit_changes
    
    success "🎉 Deployment preparation completed!"
    show_deployment_instructions
    
    echo ""
    echo "✅ Your CTF application is ready for Render.com deployment!"
    echo "📄 Next: Follow the deployment instructions above"
    echo "🔗 Environment variables template: render_env_vars.txt"
}

# Run main function
main "$@"
