#!/bin/bash
set -e

# CTF Application Deployment Script
# Professional deployment with comprehensive checks and rollback capability

echo "🚀 CTF Application Deployment Script"
echo "===================================="

# Configuration
APP_NAME="ctf-game"
DOCKER_IMAGE="ctf-app"
BACKUP_DIR="./backups"
LOG_FILE="./logs/deploy.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root for security reasons"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check if .env file exists
    if [[ ! -f .env ]]; then
        error ".env file not found. Please create it from .env.example"
        exit 1
    fi
    
    # Check required environment variables
    source .env
    required_vars=("SECRET_KEY" "POSTGRES_PASSWORD" "MAIL_USERNAME" "MAIL_PASSWORD")
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            error "Required environment variable $var is not set in .env"
            exit 1
        fi
    done
    
    success "Prerequisites check passed"
}

# Create necessary directories
create_directories() {
    log "Creating necessary directories..."
    
    directories=("logs" "backups" "uploads" "ssl" "instance")
    for dir in "${directories[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            log "Created directory: $dir"
        fi
    done
    
    success "Directories created"
}

# Generate SSL certificates (self-signed for development)
generate_ssl() {
    log "Checking SSL certificates..."
    
    if [[ ! -f ssl/cert.pem ]] || [[ ! -f ssl/key.pem ]]; then
        warning "SSL certificates not found. Generating self-signed certificates..."
        
        openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem \
            -days 365 -nodes -subj "/C=US/ST=State/L=City/O=CTF/CN=localhost"
        
        chmod 600 ssl/key.pem
        chmod 644 ssl/cert.pem
        
        warning "Self-signed SSL certificates generated. Replace with proper certificates for production!"
    else
        success "SSL certificates found"
    fi
}

# Database backup
backup_database() {
    if [[ "$1" == "skip" ]]; then
        log "Skipping database backup"
        return
    fi
    
    log "Creating database backup..."
    
    # Create backup directory with timestamp
    backup_timestamp=$(date +"%Y%m%d_%H%M%S")
    backup_path="$BACKUP_DIR/backup_$backup_timestamp"
    mkdir -p "$backup_path"
    
    # Backup database if container is running
    if docker-compose ps postgres | grep -q "Up"; then
        docker-compose exec -T postgres pg_dump -U ctfuser ctfdb > "$backup_path/database.sql"
        
        # Backup uploaded files
        if [[ -d uploads ]]; then
            cp -r uploads "$backup_path/"
        fi
        
        # Backup instance data
        if [[ -d instance ]]; then
            cp -r instance "$backup_path/"
        fi
        
        success "Database backup created: $backup_path"
    else
        warning "Database container not running, skipping backup"
    fi
}

# Build and deploy
deploy() {
    log "Starting deployment..."
    
    # Pull latest changes (if in git repo)
    if [[ -d .git ]]; then
        log "Pulling latest changes..."
        git pull origin main || warning "Git pull failed or not in git repo"
    fi
    
    # Build Docker images
    log "Building Docker images..."
    docker-compose build --no-cache
    
    # Stop existing containers
    log "Stopping existing containers..."
    docker-compose down
    
    # Start new containers
    log "Starting new containers..."
    docker-compose up -d
    
    # Wait for services to be ready
    log "Waiting for services to start..."
    sleep 30
    
    # Health check
    health_check
    
    success "Deployment completed successfully"
}

# Health check
health_check() {
    log "Performing health check..."
    
    max_attempts=30
    attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if curl -f -s http://localhost/health > /dev/null; then
            success "Health check passed"
            return 0
        fi
        
        log "Health check attempt $attempt/$max_attempts failed, retrying in 10 seconds..."
        sleep 10
        ((attempt++))
    done
    
    error "Health check failed after $max_attempts attempts"
    return 1
}

# Rollback function
rollback() {
    error "Deployment failed. Starting rollback..."
    
    # Stop current containers
    docker-compose down
    
    # Find latest backup
    latest_backup=$(ls -t "$BACKUP_DIR" | head -n1)
    
    if [[ -n "$latest_backup" ]]; then
        log "Rolling back to backup: $latest_backup"
        
        # Restore database
        if [[ -f "$BACKUP_DIR/$latest_backup/database.sql" ]]; then
            docker-compose up -d postgres
            sleep 10
            docker-compose exec -T postgres psql -U ctfuser -d ctfdb < "$BACKUP_DIR/$latest_backup/database.sql"
        fi
        
        # Restore files
        if [[ -d "$BACKUP_DIR/$latest_backup/uploads" ]]; then
            rm -rf uploads
            cp -r "$BACKUP_DIR/$latest_backup/uploads" .
        fi
        
        if [[ -d "$BACKUP_DIR/$latest_backup/instance" ]]; then
            rm -rf instance
            cp -r "$BACKUP_DIR/$latest_backup/instance" .
        fi
        
        success "Rollback completed"
    else
        error "No backup found for rollback"
    fi
}

# Cleanup old backups
cleanup_backups() {
    log "Cleaning up old backups..."
    
    # Keep only last 10 backups
    backup_count=$(ls -1 "$BACKUP_DIR" | wc -l)
    if [[ $backup_count -gt 10 ]]; then
        ls -t "$BACKUP_DIR" | tail -n +11 | xargs -I {} rm -rf "$BACKUP_DIR/{}"
        success "Old backups cleaned up"
    fi
}

# Main deployment function
main() {
    # Parse command line arguments
    SKIP_BACKUP=false
    FORCE_DEPLOY=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-backup)
                SKIP_BACKUP=true
                shift
                ;;
            --force)
                FORCE_DEPLOY=true
                shift
                ;;
            --rollback)
                rollback
                exit 0
                ;;
            --health-check)
                health_check
                exit $?
                ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --skip-backup    Skip database backup"
                echo "  --force          Force deployment without confirmation"
                echo "  --rollback       Rollback to previous version"
                echo "  --health-check   Perform health check only"
                echo "  -h, --help       Show this help message"
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")"
    
    log "Starting CTF application deployment"
    
    # Run checks
    check_root
    check_prerequisites
    create_directories
    generate_ssl
    
    # Confirmation
    if [[ "$FORCE_DEPLOY" != true ]]; then
        echo -n "Are you sure you want to deploy? (y/N): "
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            log "Deployment cancelled by user"
            exit 0
        fi
    fi
    
    # Backup
    if [[ "$SKIP_BACKUP" == true ]]; then
        backup_database skip
    else
        backup_database
    fi
    
    # Deploy
    if deploy; then
        cleanup_backups
        success "🎉 Deployment completed successfully!"
        log "Application is available at: https://localhost"
        log "Admin panel: https://localhost/admin"
    else
        error "Deployment failed"
        rollback
        exit 1
    fi
}

# Trap errors and perform rollback
trap 'error "Deployment failed with error"; rollback; exit 1' ERR

# Run main function
main "$@"
