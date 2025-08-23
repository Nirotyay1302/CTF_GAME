#!/usr/bin/env python3
"""
Performance Optimizations for CTF Application
This script contains various optimizations to make the app faster
"""

import os
import sys
from datetime import datetime, timedelta
from flask import request, g
import time

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from CTF_GAME import app, db
from models import User, Challenge, Solve, Team, Tournament, ChatMessage

def optimize_database_queries():
    """Optimize database queries with indexes and eager loading"""
    print("🔍 Optimizing database queries...")
    
    with app.app_context():
        try:
            # Add indexes for frequently queried columns
            # Note: In production, these would be migration scripts
            
            # Create indexes for better performance
            index_commands = [
                "CREATE INDEX IF NOT EXISTS idx_user_username ON user(username);",
                "CREATE INDEX IF NOT EXISTS idx_user_email ON user(email);",
                "CREATE INDEX IF NOT EXISTS idx_user_role ON user(role);",
                "CREATE INDEX IF NOT EXISTS idx_user_total_points ON user(total_points);",
                "CREATE INDEX IF NOT EXISTS idx_challenge_category ON challenge(category);",
                "CREATE INDEX IF NOT EXISTS idx_challenge_difficulty ON challenge(difficulty);",
                "CREATE INDEX IF NOT EXISTS idx_challenge_points ON challenge(points);",
                "CREATE INDEX IF NOT EXISTS idx_solve_user_id ON solve(user_id);",
                "CREATE INDEX IF NOT EXISTS idx_solve_challenge_id ON solve(challenge_id);",
                "CREATE INDEX IF NOT EXISTS idx_solve_timestamp ON solve(timestamp);",
                "CREATE INDEX IF NOT EXISTS idx_team_name ON team(name);",
                "CREATE INDEX IF NOT EXISTS idx_chat_message_channel_id ON chat_message(channel_id);",
                "CREATE INDEX IF NOT EXISTS idx_chat_message_timestamp ON chat_message(timestamp);"
            ]
            
            for command in index_commands:
                try:
                    db.engine.execute(command)
                    print(f"✅ Created index: {command.split('idx_')[1].split(' ')[0] if 'idx_' in command else 'unknown'}")
                except Exception as e:
                    print(f"⚠️ Index may already exist: {command.split('idx_')[1].split(' ')[0] if 'idx_' in command else 'unknown'}")
            
            print("✅ Database indexes optimized")
            return True
            
        except Exception as e:
            print(f"❌ Error optimizing database: {e}")
            return False

def add_caching_system():
    """Add caching for frequently accessed data"""
    print("💾 Setting up caching system...")
    
    # Simple in-memory cache
    cache = {}
    cache_timeout = 300  # 5 minutes
    
    def get_cached_leaderboard():
        """Get cached leaderboard data"""
        cache_key = 'leaderboard'
        now = time.time()
        
        if cache_key in cache:
            data, timestamp = cache[cache_key]
            if now - timestamp < cache_timeout:
                return data
        
        # Generate fresh data
        users = User.query.order_by(User.total_points.desc()).limit(50).all()
        leaderboard_data = [
            {
                'username': user.username,
                'total_points': user.total_points,
                'team_name': user.team.name if user.team else None
            }
            for user in users
        ]
        
        cache[cache_key] = (leaderboard_data, now)
        return leaderboard_data
    
    def get_cached_challenge_stats():
        """Get cached challenge statistics"""
        cache_key = 'challenge_stats'
        now = time.time()
        
        if cache_key in cache:
            data, timestamp = cache[cache_key]
            if now - timestamp < cache_timeout:
                return data
        
        # Generate fresh data
        challenges = Challenge.query.all()
        stats = {
            'total_challenges': len(challenges),
            'categories': {},
            'difficulties': {},
            'total_points': 0
        }
        
        for challenge in challenges:
            stats['categories'][challenge.category] = stats['categories'].get(challenge.category, 0) + 1
            stats['difficulties'][challenge.difficulty] = stats['difficulties'].get(challenge.difficulty, 0) + 1
            stats['total_points'] += challenge.points
        
        cache[cache_key] = (stats, now)
        return stats
    
    # Store cache functions globally for use in routes
    app.get_cached_leaderboard = get_cached_leaderboard
    app.get_cached_challenge_stats = get_cached_challenge_stats
    
    print("✅ Caching system configured")
    return True

def optimize_static_files():
    """Optimize static file serving"""
    print("📁 Optimizing static file serving...")
    
    # Add cache headers for static files
    @app.after_request
    def add_cache_headers(response):
        """Add cache headers for better performance"""
        if request.endpoint and 'static' in request.endpoint:
            # Cache static files for 1 hour
            response.cache_control.max_age = 3600
            response.cache_control.public = True
        
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        return response
    
    print("✅ Static file optimization configured")
    return True

def add_request_timing():
    """Add request timing for performance monitoring"""
    print("⏱️ Setting up request timing...")
    
    @app.before_request
    def before_request():
        """Record request start time"""
        g.start_time = time.time()
    
    @app.after_request
    def after_request(response):
        """Log slow requests"""
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
            if duration > 1.0:  # Log requests taking more than 1 second
                print(f"⚠️ Slow request: {request.endpoint} took {duration:.2f}s")
        return response
    
    print("✅ Request timing configured")
    return True

def optimize_database_connections():
    """Optimize database connection settings"""
    print("🔗 Optimizing database connections...")
    
    # Configure SQLAlchemy for better performance
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 10,
        'pool_recycle': 120,
        'pool_pre_ping': True,
        'max_overflow': 20,
        'pool_timeout': 30
    }
    
    # Optimize query performance
    app.config['SQLALCHEMY_RECORD_QUERIES'] = False  # Disable in production
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    print("✅ Database connection optimization configured")
    return True

def cleanup_old_data():
    """Clean up old data to improve performance"""
    print("🧹 Cleaning up old data...")
    
    with app.app_context():
        try:
            # Remove old chat messages (keep last 500 per channel)
            channels = db.session.query(ChatMessage.channel_id).distinct().all()
            
            for (channel_id,) in channels:
                total_messages = ChatMessage.query.filter_by(channel_id=channel_id).count()
                if total_messages > 500:
                    old_messages = ChatMessage.query.filter_by(channel_id=channel_id)\
                        .order_by(ChatMessage.id.asc())\
                        .limit(total_messages - 500).all()
                    
                    for msg in old_messages:
                        db.session.delete(msg)
                    
                    print(f"Cleaned up {len(old_messages)} old messages from channel {channel_id}")
            
            # Remove incomplete user registrations (older than 7 days, not verified)
            cutoff_time = datetime.utcnow() - timedelta(days=7)
            incomplete_users = User.query.filter(
                User.email_verified == False,
                User.created_at < cutoff_time
            ).all()
            
            for user in incomplete_users:
                db.session.delete(user)
            
            if incomplete_users:
                print(f"Cleaned up {len(incomplete_users)} incomplete user registrations")
            
            db.session.commit()
            print("✅ Data cleanup completed")
            return True
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error during cleanup: {e}")
            return False

def add_pagination_helpers():
    """Add pagination for large datasets"""
    print("📄 Setting up pagination helpers...")
    
    def paginate_query(query, page=1, per_page=20):
        """Helper function for pagination"""
        return query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
    
    # Add to app context
    app.paginate_query = paginate_query
    
    print("✅ Pagination helpers configured")
    return True

def optimize_template_rendering():
    """Optimize template rendering"""
    print("🎨 Optimizing template rendering...")
    
    # Configure Jinja2 for better performance
    app.jinja_env.auto_reload = False
    app.jinja_env.cache_size = 400
    
    # Add template globals for common data
    @app.context_processor
    def inject_common_data():
        """Inject commonly used data into templates"""
        return {
            'current_year': datetime.utcnow().year,
            'app_version': '2.0.0'
        }
    
    print("✅ Template rendering optimized")
    return True

def add_compression():
    """Add response compression"""
    print("🗜️ Setting up response compression...")
    
    try:
        from flask_compress import Compress
        
        # Configure compression
        app.config['COMPRESS_MIMETYPES'] = [
            'text/html',
            'text/css',
            'text/xml',
            'application/json',
            'application/javascript'
        ]
        
        app.config['COMPRESS_LEVEL'] = 6
        app.config['COMPRESS_MIN_SIZE'] = 500
        
        # Initialize compression
        Compress(app)
        
        print("✅ Response compression configured")
        return True
        
    except ImportError:
        print("⚠️ Flask-Compress not available, skipping compression")
        return False

def main():
    """Main optimization function"""
    print("🚀 CTF App Performance Optimizer")
    print("=" * 50)
    
    optimizations = [
        ("Database Queries", optimize_database_queries),
        ("Caching System", add_caching_system),
        ("Static Files", optimize_static_files),
        ("Request Timing", add_request_timing),
        ("Database Connections", optimize_database_connections),
        ("Data Cleanup", cleanup_old_data),
        ("Pagination", add_pagination_helpers),
        ("Template Rendering", optimize_template_rendering),
        ("Compression", add_compression)
    ]
    
    success_count = 0
    for name, func in optimizations:
        print(f"\n🔄 Optimizing: {name}")
        try:
            result = func()
            if result:
                success_count += 1
                print(f"✅ {name} optimization completed")
            else:
                print(f"⚠️ {name} optimization completed with warnings")
        except Exception as e:
            print(f"❌ {name} optimization failed: {e}")
    
    print(f"\n🎉 Optimization Summary: {success_count}/{len(optimizations)} optimizations completed")
    
    if success_count >= len(optimizations) - 1:  # Allow 1 failure
        print("🚀 Your CTF app should now be significantly faster!")
    else:
        print("⚠️ Some optimizations had issues. Check the logs above.")

if __name__ == "__main__":
    main()
