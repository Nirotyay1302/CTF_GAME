#!/usr/bin/env python3
"""
New Features for CTF Application
This file contains new routes and features to add to your CTF app
"""

from flask import render_template, request, jsonify, session, redirect, url_for, flash
from datetime import datetime, timedelta
import json

# Add these routes to your CTF_GAME.py file

def add_api_endpoints():
    """
    Add these API endpoints to your CTF_GAME.py file
    """
    
    # API endpoint for live statistics
    @app.route('/api/stats')
    def api_stats():
        """Get live statistics for the CTF"""
        try:
            stats = {
                'total_users': User.query.count(),
                'total_challenges': Challenge.query.count(),
                'total_solves': Solve.query.count(),
                'active_teams': Team.query.count(),
                'online_users': User.query.filter(User.last_seen > datetime.utcnow() - timedelta(minutes=15)).count(),
                'recent_solves': Solve.query.filter(Solve.timestamp > datetime.utcnow() - timedelta(hours=1)).count()
            }
            return jsonify(stats)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # API endpoint for challenge hints
    @app.route('/api/challenge/<int:challenge_id>/hint')
    def get_challenge_hint(challenge_id):
        """Get hint for a specific challenge"""
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        challenge = Challenge.query.get_or_404(challenge_id)
        
        # Basic hint system - you can expand this
        hints = {
            'easy': 'Try looking at the challenge description more carefully.',
            'medium': 'Consider what tools might be useful for this type of challenge.',
            'hard': 'Break down the problem into smaller parts.'
        }
        
        hint = hints.get(challenge.difficulty, 'No hint available for this challenge.')
        
        return jsonify({
            'hint': hint,
            'challenge_title': challenge.title,
            'difficulty': challenge.difficulty
        })
    
    # API endpoint for user progress
    @app.route('/api/user/progress')
    def user_progress():
        """Get current user's progress"""
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        user = User.query.get(user_id)
        
        # Get user's solves
        solves = Solve.query.filter_by(user_id=user_id).all()
        solved_challenges = [solve.challenge_id for solve in solves]
        
        # Get all challenges
        all_challenges = Challenge.query.all()
        
        # Calculate progress by category
        progress_by_category = {}
        for challenge in all_challenges:
            category = challenge.category
            if category not in progress_by_category:
                progress_by_category[category] = {'total': 0, 'solved': 0}
            
            progress_by_category[category]['total'] += 1
            if challenge.id in solved_challenges:
                progress_by_category[category]['solved'] += 1
        
        # Calculate percentages
        for category in progress_by_category:
            total = progress_by_category[category]['total']
            solved = progress_by_category[category]['solved']
            progress_by_category[category]['percentage'] = (solved / total * 100) if total > 0 else 0
        
        return jsonify({
            'user': user.username,
            'total_points': user.total_points,
            'challenges_solved': len(solved_challenges),
            'total_challenges': len(all_challenges),
            'progress_by_category': progress_by_category,
            'recent_solves': [
                {
                    'challenge_title': Challenge.query.get(solve.challenge_id).title,
                    'points': Challenge.query.get(solve.challenge_id).points,
                    'timestamp': solve.timestamp.isoformat()
                }
                for solve in solves[-5:]  # Last 5 solves
            ]
        })

def add_enhanced_features():
    """
    Enhanced features to add to your CTF application
    """
    
    # Enhanced leaderboard with filters
    @app.route('/leaderboard/advanced')
    def advanced_leaderboard():
        """Advanced leaderboard with filtering options"""
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        # Get filter parameters
        time_filter = request.args.get('time', 'all')  # all, day, week, month
        category_filter = request.args.get('category', 'all')
        
        # Base query
        query = User.query
        
        # Apply time filter
        if time_filter != 'all':
            time_delta = {
                'day': timedelta(days=1),
                'week': timedelta(weeks=1),
                'month': timedelta(days=30)
            }
            cutoff_time = datetime.utcnow() - time_delta[time_filter]
            
            # Get users who solved challenges in the time period
            recent_solvers = db.session.query(Solve.user_id).filter(
                Solve.timestamp >= cutoff_time
            ).distinct().subquery()
            
            query = query.filter(User.id.in_(recent_solvers))
        
        users = query.order_by(User.total_points.desc()).limit(50).all()
        
        # Get categories for filter dropdown
        categories = db.session.query(Challenge.category).distinct().all()
        categories = [cat[0] for cat in categories]
        
        return render_template('advanced_leaderboard.html', 
                             users=users, 
                             categories=categories,
                             current_time_filter=time_filter,
                             current_category_filter=category_filter)
    
    # Challenge search and filter
    @app.route('/challenges/search')
    def search_challenges():
        """Search and filter challenges"""
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        search_query = request.args.get('q', '')
        category_filter = request.args.get('category', '')
        difficulty_filter = request.args.get('difficulty', '')
        solved_filter = request.args.get('solved', '')  # solved, unsolved, all
        
        # Base query
        query = Challenge.query
        
        # Apply search
        if search_query:
            query = query.filter(
                Challenge.title.contains(search_query) |
                Challenge.description.contains(search_query)
            )
        
        # Apply category filter
        if category_filter:
            query = query.filter(Challenge.category == category_filter)
        
        # Apply difficulty filter
        if difficulty_filter:
            query = query.filter(Challenge.difficulty == difficulty_filter)
        
        challenges = query.all()
        
        # Apply solved filter
        if solved_filter and 'user_id' in session:
            user_solves = [solve.challenge_id for solve in 
                          Solve.query.filter_by(user_id=session['user_id']).all()]
            
            if solved_filter == 'solved':
                challenges = [c for c in challenges if c.id in user_solves]
            elif solved_filter == 'unsolved':
                challenges = [c for c in challenges if c.id not in user_solves]
        
        # Get filter options
        categories = db.session.query(Challenge.category).distinct().all()
        categories = [cat[0] for cat in categories]
        
        difficulties = db.session.query(Challenge.difficulty).distinct().all()
        difficulties = [diff[0] for diff in difficulties]
        
        return render_template('challenge_search.html',
                             challenges=challenges,
                             categories=categories,
                             difficulties=difficulties,
                             search_query=search_query,
                             category_filter=category_filter,
                             difficulty_filter=difficulty_filter,
                             solved_filter=solved_filter)
    
    # Team statistics
    @app.route('/team/<int:team_id>/stats')
    def team_statistics(team_id):
        """Detailed team statistics"""
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        team = Team.query.get_or_404(team_id)
        
        # Get team members
        members = User.query.filter_by(team_id=team_id).all()
        
        # Get team solves
        team_solves = Solve.query.filter(Solve.user_id.in_([m.id for m in members])).all()
        
        # Calculate statistics
        stats = {
            'total_points': sum(member.total_points for member in members),
            'total_solves': len(team_solves),
            'challenges_by_category': {},
            'solves_over_time': [],
            'top_solver': max(members, key=lambda m: m.total_points) if members else None,
            'recent_activity': team_solves[-10:]  # Last 10 solves
        }
        
        # Group solves by category
        for solve in team_solves:
            challenge = Challenge.query.get(solve.challenge_id)
            category = challenge.category
            if category not in stats['challenges_by_category']:
                stats['challenges_by_category'][category] = 0
            stats['challenges_by_category'][category] += 1
        
        return render_template('team_stats.html', team=team, members=members, stats=stats)

def add_admin_features():
    """
    Enhanced admin features
    """
    
    # Bulk challenge management
    @app.route('/admin/challenges/bulk', methods=['GET', 'POST'])
    def bulk_challenge_management():
        """Bulk operations on challenges"""
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Unauthorized', 'error')
            return redirect(url_for('admin_panel'))
        
        if request.method == 'POST':
            action = request.form.get('action')
            challenge_ids = request.form.getlist('challenge_ids')
            
            if action == 'delete':
                for challenge_id in challenge_ids:
                    challenge = Challenge.query.get(challenge_id)
                    if challenge:
                        db.session.delete(challenge)
                flash(f'Deleted {len(challenge_ids)} challenges', 'success')
            
            elif action == 'update_category':
                new_category = request.form.get('new_category')
                for challenge_id in challenge_ids:
                    challenge = Challenge.query.get(challenge_id)
                    if challenge:
                        challenge.category = new_category
                flash(f'Updated category for {len(challenge_ids)} challenges', 'success')
            
            elif action == 'update_difficulty':
                new_difficulty = request.form.get('new_difficulty')
                for challenge_id in challenge_ids:
                    challenge = Challenge.query.get(challenge_id)
                    if challenge:
                        challenge.difficulty = new_difficulty
                flash(f'Updated difficulty for {len(challenge_ids)} challenges', 'success')
            
            db.session.commit()
            return redirect(url_for('bulk_challenge_management'))
        
        challenges = Challenge.query.all()
        categories = db.session.query(Challenge.category).distinct().all()
        difficulties = db.session.query(Challenge.difficulty).distinct().all()
        
        return render_template('admin_bulk_challenges.html',
                             challenges=challenges,
                             categories=[cat[0] for cat in categories],
                             difficulties=[diff[0] for diff in difficulties])
    
    # System health monitoring
    @app.route('/admin/system/health')
    def system_health():
        """System health monitoring"""
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Unauthorized', 'error')
            return redirect(url_for('admin_panel'))
        
        health_data = {
            'database_status': 'healthy',
            'total_users': User.query.count(),
            'active_sessions': len([u for u in User.query.all() 
                                  if u.last_seen and u.last_seen > datetime.utcnow() - timedelta(minutes=15)]),
            'recent_errors': [],  # You can implement error logging
            'disk_usage': 'N/A',  # Implement if needed
            'memory_usage': 'N/A',  # Implement if needed
            'uptime': 'N/A'  # Implement if needed
        }
        
        return render_template('admin_health.html', health_data=health_data)

# Usage instructions:
"""
To add these features to your CTF app:

1. Copy the route functions from this file into your CTF_GAME.py
2. Create the corresponding HTML templates
3. Update your navigation to include links to new features
4. Test each feature thoroughly

New features included:
- Live statistics API
- Challenge hints system
- User progress tracking
- Advanced leaderboard with filters
- Challenge search and filtering
- Team statistics
- Bulk challenge management
- System health monitoring
"""
