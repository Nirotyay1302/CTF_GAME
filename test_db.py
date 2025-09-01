from main import app, db
from models import User, Challenge, Hint

with app.app_context():
    # Check admin users
    admin_users = User.query.filter_by(role='admin').all()
    print('Admin users:', [u.username for u in admin_users])
    
    # Check regular users
    regular_users = User.query.filter_by(role='user').all()
    print('Regular users:', [u.username for u in regular_users])
    
    # Check challenges
    challenges = Challenge.query.all()
    print('Total challenges:', len(challenges))
    print('Challenge categories:', set([c.category for c in challenges]))
    
    # Check hints
    hints = Hint.query.all()
    print('Total hints:', len(hints))
    
    # Check admin permissions
    admin = User.query.filter_by(username='admin').first()
    print('Admin exists:', admin is not None)
    if admin:
        print('Admin role:', admin.role)
        print('Admin is_active:', admin.is_active)