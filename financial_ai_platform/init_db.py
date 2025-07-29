#!/usr/bin/env python3
"""
Initialize database with demo user
"""

from web_app.app import create_app
from database.models import db, User
from werkzeug.security import generate_password_hash

def init_database():
    app = create_app()
    with app.app_context():
        # Create all tables
        db.create_all()

        # Check for demo user
        existing = User.query.filter_by(username='demo').first()
        if not existing:
            demo_user = User(
                username='demo',
                email='demo@financialai.com',
                phone_number='2222222222',
                full_name='Demo User',
                password_hash=generate_password_hash('password')
            )
            db.session.add(demo_user)
            db.session.commit()
            print("✅ Demo user created.")
        else:
            print("ℹ️ Demo user already exists.")

if __name__ == "__main__":
    init_database()
