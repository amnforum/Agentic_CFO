#!/usr/bin/env python3
"""
Database models for Financial AI Platform
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import json

# Initialize SQLAlchemy
db = SQLAlchemy()

class User(db.Model):
    """User model for authentication and profile management"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(15), nullable=True)
    full_name = db.Column(db.String(200), nullable=True)
    
    # Account status
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    chat_sessions = db.relationship('ChatSession', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'phone_number': self.phone_number,
            'full_name': self.full_name,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }
    
    def __repr__(self):
        return f'<User {self.username}>'

class ChatSession(db.Model):
    """Chat sessions with AI agents"""
    __tablename__ = 'chat_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Chat data
    query = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=False)
    
    # Agent information
    selected_agents = db.Column(db.Text, nullable=True)  # JSON array of agent names
    confidence_score = db.Column(db.Float, nullable=True)
    processing_time = db.Column(db.Float, nullable=True)  # seconds
    
    # Context and metadata
    user_context = db.Column(db.Text, nullable=True)  # JSON string
    session_id = db.Column(db.String(100), nullable=True)  # For grouping related chats
    
    # Timestamps
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f'<ChatSession {self.id} user_id={self.user_id}>'
    
    
#***************implemenation of ITR Agent ************************
# database/models.py  (add after ChatSession)
class TaxReturn(db.Model):
    """Tax return filings and calculations"""
    __tablename__ = 'tax_returns'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Tax year information
    assessment_year = db.Column(db.String(10), nullable=False)  # 2025-26
    financial_year = db.Column(db.String(10), nullable=False)   # 2024-25
    
    # Tax calculation results
    gross_income = db.Column(db.Float, nullable=True)
    taxable_income = db.Column(db.Float, nullable=True)
    total_tax_payable = db.Column(db.Float, nullable=True)
    
    # ITR data
    itr_json = db.Column(db.Text, nullable=True)  # Complete ITR JSON
    filing_status = db.Column(db.String(20), default='draft')  # draft, filed, processed
    
    # AI recommendations
    optimization_suggestions = db.Column(db.Text, nullable=True)  # JSON string
    ai_summary = db.Column(db.Text, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    filed_at = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<TaxReturn {self.assessment_year} user_id={self.user_id}>'

    


# Database initialization function
def init_db(app):
    """Initialize database with app"""
    db.init_app(app)
    
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Create demo user if it doesn't exist
        demo_user = User.query.filter_by(username='demo').first()
        if not demo_user:
            demo_user = User(
                username='demo',
                email='demo@financialai.com',
                phone_number='2222222222',  # Fi MCP test scenario
                full_name='Demo User'
            )
            demo_user.set_password('password')
            db.session.add(demo_user)
        
        try:
            db.session.commit()
            print("✅ Database initialized successfully with demo user")
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error initializing database: {e}")
