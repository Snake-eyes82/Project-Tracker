from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime, Enum, UniqueConstraint
from sqlalchemy.orm import relationship, sessionmaker, session
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from enum import Enum as PyEnum # Correct import here
from werkzeug.security import generate_password_hash  # Import for hashing
from itertools import zip_longest

Base = declarative_base()


class Milestone(Base):
    """Represents a project milestone."""
    __tablename__ = 'milestones'
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('projects.id'))
    title = Column(String(255), nullable=False)
    description = Column(String(1000))
    due_date = Column(DateTime)
    completed = Column(Boolean, default=False)
    project = relationship('Project', backref='milestones')


class ProjectMemberRole(PyEnum):  # Use Python's Enum here
    """Defines roles for project members."""
    OWNER = 'owner'
    ADMIN = 'admin'
    MEMBER = 'member'
    VIEWER = 'viewer'

class ProjectMember(Base):
    """Represents a project member."""
    __tablename__ = 'project_members'
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('projects.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    role = Column(Enum(ProjectMemberRole), default=ProjectMemberRole.MEMBER)  # Use SQLAlchemy's Enum here
    project = relationship('Project', backref='members')
    user = relationship('User', backref='project_members')


class User(Base):
    """Represents a user in the system."""
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)  # Add length and nullable
    password = Column(String(128), nullable=False)  # Adjust length for hashed password
    email = Column(String(120), unique=True, nullable=False)  # Add length and nullable
    role = Column(String(20), default='user')
    reset_token = Column(String(255), nullable=True)
    reset_token_expiration = Column(DateTime, nullable=True)
    projects = relationship('Project', back_populates='owner')
    issues_created = relationship('Issue', foreign_keys='Issue.creator_id', back_populates='creator')
    issues_assigned = relationship('Issue', foreign_keys='Issue.assignee_id', back_populates='assignee')

    def set_password(self, password):
        """Hashes and sets the user's password."""
        self.password = generate_password_hash(password)


class Project(Base):
    """Represents a project."""
    __tablename__ = 'projects'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)  # Add length and nullable
    description = Column(String(1000))
    owner_id = Column(Integer, ForeignKey('users.id'))
    owner = relationship('User', back_populates='projects')
    issues = relationship('Issue', back_populates='project')


class ProjectStatus(PyEnum):
    """Defines project statuses."""
    OPEN = 'open'
    IN_PROGRESS = 'in_progress'
    COMPLETED = 'completed'
    ON_HOLD = 'on_hold'


class Issue(Base):
    """Represents an issue within a project."""
    __tablename__ = 'issues'
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('projects.id'))
    title = Column(String(255), nullable=False)  # Add length and nullable
    description = Column(String(1000))
    status = Column(String(50))
    assignee_id = Column(Integer, ForeignKey('users.id'))
    creator_id = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    project = relationship('Project', back_populates='issues')
    assignee = relationship('User', foreign_keys='Issue.assignee_id', back_populates='issues_assigned')
    creator = relationship('User', foreign_keys='Issue.creator_id', back_populates='issues_created')