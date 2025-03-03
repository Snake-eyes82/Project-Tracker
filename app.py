from dotenv import load_dotenv
import secrets
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os
import smtplib
from email.mime.text import MIMEText
from flask import Flask, jsonify, request, send_from_directory, url_for
from sqlalchemy import create_engine
from models_temp import Base, User, Project, Issue, ProjectStatus, ProjectMember, ProjectMemberRole
from werkzeug.security import generate_password_hash, check_password_hash
import re
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import base64

app = Flask(__name__, static_folder='static')
secret_key = secrets.token_hex(16)
print(secret_key)

load_dotenv()

app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise ValueError("FLASK_SECRET_KEY environment variable is not set.")

DATABASE_URI = 'sqlite:///mydatabase.db'
engine = create_engine(DATABASE_URI)
Base.metadata.create_all(engine)
print("Database tables created!")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
            else:
                return jsonify({'message': 'Invalid authorization format. Must be Bearer <token>.'}), 401
        else:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = engine.connect().execute(User.__table__.select().where(User.id == data['user_id'])).fetchone()
            if current_user is None:
                return jsonify({'message': 'User not found!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
        except Exception as e:
            return jsonify({'message': f'Error decoding token: {str(e)}'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/api/projects/<int:project_id>/status', methods=['PUT'])
@token_required
def update_project_status(current_user, project_id):
    data = request.get_json()
    status = data.get('status')
    try:
        project = engine.connect().execute(Project.__table__.select().where(Project.id == project_id)).fetchone()
        if not project:
            return jsonify({'message': 'Project not found'}), 404
        project_member = engine.connect().execute(ProjectMember.__table__.select().where((ProjectMember.project_id == project_id) & (ProjectMember.user_id == current_user.id))).fetchone()
        if not project_member or project_member.role not in [ProjectMemberRole.OWNER, ProjectMemberRole.ADMIN]:
            return jsonify({'message': 'Unauthorized'}), 403
        try:
            status_enum = ProjectStatus(status)
        except ValueError:
            return jsonify({'message': 'Invalid status'}), 400
        engine.connect().execute(Project.__table__.update().where(Project.id == project_id).values(status=status_enum))
        return jsonify({'message': 'Project status updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': f'Error updating project status: {str(e)}'}), 500

@app.route('/api/users/reset-password-request', methods=['POST'])
def reset_password_request():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'message': 'Email is required'}), 400
    try:
        user = engine.connect().execute(User.__table__.select().where(User.email == email)).fetchone()
        if user:
            reset_token = secrets.token_urlsafe(32)
            engine.connect().execute(User.__table__.update().where(User.id == user.id).values(reset_token=reset_token, reset_token_expiration=datetime.utcnow() + timedelta(hours=1)))
            reset_link = url_for('reset_password', token=reset_token, _external=True)
            message = MIMEText(f'Click the following link to reset your password: {reset_link}')
            message['Subject'] = 'Password Reset Request'
            message['From'] = os.environ.get('SENDER_EMAIL')
            message['To'] = email
            try:
                with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                    server.login(os.environ.get('SENDER_EMAIL'), os.environ.get('SENDER_PASSWORD'))
                    server.send_message(message)
                return jsonify({'message': 'Password reset link sent to your email'}), 200
            except Exception as e:
                print(f"Email sending error: {e}")
                return jsonify({'message': 'Failed to send password reset email'}), 500
        else:
            return jsonify({'message': 'User with this email not found'}), 404
    except Exception as e:
        return jsonify({'message': f'Error processing reset request: {str(e)}'}), 500

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'GET':
        return 'Enter your new password'
    else:
        data = request.get_json()
        new_password = data.get('password')
        if not new_password:
            return jsonify({'message': 'Password is required'}), 400
        try:
            user = engine.connect().execute(User.__table__.select().where(User.reset_token == token)).fetchone()
            if user and user.reset_token_expiration > datetime.utcnow():
                engine.connect().execute(User.__table__.update().where(User.id == user.id).values(password=generate_password_hash(new_password), reset_token=None, reset_token_expiration=None))
                return jsonify({'message': 'Password reset successful'}), 200
            else:
                return jsonify({'message': 'Invalid or expired token'}), 400
        except Exception as e:
            return jsonify({'message': f'Error resetting password: {str(e)}'}), 500

@app.route('/api/users/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    print(f"Received login request: username={username}, password={password}")
    if not username or not password:
        return jsonify({'message': 'Missing required fields'}), 400
    try:
        user = engine.connect().execute(User.__table__.select().where(User.username == username)).fetchone()
        if user and check_password_hash(user.password, password):
            token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(minutes=30)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            return jsonify({'token': token, 'user_id': user.id}), 200
        else:
            return jsonify({'message': 'Invalid username or password'}), 401
    except Exception as e:
        print(f"Error during login: {e}")
        return jsonify({'message': 'An error occurred during login'}), 500

@app.route('/api/projects', methods=['POST'])
@token_required
def create_project(current_user):
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    if not name:
        return jsonify({'message': 'Missing required fields'}), 400
    try:
        new_project = Project(name=name, description = description, owner_id=current_user.id)
        engine.connect().execute(Project.__table__.insert().values(name=new_project.name, description=new_project.description, owner_id=new_project.owner_id))

        result = engine.connect().execute(Project.__table__.select().order_by(Project.id.desc()).limit(1)).fetchone()
        new_project_id = result.id

        new_member = ProjectMember(project_id=new_project_id, user_id=current_user.id, role=ProjectMemberRole.OWNER)
        engine.connect().execute(ProjectMember.__table__.insert().values(project_id=new_member.project_id, user_id=new_member.user_id, role=new_member.role))

        return jsonify({'message': 'Project created successfully'}), 201

    except Exception as e:
        return jsonify({'message': f'Error creating project: {str(e)}'}), 500
    finally:
        print("Project created successfully!")

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/users/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    if not username or not password or not email:
        return jsonify({'message': 'Missing required fields'}), 400
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'message': 'Invalid email format'}), 400
    if len(password) < 8:
        return jsonify({'message': 'Password must be at least 8 characters long'}), 400

    try:
        user_exists = engine.connect().execute(User.__table__.select().where(User.username == username)).fetchone()
        if user_exists:
            return jsonify({'message': 'Username already exists'}), 400
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        engine.connect().execute(User.__table__.insert().values(username=new_user.username, email=new_user.email, password=new_user.password))

        receiver_email = email
        sender_email = os.environ.get('SENDER_EMAIL')
        try:
            creds = None
            if os.path.exists('token.json'):
                creds = Credentials.from_authorized_user_file('token.json', ['https://mail.google.com/'])
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    flow = InstalledAppFlow.from_client_secrets_file('credentials.json', ['https://mail.google.com/'])
                    creds = flow.run_local_server(port=0)
                with open('token.json', 'w') as token:
                    token.write(creds.to_json())
            service = build('gmail', 'v1', credentials=creds)
            message = MIMEText(f'Thank you for registering, {username}!')
            message['Subject'] = 'Registration Confirmation'
            message['To'] = receiver_email
            message['From'] = sender_email
            print("Receiver email: ", receiver_email)
            print("Sender email: ", sender_email)
            raw_message = (message.as_string()).encode('utf-8')
            raw_message = base64.urlsafe_b64encode(raw_message).decode('utf-8')
            message_body = {'raw': raw_message}
            message = (service.users().messages().send(userId='me', body=message_body).execute())
            return jsonify({'message': 'User registered successfully. Confirmation email sent.'}), 201
        except HttpError as error:
            print(f'An error occurred: {error}')
            return jsonify({'message': 'User registered successfully, but email confirmation failed.'}), 201
        except Exception as email_error:
            print(f'Email sending error: {email_error}')
            return jsonify({'message': 'User registered successfully, but email confirmation failed.'}), 201
        except Exception as db_error:
            return jsonify({'message': f'Database error: {str(db_error)}'}), 500
    except Exception as e:
        return jsonify({'message': f'Error during registration: {str(e)}'}), 500

@app.route('/api/projects', methods=['GET'])
def get_projects():
    try:
        projects = engine.connect().execute(Project.__table__.select()).fetchall()
        project_list = [{'id': p.id, 'name': p.name, 'description': p.description, 'owner_id': p.owner_id} for p in projects]
        return jsonify(project_list), 200
    except Exception as e:
        return jsonify({'message': f'Error fetching projects: {str(e)}'}), 500

@app.route('/api/projects/<int:project_id>', methods=['DELETE'])
@token_required
def delete_project(current_user, project_id):
    print(f"Attempting to delete project ID: {project_id}")
    print(f"Current user ID: {current_user.id}")
    try:
        project = engine.connect().execute(Project.__table__.select().where((Project.id == project_id) & (Project.owner_id == current_user.id))).fetchone()
        if project is None:
            print("Project not found!")
            return jsonify({'message': 'Project not found!'}), 404
        print(f"Project found: {project.name}")
        engine.connect().execute(Project.__table__.delete().where(Project.id == project_id))
        print("Project deleted from database")
        return jsonify({'message': 'Project deleted successfully!'}), 200
    except Exception as e:
        print(f"Error during deletion: {e}")
        return jsonify({'message': f'Error deleting project: {str(e)}'}), 500
    finally:
        print("Deletion process completed")

@app.route('/api/projects/<int:project_id>/issues', methods=['POST'])
def create_issue(project_id):
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    creator_id = data.get('creator_id')
    if not title or not creator_id:
        return jsonify({'message': 'Missing required fields'}), 400
    try:
        new_issue = Issue(project_id=project_id, title=title, description=description, creator_id=creator_id, status='Open')
        engine.connect().execute(Issue.__table__.insert().values(project_id=new_issue.project_id, title=new_issue.title, description=new_issue.description, creator_id=new_issue.creator_id, status=new_issue.status))
        return jsonify({'message': 'Issue created successfully'}), 201
    except Exception as e:
        return jsonify({'message': f'Error creating issue: {str(e)}'}), 500

@app.route('/api/projects/<int:project_id>/issues', methods=['GET'])
def get_issues(project_id):
    try:
        issues = engine.connect().execute(Issue.__table__.select().where(Issue.project_id == project_id)).fetchall()
        issue_list = [{'id': i.id, 'title': i.title, 'description': i.description, 'status': i.status, 'assignee_id': i.assignee_id, 'creator_id': i.creator_id, 'created_at': i.created_at, 'updated_at': i.updated_at} for i in issues]
        return jsonify(issue_list), 200
    except Exception as e:
        return jsonify({'message': f'Error fetching issues: {str(e)}'}), 500

@app.route('/api/issues/<int:issue_id>', methods=['PUT'])
def update_issue(issue_id):
    data = request.get_json()
    status = data.get('status')
    assignee_id = data.get('assignee_id')
    try:
        issue = engine.connect().execute(Issue.__table__.select().where(Issue.id == issue_id)).fetchone()
        if not issue:
            return jsonify({'message': 'Issue not found'}), 404
        update_values = {}
        if status:
            update_values['status'] = status
        if assignee_id:
            update_values['assignee_id'] = assignee_id
        if update_values:
            engine.connect().execute(Issue.__table__.update().where(Issue.id == issue_id).values(update_values))
        return jsonify({'message': 'Issue updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': f'Error updating issue: {str(e)}'}), 500

@app.route('/api/issues/<int:issue_id>', methods=['DELETE'])
def delete_issue(issue_id):
    try:
        issue = engine.connect().execute(Issue.__table__.select().where(Issue.id == issue_id)).fetchone()
        if not issue:
            return jsonify({'message': 'Issue not found'}), 404
        engine.connect().execute(Issue.__table__.delete().where(Issue.id == issue_id))
        return jsonify({'message': 'Issue deleted successfully'}), 200
    except Exception as e:
        return jsonify({'message': f'Error deleting issue: {str(e)}'}), 500

@app.route('/api/projects/<int:project_id>/members', methods=['POST'])
@token_required
def add_project_member(current_user, project_id):
    data = request.get_json()
    username = data.get('username')
    role = data.get('role')

    print(f"Adding member: username={username}, role={role}")
    print(f"received role: {role}")

    try:
        project = engine.connect().execute(Project.__table__.select().where(Project.id == project_id)).fetchone()
        if not project:
            return jsonify({'message': 'Project not found'}), 404

        user = engine.connect().execute(User.__table__.select().where(User.username == username)).fetchone()
        if not user:
            return jsonify({'message': 'User not found'}), 404

        existing_member = engine.connect().execute(ProjectMember.__table__.select().where((ProjectMember.project_id == project_id) & (ProjectMember.user_id == user.id))).fetchone()
        if existing_member:
            return jsonify({'message': 'User is already a member of this project'}), 400

        try:
            member_role = ProjectMemberRole(role)
        except ValueError:
            return jsonify({'message': 'Invalid role'}), 400

        current_member = engine.connect().execute(ProjectMember.__table__.select().where((ProjectMember.project_id == project_id) & (ProjectMember.user_id == current_user.id))).fetchone()
        if not current_member or current_member.role not in [ProjectMemberRole.OWNER, ProjectMemberRole.ADMIN]:
            return jsonify({'message': 'You do not have permission to add members'}), 403

        new_member = ProjectMember(project_id=project_id, user_id=user.id, role=member_role)
        engine.connect().execute(ProjectMember.__table__.insert().values(project_id=new_member.project_id, user_id=new_member.user_id, role=new_member.role))

        return jsonify({'message': 'Member added successfully'}), 201

    except Exception as e:
        return jsonify({'message': f'Error adding member: {str(e)}'}), 500

@app.route('/api/projects/<int:project_id>/members/<int:member_id>', methods=['PUT'])
@token_required
def update_project_member(current_user, project_id, member_id):
    data = request.get_json()
    role = data.get('role')

    try:
        current_member = engine.connect().execute(ProjectMember.__table__.select().where((ProjectMember.project_id == project_id) & (ProjectMember.user_id == current_user.id))).fetchone()
        if not current_member or current_member.role != ProjectMemberRole.OWNER:
            return jsonify({'message': 'You do not have permission to update member roles'}), 403

        member_to_update = engine.connect().execute(ProjectMember.__table__.select().where((ProjectMember.project_id == project_id) & (ProjectMember.user_id == member_id))).fetchone()
        if not member_to_update:
            return jsonify({'message': 'Member not found'}), 404

        try:
            member_role = ProjectMemberRole(role)
        except ValueError:
            return jsonify({'message': 'Invalid role'}), 400

        engine.connect().execute(ProjectMember.__table__.update().where((ProjectMember.project_id == project_id) & (ProjectMember.user_id == member_id)).values(role=member_role))

        return jsonify({'message': 'Member role updated successfully'}), 200

    except Exception as e:
        return jsonify({'message': f'Error updating member role: {str(e)}'}), 500

@app.route('/api/projects/<int:project_id>/members/<int:member_id>', methods=['DELETE'])
@token_required
def delete_project_member(current_user, project_id, member_id):
    try:
        current_member = engine.connect().execute(ProjectMember.__table__.select().where((ProjectMember.project_id == project_id) & (ProjectMember.user_id == current_user.id))).fetchone()
        if not current_member or current_member.role != ProjectMemberRole.OWNER:
            return jsonify({'message': 'You do not have permission to delete members'}), 403

        member_to_delete = engine.connect().execute(ProjectMember.__table__.select().where((ProjectMember.project_id == project_id) & (ProjectMember.user_id == member_id))).fetchone()
        if not member_to_delete:
            return jsonify({'message': 'Member not found'}), 404

        engine.connect().execute(ProjectMember.__table__.delete().where((ProjectMember.project_id == project_id) & (ProjectMember.user_id == member_id)))

        return jsonify({'message': 'Member deleted successfully'}), 200

    except Exception as e:
        return jsonify({'message': f'Error deleting member: {str(e)}'}), 500

@app.route('/api/users/search', methods=['GET'])
def search_users():
    query = request.args.get('query')
    print(f'Search query: {query}')
    if not query:
        return jsonify({'message': 'Search query is required'}), 400
    try:
        users = engine.connect().execute(User.__table__.select().where((User.username.like(f'%{query}%')) | (User.email.like(f'%{query}%')))).fetchall()
        user_list = [{'id': u.id, 'username': u.username, 'email': u.email} for u in users]
        print(f'search results: {user_list}')
        return jsonify(user_list), 200
    except Exception as e:
        return jsonify({'message': f'Error searching users: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)