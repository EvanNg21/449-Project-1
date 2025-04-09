from flask import Flask, request, jsonify, session
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, InventoryItem
import re
from datetime import timedelta
import time

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey' # Flask session encryption key
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # session expiration time (30min)
Session(app)
db.init_app(app)

with app.app_context():
    db.create_all()

# ------------------------------------------------------------
# User login and Admin login 
# ------------------------------------------------------------

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json

     # Checks for missing fields
    if not all(field in data for field in ['username', 'email', 'password']):
        return jsonify({"error": "Missing required fields"}), 400

    # Validates email format
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, data['email']):
        return jsonify({"error": "Invalid email format"}), 400

    # Validates password strength
    if len(data['password']) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400
    if not re.search(r'\d', data['password']):
        return jsonify({"error": "Password must contain at least one digit."}), 400
    if not re.search(r'[A-Z]', data['password']):
        return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
    if not re.search(r'[a-z]', data['password']):
        return jsonify({"error": "Password must contain at least one lowercase letter."}), 400
    if not re.search(r'[\W_]', data['password']):
        return jsonify({"error": "Password must contain at least one special character."}), 400

    # Checks if username or email is already taken
    existing_user = User.query.filter(
        (User.username == data['username']) | (User.email == data['email'])
    ).first()
    if existing_user:
        return jsonify({"error": "Username or Email already registered"}), 409

    # Hashes the password
    hashed_password = generate_password_hash(data['password'])

    # Creates new user
    new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully!"}), 201


# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()

    if user and check_password_hash(user.password_hash, data['password']):
        session['user_id'] = user.id
        session['username'] = user.username
        session['last_activity'] = time.time()  # Store the last activity timestamp
        return jsonify({"message": "Login successful!"})
    return jsonify({"error": "Invalid credentials"}), 401


# Logout
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('last_activity', None)  # Remove last activity timestamp
    return jsonify({"message": "User logged out successfully!"})


# ------------------------------------------------------------
# Admin-Specific Inventory Management
# ------------------------------------------------------------

# ------------------------------------------------------------
# Placeholder: To be implemented!
# ------------------------------------------------------------


# ------------------------------------------------------------
# Session and Cookie Security
# ------------------------------------------------------------

@app.route('/session', methods=['GET'])
def get_session():
    # Check session expiration (if more than 30 minutes have passed since last activity)
    if 'last_activity' in session:
        if time.time() - session['last_activity'] > 30 * 60:  # If 30 minutes have passed, session will be expired
            session.pop('user_id', None)
            session.pop('username', None)
            session.pop('last_activity', None)
            return jsonify({"message": "Session expired. Please log in again."}), 401
        session['last_activity'] = time.time()  # Update the last activity timestamp
        return jsonify({
            "message": "User is logged in",
            "user_id": session['user_id'],
            "username": session['username']
        })
    return jsonify({"message": "User is not logged in"}), 401


# Protected Route (requires login)
@app.route('/logged_in', methods=['GET'])
def show_logged_in_page():
    # Check if session is expired or user is not logged in
    if 'user_id' not in session or (time.time() - session.get('last_activity', 0)) > 30 * 60:
        return jsonify({"message": "Please log in first"}), 401
    session['last_activity'] = time.time()  # Update the last activity timestamp
    return jsonify({"message": "Welcome! You are logged in."})

# ------------------------------------------------------------
# Placeholder: To be implemented!
# ------------------------------------------------------------

# ------------------------------------------------------------
# Run the Flask App
# ------------------------------------------------------------

if __name__ == '__main__':
    app.run(debug=True)