from flask import Blueprint, request, jsonify, render_template
from werkzeug.security import generate_password_hash
import re
from models import db, User

register_bp = Blueprint('register', __name__)

@register_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('Register.html')

    try:
        data = request.json

        # Checks for missing fields
        if not all(field in data for field in ['username', 'email', 'password']):
            return jsonify({"error": "Missing required fields"}), 400

        # Validate email format
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, data['email']):
            return jsonify({"error": "Invalid email format"}), 400

        # Validate password strength
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

        # Check if username or email is already taken
        existing_user = User.query.filter((User.username == data['username']) | (User.email == data['email'])).first()
        if existing_user:
            return jsonify({"error": "Username or Email already registered"}), 409

        # Hash the password
        hashed_password = generate_password_hash(data['password'])

        # Creates new user
        new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            "message": "User registered successfully!",
            "username": new_user.username,
            "id": new_user.id
        }), 201

    except Exception as e:
        return jsonify({"error": "Internal Server Error"}), 500