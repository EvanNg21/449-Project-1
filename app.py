from flask import Flask, request, jsonify, session
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, InventoryItem
import re
from datetime import timedelta
import time
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey' # Flask session encryption key
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # session expiration time (30min)
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'

Session(app)
db.init_app(app)
jwt = JWTManager(app)

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

#Admin Login (JWT-based)
@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"msg": "Bad credentials"}), 401
    
    if user.role != "admin":
        return jsonify({"msg": "Not authorized. Admins only."}), 403

    # Create and return a JWT token with admin details in the payload.
    access_token = create_access_token(identity={'id': user.id, 'username': user.username, 'role': user.role})
    return jsonify(access_token=access_token), 200

# ------------------------------------------------------------
# Admin-Specific Inventory Management (JWT-protected)
# ------------------------------------------------------------
@app.route('/admin/inventory', methods=['GET'])
@jwt_required()
def get_admin_inventory():
    current_user = get_jwt_identity()  # Current user details from JWT payload
    if current_user['role'] != 'admin':
        return jsonify({"msg": "Admins only."}), 403

    admin_items = InventoryItem.query.filter_by(admin_id=current_user['id']).all()
    items = []
    for item in admin_items:
        items.append({
            "id": item.id,
            "name": item.name,
            "description": item.description,
            "quantity": item.quantity,
            "price": item.price
        })
    return jsonify(items), 200

# Create a new inventory item associated with the admin
@app.route('/admin/inventory', methods=['POST'])
@jwt_required()
def create_inventory_item():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({"msg": "Admins only."}), 403

    data = request.json
    new_item = InventoryItem(
        name=data.get('name'),
        description=data.get('description'),
        quantity=data.get('quantity'),
        price=data.get('price'),
        admin_id=current_user['id']  # Link the new item to the admin
    )
    db.session.add(new_item)
    db.session.commit()
    
    return jsonify({"msg": "Inventory item created", "item_id": new_item.id}), 201

# Update an existing inventory item
@app.route('/admin/inventory/<int:item_id>', methods=['PUT'])
@jwt_required()
def update_inventory_item(item_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({"msg": "Admins only."}), 403

    # Ensure the item exists and belongs to the current admin.
    item = InventoryItem.query.filter_by(id=item_id, admin_id=current_user['id']).first()
    if not item:
        return jsonify({"msg": "Item not found or not authorized"}), 404

    data = request.json
    item.name = data.get('name', item.name)
    item.description = data.get('description', item.description)
    item.quantity = data.get('quantity', item.quantity)
    item.price = data.get('price', item.price)
    db.session.commit()
    
    return jsonify({"msg": "Inventory item updated"}), 200

# Delete an inventory item
@app.route('/admin/inventory/<int:item_id>', methods=['DELETE'])
@jwt_required()
def delete_inventory_item(item_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({"msg": "Admins only."}), 403

    # Check if the item exists and is owned by the logged-in admin.
    item = InventoryItem.query.filter_by(id=item_id, admin_id=current_user['id']).first()
    if not item:
        return jsonify({"msg": "Item not found or not authorized"}), 404

    db.session.delete(item)
    db.session.commit()
    
    return jsonify({"msg": "Inventory item deleted"}), 200
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