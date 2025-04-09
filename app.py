from flask import Flask, request, jsonify, session
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, InventoryItem
import re

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SESSION_TYPE'] = 'filesystem'
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

    if user:
        if check_password_hash(user.password_hash, data['password']):
            session['user_id'] = user.id
            session['username'] = user.username
            return jsonify({"message": "Login successful!"})
        else:
            return jsonify({"error": "Invalid password"}), 401
    else:
        return jsonify({"error": "Username is not registered. Please register first."}), 404


# Logout
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return jsonify({"message": "User logged out successfully!"})


# Checks Session
@app.route('/session', methods=['GET'])
def get_session():
    if 'user_id' in session:
        return jsonify({
            "message": "User is logged in",
            "user_id": session['user_id'],
            "username": session['username']
        })
    return jsonify({"message": "User is not logged in"}), 401


# Protected Route or not logged in
@app.route('/logged_in', methods=['GET'])
def show_logged_in_page():
    if 'user_id' not in session:
        return jsonify({"message": "Please log in first"}), 401
    return jsonify({"message": "Welcome! You are logged in."})

# ------------------------------------------------------------
# CRUD Operations for Inventory
# ------------------------------------------------------------

@app.route('/inventory', methods=['GET']) #gets all inventory items
def get_inventory():
    items = InventoryItem.query.all()
    inventory_list = [{
        "id": item.id,
        "name": item.name,
        "description": item.description,
        "quantity": item.quantity,
        "price": item.price
    } for item in items]

    return jsonify(inventory_list)

@app.route('/inventory/<int:item_id>', methods=['GET']) #gets specific inventory item
def get_inventory_item(item_id):
    try:
        item = InventoryItem.query.get(item_id)
        if item is None:
            return jsonify({"error": "Inventory Item not found"}), 404
        return jsonify({
            "id": item.id,
            "name": item.name,
            "description": item.description,
            "quantity": item.quantity,
            "price": item.price
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/inventory/create', methods=['POST']) #creates new inventory item
def create_inventory_item():
    data = request.json

    if not all(key in data for key in ['name', 'description', 'quantity', 'price']):
        return jsonify({"error": "Missing required fields"}), 400
    try:
        new_item = InventoryItem(
            name=data['name'], 
            description=data['description'], 
            quantity=data['quantity'], 
            price=data['price']
        )
        db.session.add(new_item)
        db.session.commit()
        return jsonify({"id": new_item.id, "name": new_item.name, "description": new_item.description, "quantity": new_item.quantity, "price": new_item.price, "message": "Inventory Item Created"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/inventory/delete/<int:item_id>', methods=['DELETE']) #deletes inventory item
def delete_inventory_item(item_id):
    try:
        item = InventoryItem.query.get(item_id)
        if item is None:
            return jsonify({"error": "Inventory Item not found"}), 404
        db.session.delete(item)
        db.session.commit()
        return jsonify({"message": "Inventory Item Deleted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/inventory/update/<int:item_id>', methods=['PUT']) #updates inventory item
def update_inventory_item(item_id):
    data = request.json
    try:
        item = InventoryItem.query.get(item_id)
        if item is None:
            return jsonify({"error": "Inventory Item not found"}), 404
        
        if 'name' in data:
            item.name = data['name']
        if 'description' in data:
            item.description = data['description']
        if 'quantity' in data:
            item.quantity = data['quantity']
        if 'price' in data:
            item.price = data['price']
        db.session.commit()

        return jsonify({"id": item.id, "name": item.name, "description": item.description, "quantity": item.quantity, "price": item.price, "message": "Inventory Item Updated"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ------------------------------------------------------------
# Admin-Specific Inventory Management
# ------------------------------------------------------------

# Placeholder: To be implemented!

# ------------------------------------------------------------
# Session and Cookie Security
# ------------------------------------------------------------

# Placeholder: To be implemented!

# ------------------------------------------------------------
# Run the Flask App
# ------------------------------------------------------------

if __name__ == '__main__':
    app.run(debug=True)
