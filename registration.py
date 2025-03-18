from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
import re  # For email validation

app = Flask(__name__)

# Configure Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db' # using sql lite for now, can be chnaged
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'  # Required for session security
                                             # will change, placeholder for now

db = SQLAlchemy(app)


# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)


# Create Database
with app.app_context():
    db.create_all()


# Registers/adds a user to the database
@app.route('/register', methods=['GET', 'POST'])
def register():

    # gets the Register html page, for the frontend
    if request.method == 'GET':
        return render_template('Register.html')  # Load HTML form

    try:
        data = request.form  # using form instead of json becuase frontend is used

        # Checks for missing fields
        if not all(field in data for field in ['username', 'email', 'password']):
            return jsonify({"error": "Missing required fields"}), 400

        # Validate email format
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'  # Regex pattern for valid email
        if not re.match(email_regex, data['email']):
            return jsonify({"error": "Invalid email format"}), 400

        # Validate password strength
        if len(data['password']) < 8:                  # Password must be at least 8 characters long
            return jsonify({"error": "Password must be at least 8 characters long"}), 400
        if not re.search(r'\d', data['password']):     # Password must contain at least one digit
            return jsonify({"error": "Password must contain at least one digit."}), 400
        if not re.search(r'[A-Z]', data['password']):  # Password must contain at least one uppercase letter
            return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
        if not re.search(r'[a-z]', data['password']):  # Password must contain at least one lowercase letter
            return jsonify({"error": "Password must contain at least one lowercase letter."}), 400
        if not re.search(r'[\W_]', data['password']):  # Password must contain at least one special character (non-alphanumeric)
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

        # Successful message
        return jsonify({
            "message": "User registered successfully!",
            "username": new_user.username,
            "id": new_user.id
        }), 201

    except Exception as e:
        return jsonify({"error": "Internal Server Error"}), 500


if __name__ == '__main__':
    app.run(debug=True)
