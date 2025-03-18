from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from login import login_bp
from registration import register_bp
from Inventory import inventory_bp
from models import db, User

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SESSION_TYPE'] = 'filesystem'

# Initialize extensions
db.init_app(app)
Session(app)

# Register blueprints
app.register_blueprint(login_bp)
app.register_blueprint(register_bp)
app.register_blueprint(inventory_bp)

@app.route('/')
def home():
    return "Hello, Flask!"

@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()  # Fetch all users from the database
    user_list = [{"id": user.id, "username": user.username, "email": user.email} for user in users]
    return jsonify(user_list)  # Return the list as a JSON response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)