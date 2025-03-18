from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash
from flask_session import Session

app = Flask(__name__)

from registration import db, User, register # imports registration.py file for use with login.py

# Adds the /register route from registration.py
app.add_url_rule('/register', view_func=register, methods=['GET', 'POST'])

# Attaches Flask app to SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)  # Register app with SQLAlchemy

app.config['SECRET_KEY'] = 'supersecretkey'  # Encrypts session data
app.config['SESSION_TYPE'] = 'filesystem'  # Stores session data on the server
Session(app)

@app.route('/login', methods=['GET', 'POST'])
def login():

    # gets the Login html page, for the frontend
    if request.method == 'GET':
        return render_template('Login.html')  # Load HTML form

    data = request.form  # using form instead of json becuase frontend is used
    user = User.query.filter_by(username=data['username']).first()

    if user and check_password_hash(user.password_hash, data['password']):
        session['user_id'] = user.id
        session['username'] = user.username  # Store login info in session
        return redirect(url_for('show_logged_in_page'))  # calls show_logged_in_page()

    return jsonify({"error": "Invalid credentials"}), 401


# for checking to see if a user is logged in.
@app.route('/session', methods=['GET'])
def get_session():
    if 'user_id' in session:
        return jsonify({"message": "User is logged in", "user_id": session['user_id']})
    return jsonify({"message": "User is not logged in"}), 401


# logging out functionality
@app.route('/logout', methods=['POST'])
def logout():
  session.pop('user_id', None)
  return jsonify({"message": "User logged out successfully!"})


# takes user to Logged_In.html page, upon successful log in
@app.route('/logged_in', methods=['GET'])
def show_logged_in_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login page if not logged in
    return render_template('Logged_In.html')


# view all the registered users in the database
@app.route('/view_users')
def view_users():
    users = User.query.all()  # Fetch all users
    user_list = [{"id": user.id, "username": user.username, "email": user.email} for user in users]
    return jsonify(user_list)  # Return as JSON



if __name__ == '__main__':
    app.run(debug=True)