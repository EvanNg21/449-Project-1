from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for
from werkzeug.security import check_password_hash
from models import User

login_bp = Blueprint('login', __name__)

@login_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('Login.html')

    data = request.json
    user = User.query.filter_by(username=data['username']).first()

    if user and check_password_hash(user.password_hash, data['password']):
        session['user_id'] = user.id
        session['username'] = user.username
        return redirect(url_for('login.show_logged_in_page'))

    return jsonify({"error": "Invalid credentials"}), 401

@login_bp.route('/session', methods=['GET'])
def get_session():
    if 'user_id' in session:
        return jsonify({"message": "User is logged in", "user_id": session['user_id']})
    return jsonify({"message": "User is not logged in"}), 401

@login_bp.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({"message": "User logged out successfully!"})

@login_bp.route('/logged_in', methods=['GET'])
def show_logged_in_page():
    if 'user_id' not in session:
        return redirect(url_for('login.login'))
    return render_template('Logged_In.html')