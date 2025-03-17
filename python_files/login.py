from flask import Flask, request, jsonify, session
from werkzeug.security import check_password_hash
from flask_session import Session

app.config['SECRET_KEY'] = 'supersecretkey'  # Encrypts session data
app.config['SESSION_TYPE'] = 'filesystem'  # Stores session data on the server
Session(app)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()

    if user and check_password_hash(user.password_hash, data['password']):
        session['user_id'] = user.id
        session['username'] = user.username  # Store login info in session
        return jsonify({"message": "Login successful!"})

    return jsonify({"error": "Invalid credentials"}), 401

# for checking to see if a user is logged in.
@app.route('/session', methods=['GET'])
def get_session():
    if 'user_id' in session:
        return jsonify({"message": "User is logged in", "user_id": session['user_id']})
    return jsonify({"message": "User is not logged in"}), 401

# loggin out
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({"message": "User logged out successfully!"})


