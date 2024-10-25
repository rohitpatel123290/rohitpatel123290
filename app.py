from flask import Flask, request, render_template, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
import time  # Import time for timestamps
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session management

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Key file for message encryption
key_file = "secret.key"

# Load or generate a new key
if os.path.exists(key_file):
    with open(key_file, "rb") as f:
        key = f.read()
else:
    key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(key)

# Ensure the key is valid
try:
    cipher_suite = Fernet(key)
except ValueError:
    # If the key is invalid, regenerate it
    key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(key)
    cipher_suite = Fernet(key)

# User database
users_db = 'users.json'

def ensure_json_file(file_path, default_content):
    if not os.path.exists(file_path):
        with open(file_path, "w") as f:
            json.dump(default_content, f)
    else:
        # Check if the file is empty
        if os.path.getsize(file_path) == 0:
            with open(file_path, "w") as f:
                json.dump(default_content, f)

# Initialize users if the user database does not exist or is empty
ensure_json_file(users_db, {
    "root": generate_password_hash("123"),  # root / 123
    "user": generate_password_hash("098"),   # user / 098
})

# Initialize a JSON file to store chat messages
ensure_json_file("messages.json", [])

class User(UserMixin):
    def __init__(self, username):
        self.username = username
        self.id = username  # Use username as ID for simplicity

    def get_id(self):
        return self.id  # Return the ID for Flask-Login

def load_users():
    with open(users_db, "r") as f:
        return json.load(f)

@login_manager.user_loader
def load_user(username):
    return User(username) if username in load_users() else None

def read_messages():
    with open("messages.json", "r") as f:
        return json.load(f)

def write_message(data):
    messages = read_messages()
    
    # Encrypt the message before storing
    encrypted_message = cipher_suite.encrypt(data['text'].encode())
    
    # Store the message with username, encrypted text, and timestamp
    timestamp = time.time()  # Get the current time
    data['text'] = encrypted_message.decode()  # Store as string in JSON
    data['timestamp'] = timestamp  # Add timestamp
    messages.append(data)
    
    with open("messages.json", "w") as f:
        json.dump(messages, f)

def decrypt_message(encrypted_message):
    return cipher_suite.decrypt(encrypted_message.encode()).decode()

@app.route('/')
def home():
    """Render home page with login form."""
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    """User login route."""
    username = request.form['username']
    password = request.form['password']
    
    users = load_users()
    if username in users and check_password_hash(users[username], password):
        login_user(User(username))  # Log the user in
        flash("Login successful!")
        return redirect(url_for('chat'))  # Redirect to chat page on successful login
    
    flash("Invalid username or password.")
    return redirect(url_for('home'))  # Redirect back to home if login fails

@app.route('/logout')
@login_required
def logout():
    """User logout route."""
    logout_user()
    flash("Logout successful!")
    return redirect(url_for('home'))

@app.route('/chat')
@login_required
def chat():
    """Render chat UI."""
    return render_template('chat.html')

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    """API endpoint for sending a message."""
    data = {
        'username': current_user.username,
        'text': request.json['text']
    }
    write_message(data)
    return jsonify({"status": "Message sent!"}), 200

@app.route('/get_messages', methods=['GET'])
@login_required
def get_messages():
    """API endpoint to fetch all messages."""
    messages = read_messages()
    # Decrypt messages before sending
    for msg in messages:
        try:
            msg['text'] = decrypt_message(msg['text'])
        except Exception as e:
            msg['text'] = "Error decrypting message"
            print(f"Decryption error: {e}")
    return jsonify(messages)

@app.route('/delete_message', methods=['POST'])
@login_required
def delete_message():
    """API endpoint to delete a message."""
    message_index = request.json['index']  # Get the index of the message to delete
    messages = read_messages()
    
    if 0 <= message_index < len(messages):
        del messages[message_index]  # Remove the message at the specified index
        with open("messages.json", "w") as f:
            json.dump(messages, f)
        return jsonify({"status": "Message deleted!"}), 200
    return jsonify({"status": "Invalid message index!"}), 400

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Password change route."""
    if request.method == 'POST':
        username = request.form['username']
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        re_password = request.form['re_password']
        
        users = load_users()
        
        if username in users and check_password_hash(users[username], current_password):
            if new_password == re_password:
                users[username] = generate_password_hash(new_password)
                with open(users_db, "w") as f:
                    json.dump(users, f)
                flash("Password changed successfully!")
                # Log in with the new username
                login_user(User(username))
                return redirect(url_for('chat'))
            else:
                flash("New passwords do not match.")
        else:
            flash("Username or current password is incorrect.")

    return render_template('forgot_password.html')

@app.route('/change_credentials', methods=['GET', 'POST'])
@login_required
def change_credentials():
    """Change username and password."""
    if request.method == 'POST':
        current_username = request.form['current_username']
        new_username = request.form['new_username']
        new_password = request.form['new_password']
        re_password = request.form['re_password']

        users = load_users()

        if current_username != current_user.username:
            flash("Current username does not match.")
            return redirect(url_for('change_credentials'))

        if new_username in users:
            flash("New username already taken.")
            return redirect(url_for('change_credentials'))

        if new_password != re_password:
            flash("Passwords do not match.")
            return redirect(url_for('change_credentials'))

        # Update user credentials
        del users[current_user.username]  # Remove old username
        users[new_username] = generate_password_hash(new_password)  # Add new username with hashed password

        # Save updated users to file
        with open(users_db, "w") as f:
            json.dump(users, f)

        # Update session
        logout_user()  # Log out the user
        login_user(User(new_username))  # Log in with new username

        flash("Credentials changed successfully!")
        return redirect(url_for('chat'))

    return render_template('change_credentials.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
