from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import timedelta
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with something secure in real apps
app.permanent_session_lifetime = timedelta(minutes=5)  # 👈 Session expires after 30 mins

# SQLite connection helper
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if username is empty
        if not username:
            flash("Username is required!", "error")
            return redirect(url_for('register'))

        # Check if email is empty
        if not email:
            flash("Email is required!", "error")
            return redirect(url_for('register'))

        # Check if password is empty
        if not password:
            flash("Password is required!", "error")
            return redirect(url_for('register'))

        # Check if confirm password is empty
        if not confirm_password:
            flash("Please confirm your password!", "error")
            return redirect(url_for('register'))

        # Validate email format using regex
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email format!", "error")
            return redirect(url_for('register'))

        # Validate password length (min 8 characters)
        if len(password) < 8:
            flash("Password must be at least 8 characters long!", "error")
            return redirect(url_for('register'))

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for('register'))

        # Check if the username already exists
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Username is already taken!", "error")
            conn.close()
            return redirect(url_for('register'))

        # Check if the email already exists
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        existing_email = cursor.fetchone()

        if existing_email:
            flash("Email is already registered!", "error")
            conn.close()
            return redirect(url_for('register'))

        # Hash the password and store the new user in the database
        password_hash = generate_password_hash(password)
        cursor.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', 
                       (username, email, password_hash))
        conn.commit()
        conn.close()

        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        # Check if username is empty
        if not username:
            flash("Username is required!", "error")
            return redirect(url_for('login'))

        # Check if password is empty
        if not password:
            flash("Password is required!", "error")
            return redirect(url_for('login'))

        # Check if the username exists in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        if user is None:
            flash("Username not found!", "error")
            conn.close()
            return redirect(url_for('login'))

        # Check if the entered password is correct
        if not check_password_hash(user['password_hash'], password):
            flash("Incorrect password!", "error")
            conn.close()
            return redirect(url_for('login'))

        # If login is successful, set session and redirect to dashboard or home page
        session.permanent = True  # 👈 This makes the session respect the expiration time
        session['user_id'] = user['id']
        session['username'] = user['username']
        conn.close()
        flash("Logged in successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash("You must be logged in to view that page.", "error")
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
