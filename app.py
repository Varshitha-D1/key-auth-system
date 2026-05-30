from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

app = Flask(__name__)

# Secret Key
app.secret_key = 'mysecretkey'

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Database
db = SQLAlchemy(app)

# User Table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )
    password = db.Column(
        db.String(200),
        nullable=False
    )

# Home Page
@app.route('/')
def home():
    return render_template('index.html')

# Register Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Check Existing User
        existing_user = User.query.filter_by(
            username=username
        ).first()
        if existing_user:
            return "Username Already Exists"
        # Hash Password
        hashed_password = generate_password_hash(password)
        # Create User
        new_user = User(
            username=username,
            password=hashed_password
        )
        # Save User
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():

    if 'login_attempts' not in session:
        session['login_attempts'] = 0

    if request.method == 'POST':

        # Check if account is locked
        if 'lock_until' in session:

            lock_until = datetime.fromisoformat(
                session['lock_until']
            )

            if datetime.now() < lock_until:

                remaining_time = (
                    lock_until - datetime.now()
                ).seconds

                return f"Account locked. Try again in {remaining_time} seconds."

            else:
                session.pop('lock_until', None)
                session['login_attempts'] = 0

        username = request.form['username']
        password = request.form['password']

        # Find User
        user = User.query.filter_by(
            username=username
        ).first()

        # Verify Password
        if user and check_password_hash(
            user.password,
            password
        ):

            # Reset Attempts
            session['login_attempts'] = 0

            # Store Session
            session['username'] = username

            return redirect(url_for('dashboard'))

        else:

            session['login_attempts'] += 1

            remaining = 3 - session['login_attempts']

            if session['login_attempts'] >= 3:

                session['lock_until'] = (
                    datetime.now() + timedelta(minutes=5)
                ).isoformat()

                return "Too many login attempts. Account locked for 5 minutes."

            return f"Invalid Username or Password. Attempts left: {remaining}"

    return render_template('login.html')

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template(
            'dashboard.html',
            username=session['username']
        )
    return redirect(url_for('login'))

# Logout
@app.route('/logout')
def logout():

    session.pop('username', None)
    session.pop('login_attempts', None)
    session.pop('lock_until', None)

    return redirect(url_for('login'))
        
# Run Application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)