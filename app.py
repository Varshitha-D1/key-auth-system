from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import re

app = Flask(__name__)

# Secret Key
app.secret_key = 'mysecretkey'

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Database
db = SQLAlchemy(app)

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
    role = db.Column(
        db.String(20),
        default='user'
    )

class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    login_time = db.Column(db.DateTime)

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
        if not re.search("[A-Z]", password):
            return "Password must contain an uppercase letter"

        if not re.search("[0-9]", password):
            return "Password must contain a number"

        if not re.search("[@#$%^&*!]", password):
            return "Password must contain a special character"
        if len(password) < 8:
            return "Password must be at least 8 characters"
        
        # Check Existing User
        existing_user = User.query.filter_by(
            username=username
        ).first()

        if existing_user:
            return """
<h2 style='text-align:center;
color:red;
margin-top:100px;
font-size:32px;'>
Username Already Exists
</h2>

<div style='text-align:center; margin-top:20px;'>
<a href='/register'>Try Again</a>
</div>
"""

        # Hash Password
        hashed_password = generate_password_hash(
            password
        )

        # Create User
        if username.lower() in ["admin", "superadmin"]:
            return """
<h2 style='text-align:center;
color:red;
margin-top:100px;
font-size:32px;'>
This Username Is Reserved
</h2>

<div style='text-align:center; margin-top:20px;'>
<a href='/register'>Try Again</a>
</div>
"""

        role = "user"

        new_user = User(
            username=username,
            password=hashed_password,
            role=role
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

                return f"""
<h2 style='text-align:center;
color:red;
margin-top:100px;
font-size:32px;'>
Account Locked
</h2>

<h3 style='text-align:center;'>
Try Again In {remaining_time} Seconds
</h3>

<div style='text-align:center; margin-top:20px;'>
<a href='/login'>Back To Login</a>
</div>
"""

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

            history = LoginHistory(
                username=username,
                login_time=datetime.now()
            )

            db.session.add(history)
            db.session.commit()

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

                return """
<h2 style='text-align:center; color:red; margin-top:100px; font-size:32px;'>
Too Many Login Attempts
</h2>

<h3 style='text-align:center;'>
Account Locked For 5 Minutes
</h3>

<div style='text-align:center; margin-top:20px;'>
<a href='/login'>Back to Login</a>
</div>
"""

            return f"""
<h2 style='text-align:center; color:red; margin-top:100px; font-size:32px;'>
Invalid Username or Password
</h2>

<h3 style='text-align:center;'>
Attempts Left: {remaining}
</h3>

<div style='text-align:center; margin-top:20px;'>
<a href='/login'>Try Again</a>
</div>
"""

    return render_template('login.html')

# Dashboard
@app.route('/dashboard')
def dashboard():

    if 'username' in session:

        last_login = LoginHistory.query.filter_by(
            username=session['username']
        ).order_by(
            LoginHistory.id.desc()
        ).first()

        return render_template(
            'dashboard.html',
            username=session['username'],
            last_login=last_login
        )

    return redirect(url_for('login'))

#Profile
@app.route('/profile')
def profile():

    if 'username' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(
        username=session['username']
    ).first()

    last_login = LoginHistory.query.filter_by(
        username=session['username']
    ).order_by(
        LoginHistory.id.desc()
    ).first()

    return render_template(
        'profile.html',
        username=session['username'],
        role=user.role,
        last_login=last_login
    )

#Admin dashboard
@app.route('/admin')
def admin():

    if 'username' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(
        username=session['username']
    ).first()

    if user.role != 'admin':
        return "Access Denied"

    search = request.args.get('search', '')

    if search:
        users = User.query.filter(
            User.username.contains(search)
        ).all()
    else:
        users = User.query.all()

    return render_template(
        'admin.html',
        users=users
    )

#Delete User
@app.route('/delete_user/<int:id>')
def delete_user(id):

    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = User.query.filter_by(
        username=session['username']
    ).first()

    if current_user.role != 'admin':
        return "Access Denied"

    user = User.query.get(id)

    if user:

        if user.username in ["admin", "superadmin"]:
            return "Admin accounts cannot be deleted"

        db.session.delete(user)
        db.session.commit()

    return redirect(url_for('admin'))

#Login history
@app.route('/history')
def history():

    if 'username' not in session:
        return redirect(url_for('login'))

    logs = LoginHistory.query.filter_by(
    username=session['username']
).order_by(
    LoginHistory.id.desc()
).all()

    return render_template(
        'history.html',
        logs=logs
    )

# Change Password
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():

    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':

        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        user = User.query.filter_by(
            username=session['username']
        ).first()

        # Verify Current Password
        if not check_password_hash(
            user.password,
            current_password
        ):
            return """
<h2 style='text-align:center;
color:red;
margin-top:100px;
font-size:32px;'>
Current Password Incorrect
</h2>

<div style='text-align:center; margin-top:20px;'>
<a href='/change_password'>Try Again</a>
</div>
"""

        # Check Password Match
        if new_password != confirm_password:
            return """
<h2 style='text-align:center;
color:red;
margin-top:100px;
font-size:32px;'>
Passwords Do Not Match
</h2>

<div style='text-align:center; margin-top:20px;'>
<a href='/change_password'>Try Again</a>
</div>
"""

        # Password Strength Validation
        if not re.search("[A-Z]", new_password):
            return "Password must contain an uppercase letter"

        if not re.search("[0-9]", new_password):
            return "Password must contain a number"

        if not re.search("[@#$%^&*!]", new_password):
            return "Password must contain a special character"

        if len(new_password) < 8:
            return "Password must be at least 8 characters"

        # Update Password
        user.password = generate_password_hash(
            new_password
        )

        db.session.commit()

        return """
<h2 style='text-align:center;
color:green;
margin-top:100px;
font-size:32px;'>
Password Updated Successfully
</h2>

<div style='text-align:center; margin-top:20px;'>
<a href='/dashboard'>Back To Dashboard</a>
</div>
"""

    return render_template(
        'change_password.html'
    )

# Forgot Password
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():

    if request.method == 'POST':

        username = request.form['username']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        security_code = request.form.get('security_code') 

        if username.lower() == "admin":
            if security_code != "1234":
                return "Invalid Admin Security Code"

        if username.lower() == "superadmin":
            if security_code != "5678":
                return "Invalid Admin Security Code"  

        user = User.query.filter_by(
            username=username
        ).first()

        if not user:
            return """
<h2 style='text-align:center;
color:red;
margin-top:100px;
font-size:32px;'>
Username Not Found
</h2>

<div style='text-align:center; margin-top:20px;'>
<a href='/forgot_password'>Try Again</a>
</div>
"""

        if new_password != confirm_password:
            return """
<h2 style='text-align:center;
color:red;
margin-top:100px;
font-size:32px;'>
Passwords Do Not Match
</h2>

<div style='text-align:center; margin-top:20px;'>
<a href='/forgot_password'>Try Again</a>
</div>
"""

        if not re.search("[A-Z]", new_password):
            return "Password must contain an uppercase letter"

        if not re.search("[0-9]", new_password):
            return "Password must contain a number"

        if not re.search("[@#$%^&*!]", new_password):
            return "Password must contain a special character"

        if len(new_password) < 8:
            return "Password must be at least 8 characters"

        user.password = generate_password_hash(
            new_password
        )

        db.session.commit()

        return """
<h2 style='text-align:center;
color:green;
margin-top:100px;
font-size:32px;'>
Password Reset Successfully
</h2>

<div style='text-align:center; margin-top:20px;'>
<a href='/login'>Go To Login</a>
</div>
"""

    return render_template(
        'forgot_password.html'
    )

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

        admin = User.query.filter_by(
            username="admin"
        ).first()

        if not admin:

            admin = User(
                username="admin",
                password=generate_password_hash("Admin@123"),
                role="admin"
            )

            db.session.add(admin)

        superadmin = User.query.filter_by(
            username="superadmin"
        ).first()

        if not superadmin:

            superadmin = User(
                username="superadmin",
                password=generate_password_hash("Super@123"),
                role="admin"
            )

            db.session.add(superadmin)

        db.session.commit()

    app.run(host='0.0.0.0', port=5000, debug=True)