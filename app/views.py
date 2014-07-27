from flask import render_template, flash, redirect, session, url_for, request, g
from flask.ext.login import login_user, logout_user, current_user, login_required
from app import app, db, lm, bcrypt
from forms import LoginForm
from models import User, ROLE_USER, ROLE_ADMIN
from crypto import generate_salt, generate_key, AES_encrypt, AES_decrypt



@app.route("/login", methods=["GET", "POST"])
def login():
    """For GET requests, display the login form. For POSTS, login the current user
    by processing the form."""
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.get(form.email.data)
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            user.authenticated = True
            db.session.add(user)
            db.session.commit()
            login_user(user, remember=True)
            return redirect(url_for("app.index"))
    return render_template("login.html", form=form)

@app.route('/')
@app.route('/index')
def index():
    return "Hello, World!"





@lm.user_loader
def load_user(id):
    return User.query.get(int(id))