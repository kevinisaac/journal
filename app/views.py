from flask import render_template, flash, redirect, session, url_for, request, g
from flask.ext.login import login_user, logout_user, current_user, login_required
from app import app, db, lm, bcrypt
from forms import LoginForm, RegistrationForm
from models import User, Post
from crypto import generate_salt, generate_key, AES_encrypt, AES_decrypt
from functools import wraps


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


def get_redirect_target(redirect_default):
    for target in request.args.get('next'), request.referrer:
        if not target:
            continue
        if is_safe_url(target):
            return target
    return url_for(redirect_default)


def logout_required(redirect_default):
    def decorated_wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.is_authenticated():
                return redirect(get_redirect_target(redirect_default))
            else:
                return f(*args, **kwargs)
        return decorated_function
    return decorated_wrapper


@app.route('/')
@app.route('/index')
def index():
    return "Hello, World!"

@app.route('/test')
@login_required
def login_test():
    user = current_user
    print user
    print type(user)
    print current_user.get_id()
    print user.active
    return "passed"


@lm.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route("/register", methods=["GET", "POST"])
@logout_required('.index')
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        # Check if username and email are already registered
        if User.query.get(form.username.data):
            flash('Username is taken')
            return render_template("register.html", title = 'Sign In', form=form)
        if User.query.get(form.email.data):
            flash('Email address is already registered')
            return render_template("register.html", title = 'Sign In', form=form)
        
        # Create new user
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=bcrypt.generate_password_hash(form.password.data),
            companion_key=generate_salt(32),
            user_key_salt=generate_salt(32),
        )

        user.authenticated = True
        db.session.add(user)
        db.session.commit()

        # Generate and store user's encryption key
        user_key = generate_key(form.password.data, user.user_key_salt, 32)
        master_key = str(
            bytearray(x ^ y for x, y in zip(bytearray(user_key), bytearray(user.companion_key)))
        )
        session[str(user.id)] = master_key

        login_user(user, remember=False)
        return redirect(url_for(".index"))
    
    return render_template("register.html", title = 'Sign In', form=form)


@app.route("/login", methods=["GET", "POST"])
@logout_required('.index')
def login():
   form = LoginForm()
   if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        print user
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            print 'PASSEDCHECK'
            user.authenticated = True
            db.session.add(user)
            db.session.commit()

            #Generate and store user's encryption key
            user_key = generate_key(form.password.data, user.user_key_salt, 32)
            master_key = str(
                bytearray(x ^ y for x, y in zip(bytearray(user_key), bytearray(user.companion_key)))
            )
            session[str(user.id)] = master_key

            login_user(user, remember=False)
            return redirect(url_for(".index"))

   return render_template("login.html", title = 'Sign In',form=form)


@app.route("/logout")
@login_required
def logout():
    user = current_user
    
    session[str(user.id)] = generate_salt(32)
    session.clear()

    user.authenticated = False
    db.session.add(user)
    db.session.commit()
    
    logout_user()
    return redirect(url_for(".index"))

