from flask import (render_template, flash, redirect, session, url_for, request, g,
    jsonify, abort)
from flask.ext.login import (login_user, logout_user, current_user, login_required,
    fresh_login_required)
from app import app, db, lm, bcrypt
from forms import LoginForm, RegistrationForm
from models import User, Post
from crypto import (generate_salt, generate_key, generate_hash, AES_encrypt,
    AES_decrypt, xor_keys)
from functools import wraps
from datetime import datetime
from urlparse import urlparse, urljoin
import snappy
import binascii

def is_safe_url(target):
    """Checks if url is safe."""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


def get_referrer(target, *args, **kwargs):
    """Finds referrer, else target."""
    for t in request.args.get('next'), request.referrer:
        if not t:
            continue
        if is_safe_url(t) and t != url_for('.logout'):
            return t
    return url_for(default, *args, **kwargs)


def logout_required(target):
    """Redirects to target if user is not logged in."""
    def decorated_wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.is_authenticated():
                return redirect(url_for(target))
            else:
                return f(*args, **kwargs)
        return decorated_function
    return decorated_wrapper


def ajax_required(target):
    """Redirects to target if request is not ajax."""
    def decorated_wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.is_xhr:
                return f(*args, **kwargs)
            else:
                return redirect(url_for(target))
        return decorated_function
    return decorated_wrapper


def same_user_required(f):
    """Checks whether user is viewing /username, else 403"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in kwargs:
            if current_user and current_user.is_authenticated():
                if current_user.username == kwargs['username']:
                    return f(*args, **kwargs)
        abort(403)
    return decorated_function


@lm.user_loader
def load_user(id):
    """Helper function needed for flask-login."""
    return User.query.get(int(id))


@app.route('/')
def index():
    if current_user and current_user.is_authenticated():
        return redirect(url_for('.u', username=current_user.username))
    else:
        return "placeholder"


@app.route('/u/<username>')
@fresh_login_required
@same_user_required
def u(username):
    print username
    return username


@app.route('/api/posts/update_post')
@fresh_login_required
@ajax_required('.index')
def api_posts_update_post():
    user = current_user
    slug = request.args.get('slug', type=str)
    meta = request.args.get('meta', type=str)
    content = request.args.get('content', type=str)

    if None not in (slug, content):
        post = user.posts.filter_by(slug=slug).first()
        if post:
            try:
                half_key = session[generate_hash(user.user_key_salt)]
                key = xor_keys(half_key, app.config['MASTER_KEY'])
                content = snappy.compress(content)
                content = AES_encrypt(key, content)

                post.meta = meta
                post.content = content
                db.session.add(post)
                db.session.commit()
                return jsonify(error=None)
            except:
                return jsonify(error="Update error")
    return jsonify(error="Not found")


@app.route('/u/<username>/posts/<slug>')
@fresh_login_required
@same_user_required
def u_posts_slug(username, slug):
    user = current_user
    post = user.posts.filter_by(slug=slug).first()
    if post:
        if post.content:
            half_key = session[generate_hash(user.user_key_salt)]
            key = xor_keys(half_key, app.config['MASTER_KEY'])
            content = AES_decrypt(key, post.content)
            content = snappy.decompress(content)
            return content
        return "Empty"
        #return render_template("post.html")
    abort(404)


@app.route('/u/<username>/posts/<slug>/delete')
@fresh_login_required
@same_user_required
def u_posts_slug_delete(username, slug):
    user = current_user
    post = user.posts.filter_by(slug=slug).first()
    if post:
        if post.content:
            # Overwrite data
            post.content = generate_salt(len(post.content))
            db.session.add(post)
            db.session.commit()
        db.session.delete(post)
        db.session.commit()
        return redirect(url_for('.index'))
    abort(404)


@app.route('/u/<username>/posts/create')
@fresh_login_required
@same_user_required
def u_posts_create(username):
    user = current_user
    post = Post(created_timestamp=datetime.utcnow(), author=user)
    db.session.add(post)
    db.session.commit()

    byte = generate_hash(str(datetime.utcnow()) + str(post.id))
    slug = binascii.hexlify(byte)[:8]
    while user.posts.filter_by(slug=slug).first():
        byte = generate_hash(str(datetime.utcnow()) + str(post.id))
        slug = binascii.hexlify(byte)[:8]

    post.slug = slug
    db.session.add(post)
    db.session.commit()

    return redirect(url_for('.u_posts_slug', username=username, slug=slug))


@app.route("/register", methods=['GET', 'POST'])
@logout_required('.index')
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if username is already taken
        if User.query.filter_by(username=form.username.data).first():
            flash('Username is already taken')
            return render_template("register.html", title = 'Sign In', form=form)
        
        # Create new user
        user = User(
            username=form.username.data,
            password=bcrypt.generate_password_hash(form.password.data),
            companion_key=generate_salt(32),
            user_key_salt=generate_salt(32)
        )

        user.authenticated = True
        db.session.add(user)
        db.session.commit()

        # Generate and store user's half_key
        user_key = generate_key(form.password.data, user.user_key_salt, 32)
        half_key = xor_keys(user_key, user.companion_key)
        session[generate_hash(user.user_key_salt)] = half_key

        login_user(user, remember=False)
        return redirect(url_for(".index"))
    
    return render_template("register.html", title = 'Sign In', form=form)


@app.route("/login", methods=['GET', 'POST'])
@logout_required('.index')
def login():
   form = LoginForm()
   if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            user.authenticated = True
            db.session.add(user)
            db.session.commit()

            # Generate and store user's half_key
            user_key = generate_key(form.password.data, user.user_key_salt, 32)
            half_key = xor_keys(user_key, user.companion_key)
            session[generate_hash(user.user_key_salt)] = half_key

            login_user(user, remember=False)

            return redirect(get_referrer('.u', username=user.username))

   return render_template("login.html", title = 'Sign In',form=form)


@app.route("/logout")
@fresh_login_required
def logout():
    user = current_user

    # Overwrite half_key
    session[generate_hash(user.user_key_salt)] = generate_salt(32)
    session.clear()

    user.authenticated = False
    db.session.add(user)
    db.session.commit()
    
    logout_user()
    return redirect(url_for(".index"))

