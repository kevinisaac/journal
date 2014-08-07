from app import app, db
from crypto import generate_salt, generate_key, AES_encrypt, AES_decrypt
import flask.ext.whooshalchemy as whooshalchemy

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(16), index=True, unique=True)
    password = db.Column(db.String(60))
    status = db.Column(db.Integer, default=0)
    posts = db.relationship('Post', backref = 'author', lazy = 'dynamic', order_by='desc(Post.created_timestamp)')

    active = db.Column(db.Boolean, default=True)
    authenticated = db.Column(db.Boolean, default=False)
    companion_key = db.Column(db.Binary(32))
    user_key_salt = db.Column(db.Binary(32))

    def is_authenticated(self):
        return self.authenticated

    def is_active(self):
        return self.active

    def is_anonymous(self):
        return False

    def get_id(self):
        return unicode(self.id)

    def __repr__(self):
        return '<User %r>' % (self.username)

class Post(db.Model):
    __searchable__ = ['meta']

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(128), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)

    meta = db.Column(db.Text)
    content = db.Column(db.LargeBinary)
    cursor = db.Column(db.Integer, default=0)
    created_timestamp = db.Column(db.DateTime, index=True)
    modified_timestamp = db.Column(db.DateTime)

    def __repr__(self):
        return '<Post %r>' % (self.id)

whooshalchemy.whoosh_index(app, Post)