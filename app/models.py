from app import db
from crypto import generate_salt, generate_key, AES_encrypt, AES_decrypt

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), index=True, unique=True)
    posts = db.relationship('Post', backref = 'author', lazy = 'dynamic')

    encrypted_key = db.Column(db.LargeBinary(32))
    companion_key = db.Column(db.LargeBinary(32), default=generate_salt(32))
    user_key_salt = db.Column(db.LargeBinary(32), default=generate_salt(32))
    authenticated = db.Column(db.Boolean, default=False)

    def is_authenticated(self):
        return self.authenticated

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return unicode(self.id)

    def __repr__(self):
        return '<User %r>' % (self.email)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    meta = db.Column(db.Text)
    body = db.Column(db.LargeBinary)
    timestamp = db.Column(db.DateTime)

    def __repr__(self):
        return '<Post %r>' % (self.timestamp)