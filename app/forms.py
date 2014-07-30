from flask.ext.wtf import Form
from wtforms import TextField, PasswordField, BooleanField
from wtforms.validators import Required, Email, Length, EqualTo, Regexp
from models import User
from app import bcrypt

class LoginForm(Form):
    """Form class for user login."""
    username = TextField('username', [
        Required(message="This field is required")])
    password = PasswordField('password', [
        Required(message="This field is required"),
    ])

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)
        self.user = None

    def validate(self):
        """Check username and password."""
        if not Form.validate(self):
            return False
        
        self.username.data = self.username.data.lower()
        user = User.query.filter_by(username=self.username.data).first()
        if not user:
            self.username.errors.append('Username does not exist')
            return False

        if not bcrypt.check_password_hash(user.password, self.password.data):
            self.password.errors.append('Password is incorrect')
            return False

        self.user = user
        return True

class RegistrationForm(Form):
    username = TextField('username', [
        Required(message="This field is required"), 
        Regexp(r'[a-zA-Z0-9]*\Z', message="Username must be alphanumeric"),
        Length(max=16, message="Username can be at most 16 characters long")
    ])
    password = PasswordField('password', [
        Required(message="This field is required"),
        Length(min=8, message="Password must be at least 8 characters long"),
        Regexp(r'[\w@#$%^&+=]*\Z', message="Password contains invalid characters"),
    ])
    confirm = PasswordField('repeat password', [
        Required(message="This field is required"),
        EqualTo('password', message='Passwords must match')
    ])

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)

    def validate(self):
        """Check if username is already taken."""
        if not Form.validate(self):
            return False
        
        self.username.data = self.username.data.lower()
        if User.query.filter_by(username=self.username.data).first():
            self.username.errors.append('Username is already taken')
            return False

        return True