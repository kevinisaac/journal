from flask.ext.wtf import Form
from wtforms import TextField, PasswordField
from wtforms.validators import Required, Email, Length, EqualTo

class LoginForm(Form):
    """Form class for user login."""
    email = TextField('email', validators=[Required(), Email()])
    password = PasswordField('password', validators=[Required()])

class RegistrationForm(Form):
    email = TextField('email', [Required(), Email(), Length(max=128)])
    password = PasswordField('password', [
        Required(),
        Length(min=8, max=128),
        EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('repeat password')