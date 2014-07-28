from flask.ext.wtf import Form
from wtforms import TextField, PasswordField
from wtforms.validators import Required, Email, Length

class LoginForm(Form):
    """Form class for user login."""
    email = TextField('email', validators=[Required(), Email()])
    password = PasswordField('password', validators=[Required()])