from flask.ext.wtf import Form
from wtforms import TextField, PasswordField, BooleanField
from wtforms.validators import Required, Email, Length, EqualTo


class LoginForm(Form):
   """Form class for user login."""
   username = TextField('username', validators=[Required()])
   password = PasswordField('password', validators=[Required()])


class RegistrationForm(Form):
   username = TextField('username', validators=[Required(), Length(max=16)])
   email = TextField('email', [Required(), Email(), Length(max=128)])
   password = PasswordField('password', [
       Required(),
       Length(min=8, max=128),
       EqualTo('confirm', message='Passwords must match')
   ])
   confirm = PasswordField('repeat password')