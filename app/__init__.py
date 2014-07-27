from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager
from flask.ext.bcrypt import Bcrypt


app = Flask(__name__)
app.config.from_object('config')

# DB
db = SQLAlchemy(app)

# Login Manager
lm = LoginManager()
lm.init_app(app)

# Bcrypt
bcrypt = Bcrypt(app)

from app import views, models