from flask import Flask
from flask_kvsession import KVSessionExtension
from simplekv.fs import FilesystemStore, WebFilesystemStore
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager
from flask.ext.bcrypt import Bcrypt
from flask.ext.script import Manager
from flask.ext.migrate import Migrate, MigrateCommand
from flask_sslify import SSLify

app = Flask(__name__)
app.debug = True

app.config.from_object('config')

# DB
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)

# Login Manager
lm = LoginManager()
lm.init_app(app)
lm.refresh_view = ".login"
lm.login_view = ".login"

# Bcrypt
bcrypt = Bcrypt(app)

# Server-Side Sessions
store = FilesystemStore('./tmp')
KVSessionExtension(store, app)

# SSL
sslify = SSLify(app)

from app import views, models