import redis
from flask import Flask
from flask_kvsession import KVSessionExtension
from simplekv.memory.redisstore import RedisStore
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager
from flask.ext.bcrypt import Bcrypt
from flask.ext.script import Manager
from flask.ext.migrate import Migrate, MigrateCommand

app = Flask(__name__)
app.config.from_object('config')

# DB
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)

# Login Manager
lm = LoginManager()
lm.init_app(app)

# Bcrypt
bcrypt = Bcrypt(app)

# Server-Side Sessions
store = RedisStore(redis.StrictRedis())
KVSessionExtension(store, app)

from app import views, models