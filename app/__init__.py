from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy

from flask.ext.login import LoginManager
from flask_oauth import OAuth


app = Flask(__name__)

# DB
app.config.from_object('config')
db = SQLAlchemy(app)

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)

# OAuth
oauth = OAuth()
twitter = oauth.remote_app('twitter',
    base_url='https://api.twitter.com/1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authenticate',
    consumer_key='yImiYnPdUpcuvHDLEfgbLISxm',
    consumer_secret='8EbQOGSfAKGwGTP2BTAEzEDZXKRXtzrnPc3vv07osmNX4seFP4'
)




from app import views, models