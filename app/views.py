from flask import render_template, session, redirect
from app import app

@app.route('/')
@app.route('/index')
def index():
    return "Hello, World!"

