import os

basedir = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')

CSRF_ENABLED = True
SECRET_KEY = 'YJF67CL5i+OetVdJBssi+nmbdcIoTn6Z79OoTCRElto='
MASTER_KEY = 'rCXc1nLJ8hUqQqdK1aeYUfu6gKCpQubRUJQEjnrcnUU='
SESSION_PROTECTION = 'strong'

