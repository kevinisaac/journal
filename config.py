import os

basedir = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')

CSRF_ENABLED = True
SECRET_KEY = 'YJF67CL5i+OetVdJBssi+nmbdcIoTn6Z'
MASTER_KEY = 'rCXc1nLJ8hUqQqdK1aeYUfu6gKCpQubR'
PUBLIC_KEY = 'Aog0APUrgXlwgfk4gPX6WAodtX3uzq0N'
SESSION_PROTECTION = 'strong'

MAX_SEARCH_RESULTS = 50
WHOOSH_BASE = os.path.join(basedir, 'search.db')

