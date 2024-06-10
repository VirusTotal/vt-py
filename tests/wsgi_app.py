"""Simulates a Flask app using vt-py to test non-async environments."""

import flask
import os
import vt

app = flask.Flask(__name__)


@app.get('/')
def home():
  with vt.Client(os.getenv('VT_APIKEY')) as c:
    g = c.get('/domains/google.com')
    return g.json()
