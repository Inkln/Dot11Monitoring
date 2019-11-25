from ..app import app, db

from flask import render_template
from .models import *
from .forms import *


@app.route('/', methods=['GET'])
@app.route('/index', methods=['GET'])
def index():
    return render_template('index.html', form_login=LoginForm(), form_register=RegisterForm())
