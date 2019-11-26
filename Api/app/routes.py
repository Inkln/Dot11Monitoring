from ..app import app, db

from flask import render_template, flash, get_flashed_messages
from flask_login import login_required
from .models import *

from .forms import *

from .handles import *


@app.route('/', methods=['GET'])
@app.route('/index', methods=['GET'])
def index():
    for category, message in get_flashed_messages(with_categories=True):
        flash(message, category)
        break
    return render_template('index.html', form_login=LoginForm(), form_register=RegisterForm())

@app.route('/main_page', methods=['GET'])
@login_required
def main_page():
    return render_template('main.html', title='Main')
