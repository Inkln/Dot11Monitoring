try:
    from ...app import app, db
except Exception:
    from app import app, db

from flask import render_template, redirect
from flask_login import login_required, current_user


@app.route('/main_page', methods=['GET'])
@login_required
def main_page():
    return render_template('main.html', title='Main')


