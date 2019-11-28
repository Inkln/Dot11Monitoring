from ...app import app, db

from flask import render_template, redirect, flash
from flask_login import login_required, current_user

@app.route('/monitor', methods=['GET'])
@login_required
def monitor():
    if not current_user.is_viewer:
        flash('You aren\'t viewer')
        return redirect('/main_page', 'Permissions denied')

    if current_user.is_viewer:
        # TODO ADD TEMPLATE
        return render_template('monitor.html', title='Main')
    else:
        return redirect('/main_page')