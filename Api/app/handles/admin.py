import json

from flask import request, abort, config, redirect, url_for, flash, render_template
from flask_login import current_user, login_user, logout_user, login_required

from ..models import User, Ap, Auth, Client, DataTransfer
from ...app import app, db

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        flash('You aren\'t admin', 'Permissions denied')
        return redirect('/main_page')

    if request.method == 'GET':
        return render_template('admin.html',
                               users=db.session.query(User).order_by(User.id).all(),
                               aps=db.session.query(Ap).order_by(Ap.id).all(),
                               clients=db.session.query(Client).order_by(Client.id).all(),
                               datatransfers=db.session.query(DataTransfer).order_by(DataTransfer.id).all(),
                               auths=db.session.query(Auth).order_by(Auth.id).all()
                               )
    elif request.method == 'POST':
        id = request.form['id']
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        is_viewer = request.form.get('is_viewer', False)
        is_collector = request.form.get('is_collector', False)
        is_admin = request.form.get('is_admin', False)

        to_bool = lambda x: False if x == False else True
        is_viewer = to_bool(is_viewer)
        is_collector = to_bool(is_collector)
        is_admin = to_bool(is_admin)

        action = request.form['action']

        if action == 'Edit and save':
            user = User.query.filter_by(id=id).first()
            user.username = username
            user.is_viewer = is_viewer
            user.is_admin = is_admin
            user.is_collector = is_collector

            if password[:7] == 'pbkdf2:':
                print('hash')
                user.password_hash = password
            else:
                print('password')
                user.set_password(password)

            db.session.commit()

        elif action == 'Delete':
            User.query.filter_by(id=id).delete()
            db.session.commit()



        return redirect('/admin')

    else:
        return redirect('/admin')