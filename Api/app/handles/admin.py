import json

from flask import request, abort, config, redirect, url_for, flash, render_template
from flask_login import current_user, login_user, logout_user

from ..models import User, Ap, Auth, Client, DataTransfer
from ..forms import LoginForm, RegisterForm
from ...app import app, db

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'GET':
        return render_template('admin.html',
                               users=db.session.query(User).all(),
                               aps=db.session.query(Ap).all(),
                               clients=db.session.query(Client).all(),
                               datatransfers=db.session.query(DataTransfer).all(),
                               auths=db.session.query(Auth).all()
                               )
    else:
        print(request.data)
        return redirect('/admin')