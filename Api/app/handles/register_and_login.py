import json

from flask import request, abort, config, redirect, url_for, flash, render_template
from flask_login import current_user, login_user, logout_user

from ..models import User
from ..forms import LoginForm, RegisterForm
from ...app import app, db


@app.route('/login', methods=['POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main_page'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'Error')
            return redirect(url_for('index'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('main_page'))
    flash('Invalid form data', 'Error')
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main_page'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!', 'Message')
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('main_page'))

    flash('Registration failed', 'Error')
    return redirect(url_for('index'))