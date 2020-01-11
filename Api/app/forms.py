from flask import flash
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, SubmitField, PasswordField, HiddenField

from wtforms.validators import DataRequired, EqualTo, ValidationError

from .models import User


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Remember Me")
    submit = SubmitField("Login")


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    repeat_password = PasswordField("Repeat password", validators=[DataRequired(), EqualTo("password")])
    remember_me = BooleanField("Remember Me")
    submit = SubmitField("Register")

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            flash("Please use a different username")
            raise ValidationError("Please use a different username")


class EditForm(FlaskForm):
    id = HiddenField(validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    is_admin = BooleanField("Is admin", validators=[DataRequired()])
    is_viewer = BooleanField("Is viewer", validators=[DataRequired()])
    is_collector = BooleanField("Is collector", validators=[DataRequired()])
    is_sql = BooleanField("Is sql executor", validators=[DataRequired()])
    action = StringField("Action", validators=[DataRequired()])
