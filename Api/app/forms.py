from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, BooleanField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    repeat_password = PasswordField('Repeat password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Register')
