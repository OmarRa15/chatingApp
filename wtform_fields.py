from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Length, EqualTo, Email


class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email', check_deliverability=True),
                                             Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm = PasswordField('Confirm_password', validators=[EqualTo('password', message='Passwords must match')])
    first_name = StringField('First Name', validators=[InputRequired(), Length(min=3, max=20)])
    last_name = StringField('Last Name', validators=[InputRequired(), Length(min=3, max=20)])


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class EmailForm(FlaskForm):
    email = StringField('Enter Your email',
                        validators=[InputRequired(), Email(message='Invalid email', check_deliverability=True),
                                    Length(max=50)])


class ResetForm(FlaskForm):
    password = PasswordField('New Password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm = PasswordField('Confirm_password', validators=[EqualTo('password', message='Passwords must match')])
