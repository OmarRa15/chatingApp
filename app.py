import flask
from flask import Flask, redirect, render_template, url_for, flash, abort
from flask_login import current_user, LoginManager, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bootstrap import Bootstrap
from flask_socketio import SocketIO, send, join_room, leave_room
from time import localtime, strftime
from os import environ
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_sqlalchemy import SQLAlchemy
from send_mail import send_confirmation_mail, send_reset_mail

from wtform_fields import *

app = Flask(__name__)
app.config['SECRET_KEY'] = environ['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = environ['DATABASE_URL'][0:8] + 'ql' + environ['DATABASE_URL'][8:]
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

socketio = SocketIO(app, manage_session=False)

ROOMS = ["lounge", "news", "games", "coding"]

Bootstrap(app)
loginManager = LoginManager()
loginManager.init_app(app)
loginManager.login_view = 'login'

from models import Users


@loginManager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class UsersModelView(ModelView):
    column_list = ('id', 'first_name', 'last_name', 'username', 'email', 'ip_address', 'is_admin', 'is_confirmed')

    def is_accessible(self):
        if current_user.is_anonymous:
            return False

        return current_user.is_admin


class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        if current_user.is_anonymous:
            return False

        return current_user.is_admin

    @expose('/')
    def index(self):
        initial_list = Users.query.all()

        users_list = []
        for i in range(len(initial_list)):
            if initial_list[i].ip_address != '':
                users_list.append([initial_list[i].first_name + ' ' + initial_list[i].last_name, initial_list[i].email,
                                   initial_list[i].ip_address])

        return self.render('admin/index.html', users_list=users_list)


admin = Admin(app, template_mode='bootstrap3', index_view=MyAdminIndexView(url='/admin'))
admin.add_view(UsersModelView(Users, db.session))


@app.route('/chat')
@login_required
def chat():
    if current_user.is_admin:
        return redirect('/admin')

    return render_template('chat.html', username=current_user.first_name + ' ' + current_user.last_name,
                           rooms=ROOMS)


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/chat')
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data.lower()).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                if not user.is_confirmed:
                    return '<h1 style= "text-align: center">Your Email hasn\'t been confirmed yet,' \
                           '\nPlease <a href="{}">click here</a> to confirm your email <h1>' \
                        .format(url_for('send_confirmation', email=user.email, _external=True))
                login_user(user, remember=form.remember.data)
                user.ip_address = flask.request.remote_addr
                db.session.commit()
                if current_user.is_admin:
                    return redirect('/admin')
                return redirect('/chat')
        return render_template('login.html', form=form, errorMsg="Invalid Username or password")

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect('/chat')
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data.lower()
        password = form.password.data
        email = form.email.data.lower()

        user = Users.query.filter_by(username=username).first()
        if user:
            return render_template('signup.html', form=form, errorMsg="username already exists")

        user = Users.query.filter_by(email=email).first()
        if user:
            return render_template('signup.html', form=form, errorMsg="email already exists")

        hashedPass = generate_password_hash(password, method='sha256')

        newUser = Users(first_name=form.first_name.data, last_name=form.last_name.data,
                        username=username, email=email, password=hashedPass)

        db.session.add(newUser)
        db.session.commit()

        flash("Signed Up Successfully!!")
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if current_user.is_authenticated:
        return redirect('/')

    form = EmailForm()
    if form.validate_on_submit():
        email = form.email.data.lower()
        user = Users.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(email)
            link = url_for('resetPass', token=token, _external=True)
            if send_reset_mail(recipient=email, link=link):
                message = "Reset email has been sent successfully,\n Please check your email"
                return render_template('messagePage.html', message=message)
            message = "The email could not be sent. Please try again later"
            return render_template('messagePage.html', message=message)

        return render_template('forgot.html', form=form, errorMsg="Invalid email")
    return render_template('forgot.html', form=form)


@app.route('/resetPass/<token>', methods=['GET', 'POST'])
def resetPass(token):
    if current_user.is_authenticated:
        return redirect('/')
    try:
        form = ResetForm()
        email = serializer.loads(token, max_age=1800)
        user = Users.query.filter_by(email=email).first()
        if form.validate_on_submit():
            hashedPass = generate_password_hash(form.password.data, method='sha256')
            user.password = hashedPass
            db.session.commit()
            flash("Password has been reset Successfully!!")
            return redirect('/')
        return render_template('resetPass.html', form=form)
    except SignatureExpired:
        return render_template('messagePage.html', message="Signature Expired")
    except BadTimeSignature:
        return abort(404)


@app.route('/send_confirmation/<email>')
def send_confirmation(email):
    token = serializer.dumps(email)
    link = url_for('confirm_email', token=token, _external=True)
    if send_confirmation_mail(recipient=email, link=link):
        message = "Email confirmation has been sent successfully, Please check your email\n"
        return render_template('messagePage.html', message=message)

    message = "The email could not be sent. Please try again later"
    return render_template('messagePage.html', message=message)


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, max_age=1800)
        user = Users.query.filter_by(email=email).first()
        user.is_confirmed = True
        db.session.commit()
        message = "Your email has been confirmed successfully. You can sign in now."
        return render_template('messagePage.html', message=message)
    except SignatureExpired:
        return render_template('messagePage.html', message='Signature Expired')
    except BadTimeSignature:
        return abort(404)


@app.route('/logout')
@login_required
def logout():
    user = Users.query.filter_by(username=current_user.username).first()
    user.ip_address = ''
    db.session.commit()

    logout_user()
    return redirect(url_for('login'))


@socketio.on('incoming-msg')
def on_message(data):
    """Broadcast messages"""

    msg = data["msg"]
    username = data["username"]
    room = data["room"]
    # Set timestamp
    time_stamp = strftime('%b-%d %I:%M%p', localtime())
    send({"username": username, "msg": msg, "time_stamp": time_stamp}, room=room)


@socketio.on('join')
def on_join(data):
    """User joins a room"""

    username = data["username"]
    room = data["room"]
    join_room(room)

    # Broadcast that new user has joined
    send({"msg": username + " has joined the " + room + " room."}, room=room)


@socketio.on('leave')
def on_leave(data):
    """User leaves a room"""

    username = data['username']
    room = data['room']
    leave_room(room)
    send({"msg": username + " has left the room"}, room=room)


if __name__ == '__main__':
    db.create_all()
    db.session.commit()
    app.run()
