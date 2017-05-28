# have a global database with g
from flask import (Flask, g, render_template, flash, redirect, url_for)
from flask_bcrypt import check_password_hash
from flask_login import (LoginManager, login_user, logout_user, 
                         login_required)

import forms
import models

DEBUG = True
PORT = 8000
HOST = '0.0.0.0'

app = Flask(__name__)
# for using sessions
app.secret_key = 'ajnfjnsbjnjknegwin28f242tt2t4bv24t2g4'

login_manager = LoginManager()
login_manager.init_app(app)
# if they are not logged in, call the view login, redirect to login
login_manager.login_view = 'login'

# the function that the login_manager will use to look up a user
@login_manager.user_loader
def load_user(userid):
    try:
        return models.User.get(models.User.id == userid)
    except models.DoesNotExist:
        return None


@app.before_request
def before_request():
    """Connect to the database before each request."""
    g.db = models.DATABASE
    g.db.connect()


@app.after_request
def after_request(response): # get the return
    """Close the database connection after each request."""
    g.db.close()
    return response

# this is a view
@app.route('/register', methods=['GET', 'POST'])
def register():
    # we don't have to give information to RegisterForm
    # flask and flaskwtf know that if information came through
    # the form it should send that
    form = forms.RegisterForm()
    # validate the form, method comes from form
    # success is the message category
    if form.validate_on_submit():
        flash("Yay, you registered!", "success")
        models.User.create_user(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data
        )
        return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = forms.LoginForm()
    if form.validate_on_submit():
        try:
            user = models.User.get(models.User.email == form.email.data)
        except models.DoesNotExist:
            flash("Your email or password doesn't match!", "error")
        else:
            if check_password_hash(user.password, form.password.data):
                # create session
                login_user(user)
                flash("You've been logged in!", "success")
                return redirect(url_for('index'))
            else:
                flash("Your email or password doesn't match!", "error")
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    # delete session
    logout_user()
    flash("You've been logged out! Come back soon!", "success")
    return redirect(url_for('index'))


@app.route('/')
def index():
    return 'Hey'


if __name__ == "__main__":
    models.initialize()
    try:
        models.User.create_user(
            username='robindymer',
            email='robindymer@hotmail.com',
            password='password123',
            admin=True
        )
    except ValueError:
        pass
    app.run(debug=DEBUG, host=HOST, port=PORT)