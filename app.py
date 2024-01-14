from flask import Flask, render_template, redirect, flash, session
from models import db, connect_db, User
from forms import RegisterForm, LoginForm
from SECRETS import secret_key

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///auth_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
app.config['SECRET_KEY'] = secret_key

app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False

connect_db(app)

@app.route('/')
def redirect_to_register():
    return redirect('/register')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle registering new users"""
    form = RegisterForm()

    if form.validate_on_submit():
        data = form.data
        data.pop('csrf_token')
        new_user = User.register(**data)
        db.session.add(new_user)
        db.session.commit()
        session['username'] = new_user.username
        
        flash(f'Account registered, welcome {new_user.username}!', 'success')
        return redirect('/secret')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)

        if user:
            session['username'] = user.username #keep logged in
            flash(f'Welcome back {user.username}', 'info')
            return redirect('/secret')
        
        flash('User credentials incorrect', 'warning')
        return redirect('/login')
    
    return render_template('login-form.html', form=form)

@app.route('/logout', methods=['POST'])
def logout():
    """Logs out user and redirects to login"""
    session.pop("username")
    flash('Come back soon!', 'success')
    return redirect('/login')

@app.route('/secret')
def show_secret():
    if session.get('username'):
        username = session['username']
        user = User.query.filter_by(username=username).first()
        users = User.query.all()

        return render_template('secret.html', users=users, user=user)
    else:
        flash('Please login to access secret page', 'danger')
        return redirect('/login')