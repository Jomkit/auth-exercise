from flask import Flask, render_template, redirect, flash, session, g, request
from functools import wraps
from models import db, connect_db, User, Feedback
from forms import RegisterForm, LoginForm, FeedbackForm
from SECRETS import secret_key

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///auth_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
app.config['SECRET_KEY'] = secret_key

app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False

connect_db(app)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('username') is None:
            flash('Unauthorized access', 'danger')
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def check_same_user(username):
    # User logged in, fetch user data for user page attempting to be access
    user = User.query.get_or_404(username)
    # Check session user aka logged in user is same as user being accessed
    if session.get('username', False) != user.username:
        # send to own user page
        flash('Unauthorized access', 'warning')
        return redirect(f'/users/{session["username"]}')
    else: 
        return user

@app.route('/')
def redirect_to_register():
    return redirect('/register')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle registering new users"""

    if session.get('username'):
        flash('Already logged in', 'warning')
        return redirect(f"/users/{session['username']}")
    
    form = RegisterForm()

    if form.validate_on_submit():
        data = form.data
        data.pop('csrf_token')
        new_user = User.register(**data)
        db.session.add(new_user)
        db.session.commit()
        session['username'] = new_user.username
        
        flash(f'Account registered, welcome {new_user.username}!', 'success')
        return redirect(f'/users/{new_user.username}')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    """Get login page and redirect to user page if user log in info correct or
    if logged in user attempts to access login page"""
    if session.get('username'):
        flash('Already logged in', 'warning')
        return redirect(f"/users/{session['username']}")
    
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)

        if user:
            session['username'] = user.username #keep logged in
            flash(f'Welcome back {user.username}', 'info')
            return redirect(f'/users/{user.username}')
        
        flash('User credentials incorrect', 'warning')
        return redirect('/login')
    
    return render_template('login-form.html', form=form)

@app.route('/users/<string:username>')
@login_required
def show_user_info(username):
    """Show user's information except password"""

    user = check_same_user(username)
    
    return render_template('user-info.html', user=user)

@app.route('/users/<string:username>/delete', methods=['POST'])
@login_required
def delete_user(username):
    """Delete user.
    Should first check that the user requesting to delete is the same
    as the current user logged in"""

    # Check user is user, else redirect to user page
    user = check_same_user(username)
    db.session.delete(user)
    db.session.commit()
    
    session.pop('username')
    flash('Account deleted', 'danger')
    return redirect('/')
    
@app.route('/users/<string:username>/feedback/add', methods=['GET', 'POST'])
@login_required
def feedback_form(username):
    """Get and post feedback"""
    
    user = check_same_user(username)

    form = FeedbackForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data

        new_fb = Feedback(title=title, content=content, username=user.username)
        db.session.add(new_fb)
        db.session.commit()

        flash('Feedback added!', 'success')
        return redirect(f'/users/{user.username}')
    
    return render_template('feedback-form.html', form=form)

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