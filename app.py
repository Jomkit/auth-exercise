from flask import Flask, render_template, redirect, flash, session, abort, request
from flask_mail import Mail, Message
from functools import wraps
from models import db, connect_db, User, Feedback
from forms import RegisterForm, LoginForm, FeedbackForm, ResetPasswordForm
from SECRETS import secret_key, MAIL_USERNAME, MAIL_PW
import secrets

app = Flask(__name__)
mail = Mail(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = MAIL_USERNAME 
app.config['MAIL_PASSWORD'] = MAIL_PW
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///auth_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
app.config['SECRET_KEY'] = secret_key

app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False

connect_db(app)

# Decorator that checks login status, redirects to login if no one logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('username') is None:
            flash('User must log in first', 'danger')
            return redirect('/login')
            
        return f(*args, **kwargs)
    return decorated_function

def check_same_user(username):
    # User logged in, fetch user data for user page attempting to be access
    user = User.query.get_or_404(username)
    curr_user = User.query.get_or_404(session.get('username'))

    # if curr_user is admin, they have free access
    if curr_user.is_admin == True:
        return curr_user

    # Check session user aka logged in user is same as user being accessed
    if user.username != curr_user.username:
        # error 401 - unauthorized access
        abort(401)
    else: 
        return user

@app.errorhandler(404)
def user_not_found(e):
    """In the case of this app, 404 will result from a user instance
    not being found
    """
    return render_template('error-page.html', e=e), 404 

@app.errorhandler(401)
def unauthorized_access(e):
    """In the case of this app, 401 will result from attempting to access another user's account
    """
    return render_template('error-page.html', e=e), 401

################ ROUTES ####################

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

    dest_username = username
    user = check_same_user(dest_username)

    if user.is_admin == True:
        dest_user = User.query.get_or_404(dest_username)
        return render_template('user-info.html', user=dest_user, admin=user)
    
    return render_template('user-info.html', user=user)

@app.route('/reset-email', methods=['GET', 'POST'])
def send_reset_email():
    """Send an email to reset user's password

    First verify that the username and email match, then send an email
    to the user's email with a link to a rest-password form
    """
    # Check that user exists and that the email matches

    # if posting, send recovery email
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.get(username)

        if not user:
            flash('Username incorrect', 'warning')
            return redirect('/reset-email')
        elif user.email != request.form['email']:
            flash('Username and email address do not match', 'danger')
            return redirect('/reset-email')
        
        reset_token = secrets.token_urlsafe()
        msg = Message(subject='Recovery Email',
                      sender=MAIL_USERNAME,
                      recipients=[user.email])
        email_html = f'<p>Hello {user.username}, <br> A password reset was recently requested for your account. <br> If this is you, please follow the link below, and type in the unique token: {reset_token} <br> <a href="http://localhost:5000/reset-password">LINK</a> <br> </p>'
        msg.html = email_html
        mail.send(msg)

        user.reset_token = reset_token
        db.session.commit()

        flash('Please check your email for the recovery email', 'success')
        return redirect('/')
        
    return render_template('reset-email-form.html')

@app.route('/reset-password', methods=['GET','POST'])
def reset_password():
    """Route for resetting password

    User requesting to reset their password must have the appropriate 
    reset_token, sent via email
    NOTE: consider hashing the token
    """
    form = ResetPasswordForm()
    if form.validate_on_submit():
        # get the user instance by reset token, should only have one
        user = User.query.filter_by(reset_token=form.token.data).one()

        if user:
            user.password = user.newPassword(form.new_password.data)
            user.reset_token = None
            db.session.commit()
            flash('Password successfully reset!', 'success')
            return redirect('/login')

    return render_template('reset-password-form.html', form=form)

@app.route('/users/<string:username>/delete', methods=['POST'])
@login_required
def delete_user(username):
    """Delete user.
    Should first check that the user requesting to delete is the same
    as the current user logged in"""

    # Check user is user or admin, else redirect to user page
    user = check_same_user(username)

    if user.is_admin == True:
        # user is actually admin and needs to be renamed, 
        # destination user needs to be reassigned to user
        admin = user
        user = User.query.get_or_404(username)

        db.session.delete(user)
        db.session.commit()

        flash(f'Admin {user.username} has deleted {user.username}', 'warning')
        return redirect(f'users/{admin.username}')
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

    if user.is_admin == True:
        # user is actually admin and needs to be renamed, 
        # destination user needs to be reassigned to user
        admin = user
        user = User.query.get_or_404(username)
        

    form = FeedbackForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data

        new_fb = Feedback(title=title, content=content, username=user.username)
        db.session.add(new_fb)
        db.session.commit()

        flash('Feedback added!', 'success')
        return redirect(f'/users/{user.username}')
    
    return render_template('feedback-form.html', form=form, admin=admin)

@app.route('/feedback/<int:id>/update', methods=['GET', 'POST'])
@login_required
def update_feedback(id):
    """Update a user's feedback"""

    fb = Feedback.query.get_or_404(id)
    form = FeedbackForm(obj=fb)
    user = check_same_user(fb.user.username)
    if user.is_admin == True:
        # user is actually admin and needs to be renamed, 
        # destination user needs to be reassigned to user
        admin = user
        user = User.query.get_or_404(fb.user.username)

    if form.validate_on_submit():
        fb.title = form.title.data
        fb.content = form.content.data
        
        db.session.add(fb)
        db.session.commit()
        flash('Feedback updated!', 'success')
        return redirect(f'/users/{user.username}')

    return render_template('feedback-update-form.html', form=form, admin=admin)

@app.route('/feedback/<string:id>/delete', methods=['POST'])
@login_required
def delete_feedback(id):
    """Delete user.
    Should first check that the user requesting to delete is the same
    as the current user logged in"""
    fb = Feedback.query.get_or_404(id)
    # Check user is user, else redirect to user page
    user = check_same_user(fb.user.username)
    db.session.delete(fb)
    db.session.commit()
    
    flash('Feedback deleted', 'danger')
    return redirect(f'/users/{user.username}')

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
    
