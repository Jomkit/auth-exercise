from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField

def usernameField(): 
    return StringField('Username')
def passwordField(): 
    return PasswordField('Password')

class LoginForm(FlaskForm):
    username = usernameField()
    password = passwordField()
    
class RegisterForm(FlaskForm):
    """Register new user"""
    username = usernameField()
    password = passwordField()
    email = StringField("Email")
    first_name = StringField("First Name")
    last_name = StringField("Last Name")

class FeedbackForm(FlaskForm):
    """User Feedback"""
    title = StringField("Title")
    content = TextAreaField("Content")