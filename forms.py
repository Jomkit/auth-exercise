from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired

def usernameField(): 
    return StringField('Username', validators=[DataRequired()])
def passwordField(): 
    return PasswordField('Password', validators=[DataRequired()])

class LoginForm(FlaskForm):
    username = usernameField()
    password = passwordField()
    
class RegisterForm(FlaskForm):
    """Register new user"""
    username = usernameField()
    password = passwordField()
    email = StringField("Email", validators=[DataRequired()])
    first_name = StringField("First Name", validators=[DataRequired()])
    last_name = StringField("Last Name", validators=[DataRequired()])

class FeedbackForm(FlaskForm):
    """User Feedback"""
    title = StringField("Title", validators=[DataRequired()])
    content = TextAreaField("Content", validators=[DataRequired()])