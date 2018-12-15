# Importing external package dependency:
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, TextField, RadioField, SelectField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms import ValidationError
from wtforms.validators import DataRequired, Email, EqualTo, Length


# Select Choices for userPlan:
pnp_choices = [('Amazon', 'Amazon'), ('Flipkart', 'Flipkart'), ('Snapdeal', 'Snapdeal')]


# Form for User Registration:
class RegistrationForm(FlaskForm):
    email = StringField("Email: ", validators=[DataRequired(message="Email is a required field."), Email(message="Please enter a valid email id.")])
    username = StringField("Username: ", validators=[DataRequired(message="Username is a required field.")])
    userPlan = SelectField("Member Plan: ", choices=pnp_choices, validators=[DataRequired()])
    password = PasswordField("Password: ", validators=[DataRequired(message="Password is a required field."), EqualTo("pass_confirm", message="Passwords must match!"), Length(min=6, max=25, message="Please use between 6 and 25 characters!")])
    pass_confirm = PasswordField("Confirm Password: ", validators=[DataRequired(message="This is a required field.")])
    submit = SubmitField("Register")

    # Checking if entered Email has already been registered:
    def check_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError("Please use a different email address!")
    # Checking availability of User opted 'username':
    def check_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError("Please use a different username!")



# Form for User Account Login process:
class LoginForm(FlaskForm):
    email = StringField("Email: ", validators=[DataRequired(message="Email is a required field."), Email(message="Please enter a valid email id.")])
    password = PasswordField("Password: ", validators=[DataRequired(message="Password is a required field."), Length(max=25)])
    submit = SubmitField("Login")


# Form for raising Support tickets [Needs to be modified for Dynamic SelectField entries]:
class SupportForm(FlaskForm):
    email = StringField("Email Address: ", validators=[DataRequired(), Email()])
    issueCategory = StringField("Select Category: ", validators=[DataRequired()])
    issueType = StringField("Issue Type: ", validators=[DataRequired()])
    issueDescription = TextAreaField("Issue Description: ", validators=[DataRequired()])
    submit = SubmitField("Report")


# Form for User to initiate Password Reset request:
class ForgotPasswordForm(FlaskForm):
    email = StringField("Email Address: ", validators=[DataRequired()])
    submit = SubmitField("Reset Password")


# Form for updating User Password in our Database:
class PasswordResetForm(FlaskForm):
    email = StringField("Email Address: ", validators=[DataRequired()])
    new_password = PasswordField("New Password: ", validators=[DataRequired(message="Password is a required field."), EqualTo("new_pass_confirm", message="Passwords must match!"), Length(min=6, max=25, message="Please use between 6 and 25 characters!")])
    new_pass_confirm = PasswordField("Confirm New Password: ", validators=[DataRequired(message="This is a required field.")])
    submit = SubmitField("Update Password")


# Form for Amazon User Profile:
class AMZUserProfile(FlaskForm):
    email = StringField("Email Address: ")
    username = StringField("Username: ")
    social_id = StringField("Member ID: ")
    first_name = StringField("First Name: ")
    last_name = StringField("Last Name: ")
    userPlan = StringField("Member Plan: ")
    userAddress = StringField("Postal Address: ")
    userCity = StringField("Residing City: ")
    userState = StringField("State: ")
    userCountry = StringField("Country: ")
    company_name = StringField("Company Name: ")
    company_url = StringField("Company URL: ")
    facebook_url = StringField("Facebook URL: ")
    linkedin_url = StringField("LinkedIn URL: ")
    submit = SubmitField("Update Profile")


# Form for User to manually upload AMZ Seller Central data:
class FileUploadForm(FlaskForm):
    order_report = FileField(validators=[DataRequired()])
    return_report = FileField(validators=[DataRequired()])
    payment_report = FileField(validators=[DataRequired()])
    payment1_report = FileField()
    submit = SubmitField("Upload")


# Form for User to upload Google Drive link for AMZ Seller Central data::
class LinkUploadForm(FlaskForm):
    orders_amz_url = StringField(validators=[DataRequired()])
    returns_amz_url = StringField(validators=[DataRequired()])
    payments_amz_url = StringField(validators=[DataRequired()])
    payments1_amz_url = StringField()
    submit = SubmitField("Upload")
