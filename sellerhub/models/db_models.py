# Importing external package dependency:
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime
from hashlib import md5

# Importing required internal packages:
from sellerhub import login_manager
from sellerhub import db


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# Generates a local 'ticket_id' in 'users' table, that can be internally used for tracking issue resolution process:
def generate_social_id(size=10, chars=string.digits):
    return "".join(random.SystemRandom().choice(chars) for _ in range(size))

# Generates a local 'ticket_id' that can be internally used for tracking issue resolution process:
def generate_ticket_id(size=15, chars=string.digits):
    return "".join(random.SystemRandom().choice(chars) for _ in range(size))


# [MASTER TABLE] Holds primary information about User Registeration & Authentication life-cycle:
class User(db.Model, UserMixin):
    """
    UserMixin provides default implementations for few methods from Flask-Login
    like: is_active, is_authenticated, is_anonymous, get_id
    Additionally, unique 'social_id' is being generated for each registered User. And Passwords are being stored in encrypted format.
    """

    __tablename__ = "users"

    id = db.Column(db.Integer)
    social_id = db.Column(db.String, nullable=False)
    email = db.Column(db.String, index=True, nullable=False)
    username = db.Column(db.String, nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)
    first_name = db.Column(db.String, nullable=True)
    last_name = db.Column(db.String, nullable=True)
    userAddress = db.Column(db.String, nullable=True)
    userCity = db.Column(db.String, nullable=True)
    userState = db.Column(db.String, nullable=True)
    userCountry = db.Column(db.String, nullable=True)
    company_name = db.Column(db.String, nullable=True)
    company_url = db.Column(db.String, nullable=True)
    facebook_url = db.Column(db.String, nullable=True)
    linkedin_url = db.Column(db.String, nullable=True)
    amz_orders_url = db.Column(db.String, nullable=True)
    amz_returns_url = db.Column(db.String, nullable=True)
    amz_payments_url = db.Column(db.String, nullable=True)
    amz_payments1_url = db.Column(db.String, nullable=True)
    pwdUpdate_requestedOn = db.Column(db.DateTime, nullable=True)
    pwdUpdate_requestIP = db.Column(db.String, nullable=True)
    passwordUpdated_on = db.Column(db.DateTime, nullable=True)
    userPlan = db.Column(db.String, nullable=False) #Added from Registration form.
    paid = db.Column(db.Boolean, nullable=False, default=False)
    account_status = db.Column(db.String, nullable=False, default="New") #New/Active/Disabled
    account_expiry_date = db.Column(db.DateTime, nullable=True)
    payable_amount = db.Column(db.Integer, nullable=False, default=299) #SellerHub format
    razor_amount = db.Column(db.Integer, nullable=False, default=29900) #RazorPay format
    pay_difference = db.Column(db.Integer, nullable=True, default=0) #SellerHub format
    razor_difference = db.Column(db.Integer, nullable=True, default=0) #RazorPay format
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, email, username, password, userPlan):
        self.social_id = generate_social_id()
        self.email = email
        self.username = username
        self.userPlan = userPlan
        self.password_hash = generate_password_hash(password)
        self.registered_on = datetime.utcnow()

    # Setting Table Primary key and Unique keys:
    __table_args__ = (db.PrimaryKeyConstraint("id", name="pk_users"), db.UniqueConstraint("social_id", "email", "username", name="uq_users_1"))

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_password(self, value):
        self.password_hash = generate_password_hash(value)

    @property
    def password(self):
        #The password property will call werkzeug.security and write the result to the 'password_hash' field.
        #Reading this property will return an error.
        raise AttributeError("password is not a readable attribute")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    # Convert specified fields from 'users' Table to a dictionary that can go into a JSON, if reqd. :
    def to_dict(self):
        return {"social_id": self.social_id, "email": self.email, "username": self.username, "registered_on": self.registered_on, "confirmed_on": self.confirmed_on, "city": self.userCity, "state": self.userState, "country": self.userCountry}

    # Generates Gravatar URL to User model:
    def avatar(self, size):
        digest = md5(self.email.lower().encode("utf-8")).hexdigest()
        return "https://www.gravatar.com/avatar/{}?d=identicon&s={}".format(digest, size)



# Holds records of support tickets being generated:
class Support(db.Model):

    __tablename__ = "support"

    id = db.Column(db.Integer)
    ticket_id = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer)  # Back-references to 'users' table for 'id' values, else left empty.
    issueCategory = db.Column(db.String, index=True, nullable=False)
    issueType = db.Column(db.String, nullable=False)
    issueDescription = db.Column(db.String, nullable=True)
    reported_on = db.Column(db.DateTime, index=True, nullable=False)
    ticket_status = db.Column(db.String, nullable=False, default="Open")
    statusChange_on = db.Column(db.DateTime, nullable=True)
    statusChange_by = db.Column(db.String, nullable=True)

    def __init__(self, email, issueCategory, issueType):
        self.ticket_id = generate_ticket_id()
        self.email = email
        self.issueCategory = issueCategory
        self.issueType = issueType
        self.reported_on = datetime.utcnow()

    # __table_args__ value must be a tuple, dict, or None
    __table_args__ = (db.PrimaryKeyConstraint("id", name="pk_support"), db.UniqueConstraint("ticket_id", name="uq_support_1"))

    # Pulling all tickets raised by all Users:
    def get_all_tickets():
        """ DOCSTRING: Returns all tickets raised by all Users """
        return Support.query.order_by("email").all()

    # Pulling all Open Tickets for all Users:
    def get_all_open_tickets():
        """ DOCSTRING: Pulls all 'Open' status Tickets of support table """
        return Support.query.filter_by(ticket_status = "Open").all()

    # Pulling all tickets raised by a particular User:
    def get_all_tickets_perUser(email):
        """ DOCSTRING: Returns all tickets raised by a particular User based on his email """
        return Support.query.filter_by(email).all()

    # Converting specified fields to a Dictionary that can go into a JSON, if reqd. later:
    def to_dict(self):
        return {"ticket_id": self.ticket_id, "email": self.email, "issueCategory": self.issueCategory, "issueType": self.issueType, "issueDescription":self.issueDescription, "reported_on": self.reported_on, "ticket_status": self.ticket_status, "statusChange_on": self.statusChange_on}


# Holds Payment records extracted from RazorPay JSON dump:
class Transactions(db.Model):

    __tablename__ = "transactions"

    id = db.Column(db.Integer, primary_key=True)
    razor_id = db.Column(db.String, nullable=True)
    type = db.Column(db.String, nullable=True)
    amount = db.Column(db.Integer, nullable=True) #RazorPay format
    currency = db.Column(db.String, nullable=True)
    razor_status = db.Column(db.String, nullable=True)
    international = db.Column(db.Boolean, nullable=True)
    method = db.Column(db.String, nullable=True)
    capture_status = db.Column(db.Boolean, nullable=True)
    description = db.Column(db.String, nullable=True)
    user_bank = db.Column(db.String, nullable=True)
    user_wallet = db.Column(db.String, nullable=True)
    razor_email = db.Column(db.String, nullable=True)
    razor_phone = db.Column(db.String, nullable=True)
    trans_fee = db.Column(db.Integer, nullable=True) #RazorPay format
    trans_tax = db.Column(db.Integer, nullable=True) #RazorPay format
    trans_error_code = db.Column(db.String, nullable=True)
    trans_error_desc = db.Column(db.String, nullable=True)
    trans_created_at = db.Column(db.DateTime, nullable=True)
    trans_item = db.Column(db.String, nullable=True)



# Add-on function to create Admin Users (if later required):
def create_admin():
    db.session.add(User(social_id=generate_social_id(), email="admin@sunindudata.com", username="admin", password="Password123", admin=True, confirmed=True, confirmed_on=datetime.utcnow(), paid=True, userPlan="Amazon", registered_on=datetime.utcnow()))
    # Flush the remaining changes and commit the transaction:
    db.session.commit()
