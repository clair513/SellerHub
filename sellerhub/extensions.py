# Importing required external packages:
import os, fnmatch
import json
import requests
from datetime import datetime
from functools import wraps
from flask import flash, redirect, url_for, request
from flask_login import current_user
from flask_mail import Message
import urllib.request

# Importing internal module dependency:
from sellerhub import app, mail, db
from sellerhub.config import BaseConfig
from sellerhub.models.db_models import User, Support, Transactions


# [BOT Detection] To cross-check User response from reCaptcha v2:
def is_human(captcha_response):
    """
    DOCSTRING: Validating recaptcha response from google serverself.
    Returns 'True' if captcha test passed for submitted form,
    else returns 'False'.
    """
    secret = BaseConfig.RECAPTCHA_PRIVATE_KEY
    payload = {"response":captcha_response, "secret":secret}
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", payload)
    response_text = json.loads(response.text)
    return response_text["success"]


# Script to check for confirmed Users:
def check_confirmed(func):
    """
    DOCSTRING: Set of decorators for keeping a check on User access to various pages.
    """
    @wraps(func)
    def decorated_function(*args, **kwargs):
        # If User found but not yet confirmed, push him to 'Unconfirmed' page:
        if current_user.confirmed is False:
            flash("Please confirm your account!")
            return redirect(url_for("unconfirmed"))
        return func(*args, **kwargs)
    return decorated_function


# Script to push emails in any required scenario to Users:
def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients = [to],
        html = template,
        sender = app.config["MAIL_DEFAULT_SENDER"]
    )
    mail.send(msg)


# [Available for both, Active & Disabled Users] Dynamically updating 'UPGRADE COST' for every User. [Saved as 'upgrade_bapro_cost' & 'upgrade_proprem_cost' in Users Table]:
@app.before_request
def before_request():
    if current_user.is_anonymous:
        pass
    else:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        if current_user.userPlan == "Amazon" and current_user.account_status == "Active" and current_user.account_expiry_date == datetime.utcnow().date():
            current_user.account_status = "Disabled"
            current_user.paid = False
            db.session.commit()


# Locates list of file in a directory as per matching pattern:
def find_local_file(pattern, path):
    # Use Case: find_local_file("acer18__amz__orders__*","amz_uploaded_files/") --> Returns either an empty List like [] or with all available item/file paths like ['amz_uploaded_files/acer18__amz__orders__orders.txt'].
    result = []
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                result.append(os.path.join(root, name))
    return result


# [Not Implemented] Checking file extension for file being uploaded ['AMZ File Upload-Manual']:
def allowed_file(filename):
    """
    DOCSTRING: http://flask.pocoo.org/docs/0.12/patterns/fileuploads/
    """
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# [Below 3 NOT IMPLEMENTED] Downloads file from Google Drive based on URL provided:
def download_file_from_google_drive(id, destination):
    URL = "https://docs.google.com/uc?export=download"
    session = requests.Session()
    response = session.get(URL, params = { 'id' : id }, stream = True)
    token = get_confirm_token(response)
    if token:
        params = { 'id' : id, 'confirm' : token }
        response = session.get(URL, params = params, stream = True)
    save_response_content(response, destination)

def get_confirm_token(response):
    for key, value in response.cookies.items():
        if key.startswith('download_warning'):
            return value
    return None

def save_response_content(response, destination):
    CHUNK_SIZE = 32768
    with open(destination, "wb") as f: # Write Permission Error to 'destination' as of now.
        for chunk in response.iter_content(CHUNK_SIZE):
            if chunk: # filter out keep-alive new chunks
                f.write(chunk)
# [Above 3 go hand-in-hand] Just using 1st automates rest 2 functions.


# Terminal/Shell References:
@app.shell_context_processor
def make_shell_context():
    return {"db": db, "User": User, "Support": Support, "Transactions": Transactions}
