# Importing external package dependency:
import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, url_for, redirect, flash, session, abort, jsonify
from flask_migrate import Migrate
from flask_login import LoginManager, AnonymousUserMixin
from flask_mail import Mail, Message
from flask_sqlalchemy import sqlalchemy, SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_moment import Moment
from logging.handlers import SMTPHandler

# Importing internal module dependency:
from sellerhub.config import config, BaseConfig
from sellerhub.logger import setup_logging


# Setting File Upload Extension types:
ALLOWED_EXTENSIONS = set(["csv", "txt", "tsv", "xlsx"])


# Initiating our primary Flask application. '__name__' shall currently direct to app.py:
app = Flask(__name__, static_folder = "static", template_folder="templates")
app.config.from_object(BaseConfig)

# Setting up logging levels [Currently with 'default' value]:
setup_logging()

# Database BaseConfig(object) settings for SQLite:
login_manager = LoginManager()
db = SQLAlchemy(app)
Migrate(app, db)
login_manager.init_app(app)
login_manager.login_view = "login"

# Email Push Initiation and Logging + Setting Sessions:
mail = Mail(app)

# Creating 'Guest' User:
class Anonymous(AnonymousUserMixin):
  def __init__(self):
    self.username = "Guest"
login_manager.anonymous_user = Anonymous


CSRFProtect(app)
moment = Moment(app)


from sellerhub import models, errors
if not app.debug:
    if app.config["MAIL_SERVER"]:
        auth = None
        if app.config["MAIL_USERNAME"] or app.config["MAIL_PASSWORD"]:
            auth = (app.config["MAIL_USERNAME"], app.config["MAIL_PASSWORD"])
        secure = None
        if app.config["MAIL_USE_TLS"] or app.config["MAIL_USE_SSL"]:
            secure = ()
        mail_handler = SMTPHandler(
            mailhost = (app.config["MAIL_SERVER"], app.config["MAIL_PORT"]),
            fromaddr = "no-reply@" + app.config["MAIL_SERVER"],
            toaddrs = app.config["ADMINS"], subject="SellerHub Failure",
            credentials=auth, secure=secure)
        # Ignoring Warnings and Informational or Debugging messages:
        mail_handler.setLevel(logging.ERROR)
        app.logger.addHandler(mail_handler)
