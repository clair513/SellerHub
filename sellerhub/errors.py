from flask import render_template, request
from sellerhub import app, db
from flask_wtf.csrf import CSRFError


# CSRF Error:
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template("errors/csrf_error.html", reason=e.description), 400


# 401 Unauthorized Access:
@app.errorhandler(401)
def unauthorized(error):
    return render_template("errors/401.html"), 401


# 403 Access Forbidden:
@app.errorhandler(403)
def forbidden(error):
    return render_template("errors/403.html"), 403


# File not Found:
@app.errorhandler(404)
def not_found_error(error):
    return render_template("errors/404.html"), 404


# Internal Server Error:
@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template("errors/500.html"), 500
