"""
Token generation for Email verification process while a User tries to register.
"""
# Importing external package dependency:
from itsdangerous import URLSafeTimedSerializer
from sellerhub import app, db


# Following two funcs process Email verification token during Registration process:
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return serializer.dumps(email, salt=app.config["SECURITY_PASSWORD_SALT"])

def confirm_token(token, expiration=86400):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        email = serializer.loads(token, salt=app.config["SECURITY_PASSWORD_SALT"], max_age=expiration)
    except:
        return False
    return email


# Following two funcs process Email verification token during Password Reset process:
def generate_pwdreset_token(email):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return serializer.dumps(email, salt="iDq87Ao09VbbQzO02npT5vx7X36zHc")

def pwdreset_token(token, expiration=86400):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        email = serializer.loads(token, salt="iDq87Ao09VbbQzO02npT5vx7X36zHc", max_age=expiration)
    except:
        return False
    return email
