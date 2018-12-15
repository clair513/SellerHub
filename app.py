"""
This is our primary application script for production.
"""

# Importing required external libraries:
import os
import json
import httpagentparser
import mpu.io as mio
import urllib.request
import razorpay
from werkzeug import secure_filename
from datetime import datetime, timedelta
from flask import Flask, render_template, request, url_for, redirect, flash, session, abort
from sellerhub import app, db
from flask_login import login_user, login_required, logout_user, current_user

# Importing dependent internal modules:
from sellerhub.forms import LoginForm, RegistrationForm, SupportForm, ForgotPasswordForm, PasswordResetForm, AMZUserProfile, FileUploadForm, LinkUploadForm
from sellerhub.models.db_models import User, Support, Transactions
from sellerhub.config import config, BaseConfig
from sellerhub.confirmation_tokens import generate_confirmation_token, confirm_token, generate_pwdreset_token, pwdreset_token
from sellerhub.extensions import send_email, check_confirmed, is_human, allowed_file, download_file_from_google_drive, get_confirm_token, save_response_content, find_local_file
from sellerhub.amazon.orders.ordersFile_parsing import file_parser, columns_renamer
from sellerhub.amazon.orders.ordersFile_preprocessing import data_sanity_check, data_substitution, day_of_week, phase_of_day, total_earnings, month_and_festivals, weekday_end
from sellerhub.amazon.orders.ordersFile_columnization import purchaseQuantity_perDate_month, totalEarnings_perDate_month, fastSlow_monthlyItems, single_bucket_bulk_order, removing_duplicate_columns, state_col_restructuring, metro_premium_city, repeat_new_unknown, discounted_item


# RazorPay Setup:
razorpay_client = razorpay.Client(auth=(app.config["RAZORPAY_API_KEY"], app.config["RAZORPAY_SECRET_KEY"]))
razorpay_client.set_app_details({"title" : "SellerHub", "version" : "0.1"})


# [Navbar 'SellerHub' tab] Landing/Home Page View:
@app.route("/")
def landing_page():
    return render_template("main/landing_page.html")


# [Navbar 'Product & Pricing' tab] Product & Pricing Page:
@app.route("/amz_pnp")
def pnp():
    return render_template("main/pnp.html")


# [Navbar 'Blog' tab] Blog tab View:
@app.route("/blog")
def blog():
    return render_template("main/blog.html")


# [Navbar 'Contact Us' tab] Support View:
@app.route("/support", methods=["GET","POST"])
def support():
    form = SupportForm()
    if form.validate_on_submit():
        support = Support(email=form.email.data, issueCategory=form.issueCategory.data, issueType=form.issueType.data, issueDescription=form.issueDescription.data.strip())
        db.session.add(support)
        db.session.commit()
        # If a registered User logs ticket, capture his 'id' from 'user' table:
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            for item in Support.query.filter_by(email=form.email.data).all():
                item.user_id = user.id
                db.session.commit()
        html = render_template("main/supportTicket_userInform.html")
        subject = "SellerHub Incident | Ticket Number: " + support.ticket_id
        send_email(support.email, subject, html)
        # Flashing successful submission confirmation:
        flash("Your issue has been registered with us. Thank You!")
        # Routing User to Home page:
        return redirect(url_for("landing_page"))
    return render_template("main/support.html", form=form)


# User Registration or Signup View:
@app.route("/register", methods=["GET","POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Grabbing User based of entered Email:
        existingUser = User.query.filter_by(email=form.email.data).first()
        # Currently not allowing Snapdeal or Flipkart Member Plan entries:
        if form.userPlan.data=="Flipkart" or form.userPlan.data=="Snapdeal":
            flash(u"Highly appreciate your interest but currently we only have 'Amazon' member plan available, so kindly select accordingly.")
            return render_template("main/users_general/register.html", form=form)
        # Checking for username duplicacy:
        if User.query.filter_by(username=form.username.data).first():
            flash(u"Please select a different username!")
            return render_template("main/users_general/register.html", form=form)
        # If User had previously registered and is still not confirmed:
        elif existingUser and existingUser.confirmed==False:
            flash(u"Account already exists! Please check your mailbox (possibly Spam folder) for a verification link to click on. In case of any issues, kindly reach our Support team.")
            return redirect(url_for("unconfirmed"))
        # If User had previously registered and is also confirmed:
        elif existingUser and existingUser.confirmed:
            flash(u"Account already exists! Please login with your credentials. In case of any issues, kindly reach our Support team.")
            return redirect(url_for("login"))
        # If new User:
        else:
            # Creating User object and simultaneously tracking User IP Address, Browser, Operating System, City, State, Country, Continent:
            user = User(email=form.email.data, username=form.username.data, userPlan=form.userPlan.data, password=form.password.data)
            user.account_status = "New"
            # Adding this User to our 'User' database, and commiting changes:
            db.session.add(user)
            db.session.commit()
            # Pushing verification email to User:
            token = generate_confirmation_token(user.email)
            confirm_url = url_for("confirm_email", token=token, _external=True)
            html = render_template("main/users_general/activate_email.html", confirm_url=confirm_url)
            subject = "Verify your Email!"
            send_email(user.email, subject, html)
            flash(u"Member account created successfully!")
            # Routing User to login page:
            return redirect(url_for("unconfirmed"))
    else:
        flash(u"Kindly fill in below details carefully! If previously registered with us, kindly check mailbox (or Spam folder), or else click on 'Support' for assistance.")
    # Rendering a template for User to register/signup:
    return render_template("main/users_general/register.html", form=form)


# No dedicated HTML page required as this helper function/view just redirects User after clicking email verification link to Login page:
@app.route("/confirm/<token>")
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash("Your confirmation link is invalid or has expired. Kindly contact our support team for further assistance!")
        return redirect(url_for("support"))
    user = User.query.filter_by(email=email).first()
    # Ideally below first condition is not going to happen (unless accidental). [Though link expires in 24 hours] :
    if user.confirmed and user.paid:
        # Fully authorized user who accidentally might have clicked link in mail. Routing to User-specific Profile page.
        return redirect(url_for("#"))
    # This is our ideal step that should happen. User properly confirms email and is
    else:
        user.confirmed = True
        user.confirmed_on = datetime.utcnow()
        user.paid = False
        db.session.add(user)
        db.session.commit()
        flash("Account successfully confirmed!")
        return redirect(url_for("login"))


# User Login View:
@app.route("/login", methods=["GET","POST"])
def login():
    form = LoginForm()
    # Checking if valid form has been submitted:
    if form.validate_on_submit():
        # Grabbing User based of entered Email:
        user = User.query.filter_by(email=form.email.data).first()
        # If User does not exist in our records:
        if user is None:
            flash(u"No matching records found. Kindly register!")
            return redirect(url_for("register"))
        # If User found but yet not yet confirmed:
        elif user.confirmed is False:
            flash(u"Email account yet not confirmed!")
            return redirect(url_for("unconfirmed"))
        # If Password mismatch:
        elif user.check_password(form.password.data)==False:
            flash(u"Incorrect password! Please retry or click on 'Forgot Password' if you can't recollect.")
            return redirect(url_for("login"))
        # User has properly logged in but hasn't yet Paid --> Re-routing back to Payments page:
        elif user.account_status=="New" and user.paid==False and user.pay_difference==0:
            login_user(user)
            flash(u"Just one last step to unlock your treasure.")
            return redirect(url_for("amz_user_payments", username=user.username))
        # User has properly logged in BUT paid PARTIALLY --> Re-routing to PENDING PAYMENT page:
        elif user.account_status=="New" and user.paid==False and user.pay_difference!=0:
            login_user(user)
            flash(u"Kindly make remaining payment to proceed. For any issues, please reach our Support team.")
            return redirect(url_for("amz_user_payments", username=user.username))
        # Existing User who hasn't yet renewed account --> Re-routing back to Payments page:
        elif user.account_status == "Disabled" and user.paid==False and user.pay_difference==0:
            login_user(user)
            flash(u"Kindly renew your account for uninterrupted access. For any issues, please reach our Support team.")
            return redirect(url_for("amz_user_payments", username=user.username))
        # Existing User who made PARTIAL Payment to renew --> Re-routing to PENDING PAYMENT page:
        elif user.account_status == "Disabled" and user.paid==False and user.pay_difference!=0:
            login_user(user)
            flash(u"Kindly make remaining payment to renew your account for uninterrupted access. For any issues, please reach our Support team.")
            return redirect(url_for("amz_user_payments", username=user.username))
        # IDEAL (PAID & ACTIVE) USER --> If user is registered, checking Password and Payment match:
        else:
            # Logging in User:
            login_user(user)
            # Greeting with a welcome message:
            flash(u"Login successful!")
            # Grabbing the actual page User was trying to access/request:
            next = request.args.get("next")
            # User wasn't trying to access any particular page --> User 'File Upload' page:
            if next == None or not next[0]=="/":
                next = url_for("amz_upload_manual", username=user.username)
            # But if they were trying to access any particular page, redirecting them to that particular page:
            return redirect(next)
    # Allowing User to actually authenticate/login:
    return render_template("main/users_general/login.html", form=form)


# View for Registered but Unconfirmed User:
@app.route("/unconfirmed")
def unconfirmed():
    return render_template("main/users_general/unconfirmed.html")


# User 'FORGOT PASSWORD' View:
@app.route("/forgot_password", methods=["GET","POST"])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # User is not registered with us:
        if user is None:
            flash(u"Unknown email address. Kindly retry!")
            return render_template("main/users_general/forgot_password.html", form=form)
        # User is registered BUT not yet confirmed:
        elif user is not None and user.confirmed is False:
            flash(u"Your email address must be confirmed before attempting a password reset.")
            return redirect(url_for("unconfirmed"))
        # User is registered and confirmed, sending Password Reset email:
        elif user is not None and user.confirmed:
            token = generate_pwdreset_token(user.email)
            reset_url = url_for("pwdreset_email", token=token, _external=True)
            html = render_template("main/users_general/password_email.html", confirm_url=reset_url)
            subject = "Password Reset!"
            send_email(user.email, subject, html)
            user.pwdUpdate_requestedOn = datetime.now()
            user.pwdUpdate_requestIP = "72.229.28.185" if request.remote_addr == "127.0.0.1" else request.remote_addr
            db.session.add(user)
            db.session.commit()
            flash(u"Kindly check registered email for a password reset link! This link is valid for next 24 hours. Please reach our Support team if you do not receive this email.")
            # Routing User to login page:
            return redirect(url_for("login"))
    # Rendering a template for User to initiate Password Reset:
    return render_template("main/users_general/forgot_password.html", form=form)


# Helper view to redirect User after clicking on Password Reset link to 'password_reset.html' page:
@app.route("/reset/<token>")
def pwdreset_email(token):
    try:
        email = pwdreset_token(token)
    except:
        flash("Your password reset link is invalid or has expired. Kindly contact our support team for further assistance!")
        return redirect(url_for("support"))
    return redirect(url_for("password_reset"))


# View for Password Reset form:
@app.route("/password_reset", methods=["GET","POST"])
def password_reset():
    form = PasswordResetForm()
    if form.validate_on_submit():
        # Grabbing User based of entered Email:
        user = User.query.filter_by(email=form.email.data).first()
        # User doesn't exist in records:
        if user is None:
            flash(u"Unknown Email address! Kindly retry or contact our Support team if issue persists.")
            return render_template("main/users_general/password_reset.html", form=form)
        elif form.new_password.data != form.new_pass_confirm.data:
            flash(u"Password mismatch! Kindly retry.")
            return render_template("main/users_general/password_reset.html", form=form)
        elif user.check_password(form.new_password.data):
            flash("Kindly choose different password!")
            return render_template("main/users_general/password_reset.html", form=form)
        else:
            user.passwordUpdated_on = datetime.utcnow()
            user.set_password(value=(form.new_password.data))
            db.session.add(user)
            db.session.commit()
            html = render_template("main/users_general/pwdreset_inform.html")
            subject = "SellerHub Account Password Updated"
            send_email(user.email, subject, html)
            flash("Password has been successfully updated! Please login with your new password.")
            return redirect(url_for("login"))
    return render_template("main/users_general/password_reset.html", form=form)


# AMAZON User Dashboard [FULL] 'Payments' section:
@app.route("/amz_user_payments/<username>", methods=["GET", "POST"])
@login_required
def amz_user_payments(username):
    user = User.query.filter_by(username=username).first_or_404()
    transactions = Transactions.query.filter_by(razor_email=current_user.email).all()
    if transactions is None:
        flash(u"No transaction found in our records. Please reach our Support team for issues, if any.")
    return render_template("main/amazon/amz_user_payments.html", user=user, transactions=transactions)


# [FULL + PARTIAL Payment] Capturing RazorPay Payment Transaction [No Template Required]:
@app.route("/amz_charge", methods=["POST"])
def amz_charge():
    # FULL Payment Scenario:
    if current_user.pay_difference == 0:
        amount = current_user.razor_amount
        payment_id = request.form["razorpay_payment_id"]
        razorpay_client.payment.capture(payment_id, amount)
        data = json.dumps(razorpay_client.payment.fetch(payment_id))
        resp = json.loads(data)
        if "error_code" in resp.keys():
            # If PARTIAL payment is received from RazorPay gateway:
            if resp["error_code"] is None and resp["amount"] < current_user.razor_amount:
                current_user.razor_difference = current_user.razor_amount - resp["amount"]
                current_user.pay_difference = (current_user.razor_amount - resp["amount"])/100
                db.session.commit()
                flash(u"Partial payment successful! Kindly pay the remaining amount. For any issues, please contact our Support team.")
                return redirect(url_for("amz_user_payments", username=current_user.username))
            # If FULL payment went through successfully on RazorPay gateway:
            elif resp["error_code"] is None and resp["amount"] >= current_user.razor_amount:
                # Adding transaction details from RazorPay JSON to 'Transactions' table:
                transaction = Transactions(razor_id=resp["id"], type=resp["entity"].capitalize(), amount=resp["amount"], currency=resp["currency"], razor_status=resp["status"].capitalize(), international=resp["international"], method=resp["method"].capitalize(), capture_status=resp["captured"], description=resp["description"], user_bank=resp["bank"], user_wallet=resp["wallet"], razor_email=resp["email"], razor_phone=resp["contact"], trans_fee=resp["fee"], trans_tax=resp["tax"], trans_error_code=resp["error_code"], trans_error_desc=resp["error_description"], trans_created_at=datetime.utcnow(), trans_item=resp["description"]+" Activation")
                db.session.add(transaction)
                db.session.commit()
                # Making corresponding changes in 'User' Table:
                current_user.paid = True
                current_user.account_status = "Active"
                current_user.account_expiry_date = datetime.utcnow().date() + timedelta(days=31)
                db.session.commit()
                flash(u"Payment successful! Account activated.")
                return redirect(url_for("amz_user_payments", username=current_user.username))
        else:
            # Attending payment failure from RazorPay gateway:
            flash(u"Payment failed! Kindly retry or report this incident to our Support team in case of any issues.")
            return redirect(url_for("amz_user_payments", username=current_user.username))
    # PARTIAL Payment Scenario:
    else:
        if "error_code" in resp.keys():
            # If PARTIAL payment is received from RazorPay gateway:
            if resp["error_code"] is None and resp["amount"] < current_user.razor_difference:
                current_user.razor_difference = current_user.razor_difference - resp["amount"]
                current_user.pay_difference = (current_user.pay_difference - resp["amount"])/100
                db.session.commit()
                flash(u"Partial payment successful! Kindly pay the remaining amount. For any issues, please contact our Support team.")
                return redirect(url_for("amz_user_payments", username=current_user.username))
            # If FULL payment went through successfully on RazorPay gateway:
            elif resp["error_code"] is None and resp["amount"] >= current_user.razor_difference:
                # Adding transaction details from RazorPay JSON to 'Transactions' table:
                transaction = Transactions(razor_id=resp["id"], type=resp["entity"].capitalize(), amount=resp["amount"], currency=resp["currency"], razor_status=resp["status"].capitalize(), international=resp["international"], method=resp["method"].capitalize(), capture_status=resp["captured"], description=resp["description"], user_bank=resp["bank"], user_wallet=resp["wallet"], razor_email=resp["email"], razor_phone=resp["contact"], trans_fee=resp["fee"], trans_tax=resp["tax"], trans_error_code=resp["error_code"], trans_error_desc=resp["error_description"], trans_created_at=datetime.utcnow(), trans_item=("[Pending] "+resp["description"]+" Activation"))
                db.session.add(transaction)
                db.session.commit()
                # Making corresponding changes in 'User' Table:
                current_user.razor_difference = 0
                current_user.pay_difference = 0
                current_user.paid = True
                current_user.account_status = "Active"
                current_user.account_expiry_date = datetime.utcnow().date() + timedelta(days=31)
                db.session.commit()
                flash(u"Payment successful! Account activated.")
                return redirect(url_for("amz_user_payments", username=current_user.username))
        else:
            # Attending payment failure from RazorPay gateway:
            flash(u"Payment failed! Kindly retry or report this incident to our Support team if amount has been deducted from your bank account.")
            return redirect(url_for("amz_user_payments", username=current_user.username))


# AMAZON Dashboard 'FILE UPLOAD - Manual' section:
@app.route("/amz_upload_manual/<username>", methods=["GET", "POST"])
@login_required
def amz_upload_manual(username):
    user = User.query.filter_by(username=username).first_or_404()
    form = FileUploadForm()
    if form.validate_on_submit():
        # Checking for URL Duplicacy with possible probabilities:
        if form.order_report.data==form.return_report.data or form.order_report.data==form.payment_report.data or form.payment_report.data==form.return_report.data or form.payment_report.data==form.payment1_report.data:
            flash(u"Duplicate file entries found. Kindly retry and ensure to enter specific files in their assigned space.")
            return redirect(url_for("amz_upload_manual", username=current_user.username))
        # Check for previously uploaded 'Orders' files for User & delete all of them, if exists:
        if find_local_file((current_user.username + "__amz__orders__*"), "amz_uploaded_files/") != []:
            for item in (find_local_file((current_user.username + "__amz__orders__*"), "amz_uploaded_files/")):
                os.remove(item)
        # Save newly uploaded 'Orders' Report:
        order_filename = secure_filename(form.order_report.data.filename)
        form.order_report.data.save("amz_uploaded_files/" + current_user.username + "__amz__orders__" + order_filename)

        # Check for previously uploaded 'Returns' files for User & delete all of them, if exists:
        if find_local_file((current_user.username + "__amz__returns__*"), "amz_uploaded_files/") != []:
            for item in (find_local_file((current_user.username + "__amz__returns__*"), "amz_uploaded_files/")):
                os.remove(item)
        # Save newly uploaded 'Returns' Report:
        return_filename = secure_filename(form.return_report.data.filename)
        form.return_report.data.save("amz_uploaded_files/" + current_user.username + "__amz__returns__" + return_filename)

        # Check for previously uploaded 'Payments' files for User & delete all of them, if exists:
        if find_local_file((current_user.username + "__amz__payments1__*"), "amz_uploaded_files/") != []:
            for item in (find_local_file((current_user.username + "__amz__payments1__*"), "amz_uploaded_files/")):
                os.remove(item)
        # Save newly uploaded 'Payments' Report:
        payment_filename = secure_filename(form.payment_report.data.filename)
        form.return_report.data.save("amz_uploaded_files/" + current_user.username + "__amz__payments1__" + payment_filename)

        # Check for previously uploaded 'Optional Payments' files for User & delete all of them, if exists:
        if find_local_file((current_user.username + "__amz__payments2__*"), "amz_uploaded_files/") != []:
            for item in (find_local_file((current_user.username + "__amz__payments2__*"), "amz_uploaded_files/")):
                os.remove(item)
        # [OPTIONAL from User] Save newly uploaded 'Additional/optional Payments' Report:
        if form.payment1_report.data is not None:
            payment1_filename = secure_filename(form.payment1_report.data.filename)
            form.return_report.data.save("amz_uploaded_files/" + current_user.username + "__amz__payments2__" + payment1_filename)

        flash(u"Files have been successfully uploaded.")
        return redirect(url_for("amz_user_overview", username=current_user.username))
    return render_template("main/amazon/amz_upload_manual.html", user=user, form=form)


"""
# [FAILED] AMAZON Dashboard 'FILE UPLOAD - Google Drive URL' section [Though Links getting added to 'Users' table]:
@app.route("/amz_upload_googleURL/<username>", methods=["GET", "POST"])
@login_required
def amz_upload_googleURL(username):
    user = User.query.filter_by(username=username).first_or_404()
    form = LinkUploadForm()
    if form.validate_on_submit():
        # Validating if provided link is of Google Drive or not:
        # REFERENCE: https://stackoverflow.com/questions/38511444/python-download-files-from-google-drive-using-url/38516081#38516081
        if form.orders_amz_url.data.split("id=")[0]== "https://drive.google.com/open?" and form.returns_amz_url.data.split("id=")[0]== "https://drive.google.com/open?" and form.payments_amz_url.data.split("id=")[0]== "https://drive.google.com/open?":
            destination = "amz_uploaded_files/"
            # Downloading Orders File:
            current_user.amz_orders_url = form.orders_amz_url.data
            file_id = form.orders_amz_url.data.split("id=")[1]
            download_file_from_google_drive(file_id, destination)
            # Downloading Returns File:
            current_user.amz_returns_url = form.returns_amz_url.data
            file_id = form.returns_amz_url.data.split("id=")[1]
            download_file_from_google_drive(file_id, destination)
            # Downloading Payments File:
            current_user.amz_payments_url = form.payments_amz_url.data
            file_id = form.payments_amz_url.data.split("id=")[1]
            download_file_from_google_drive(file_id, destination)
            # Downloading Optional Payments File, if available:
            if form.payments1_amz_url.data is not None:
                current_user.amz_payments1_url = form.payments1_amz_url.data
                file_id = form.payments1_amz_url.data.split("id=")[1]
                download_file_from_google_drive(file_id, destination)
            db.session.commit()
            flash(u"Google Drive URLs successfully uploaded!")
            return redirect(url_for("amz_upload_googleURL", username=user.username))
        elif form.orders_amz_url.data.split("id=")[0]!= "https://drive.google.com/open?" or form.returns_amz_url.data.split("id=")[0]!= "https://drive.google.com/open?" or form.payments_amz_url.data.split("id=")[0]!= "https://drive.google.com/open?":
            flash(u"Unrecognized File URL format. Kindly cross-check URL before trying again or may refer our guidebook. If issue persists, kindly reach out our Support team.")
            return redirect(url_for("amz_upload_googleURL", username=user.username))
    return render_template("main/amazon/amz_upload_googleURL.html", form=form, user=user)


# [NOT ATTEMPTED] AMAZON Dashboard 'FILE UPLOAD - AMZ MWS' section:
@app.route("/amz_upload_amzmws/<username>", methods=["GET", "POST"])
@login_required
def amz_upload_amzmws(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template("main/amazon/amz_upload_amzmws.html", user=user)
"""


# AMAZON Dashboard 'Overview' section:
@app.route("/amz_user_overview/<username>", methods=["GET", "POST"])
@login_required
def amz_user_overview(username):
    user = User.query.filter_by(username=username).first_or_404()
    # Locating User specific 'ORDERS' File and selecting first file [Not expecting more than one file though]:
    order_file = find_local_file((current_user.username + "__amz__orders__*"), "amz_uploaded_files/")[0]
    # Parsing 'Orders' file and internally renaming columns:
    order_data = columns_renamer(file_parser(filepath = order_file))
    # Getting list of column header/names:
    return render_template("main/amazon/amz_user_overview.html", user=user, data=order_data)


# AMAZON Dashboard TOP-3 ICON: 'Support' section:
@app.route("/amz_user_incident_report/<username>", methods=["GET", "POST"])
@login_required
def amz_user_incident_report(username):
    form = SupportForm()
    if form.validate_on_submit():
        support = Support(email=form.email.data, issueCategory=form.issueCategory.data, issueType=form.issueType.data)
        support.issueDescription = form.issueDescription.data.strip()
        db.session.add(support)
        db.session.commit()
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            for item in Support.query.filter_by(email=form.email.data).all():
                item.user_id = user.id
                db.session.commit()
        else:
            for item in Support.query.filter_by(email=form.email.data).all():
                item.user_id = "Unknown"
                db.session.commit()
        html = render_template("main/supportTicket_userInform.html")
        subject = "Support Ticket | Ticket Number: " + support.ticket_id
        send_email(support.email, subject, html)
        # Flashing successful submission confirmation:
        flash("Your issue has been registered with us. Thank You!")
    user = User.query.filter_by(username=username).first_or_404()
    support = Support.query.filter_by(email=current_user.email).all()
    if support is None:
        flash(u"Seems everything has been sailing smoothly! No incident found in our records.")
    return render_template("main/amazon/amz_user_incident_report.html", user=user, support=support, form=form)


# AMAZON Dashboard 'User Profile' section:
@app.route("/amz_user_profile/<username>", methods=["GET", "POST"])
@login_required
def amz_user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    form = AMZUserProfile(current_user.username)
    if request.method == "POST":
        current_user.first_name = request.form["first_name"]
        current_user.last_name = request.form["last_name"]
        current_user.userAddress = request.form["userAddress"]
        current_user.userCity = request.form["userCity"]
        current_user.userState = request.form["userState"]
        current_user.userCountry = request.form["userCountry"]
        current_user.company_name = request.form["company_name"]
        current_user.company_url = request.form["company_url"]
        current_user.facebook_url = request.form["facebook_url"]
        current_user.linkedin_url = request.form["linkedin_url"]
        db.session.commit()
        flash(u"Profile details successfully updated!")
        return redirect(url_for("amz_user_profile", username=user.username))
    return render_template("main/amazon/amz_user_profile.html", user=user, form=form)


# User LOGOUT View [Always place it last]:
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been successfully logged out!")
    return redirect(url_for("landing_page"))


# Run Application:
if __name__ == "__main__":
    app.run(debug=True if not os.getenv("PORT") else False)
