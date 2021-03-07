"""Owings Lab Eight"""
import csv
import gc
import re
from datetime import datetime, date
from functools import wraps
import logging
import pandas as pd
from passlib.hash import sha256_crypt
from flask import Flask, render_template, \
    request, redirect, flash, url_for, session


app = Flask(__name__)
app.secret_key = "filesystem"


def time():
    """Time Function"""
    now_time = datetime.now()
    current_time = now_time.strftime("%H:%M:%S")
    return current_time


date_object = date.today()


def login_required(_f):
    """Login Required Function"""
    @wraps(_f)
    def wrap(*args, **kwargs):
        if "logged_in" in session:
            return _f(*args, **kwargs)
        flash("You need to register or login first")
        return redirect(url_for("login"))
    return wrap


def secret_required(_f):
    """Secret Required Function"""
    @wraps(_f)
    def wrap(*args, **kwargs):
        if "secret_on" in session:
            return _f(*args, **kwargs)
        flash("You need to enter your secret first")
        return redirect(url_for("secretpage"))
    return wrap

@app.route("/")
@login_required
def home():
    """Home Page Function"""
    return render_template("main.html",
                           plhld="Screenshot 2021-02-19 165624.png",
                           title="Home",
                           time=time(),
                           date=date_object
                           )


@app.route("/beers")
@login_required
def beers():
    """Beers Page Function"""
    return render_template("beer.html", plhld="Row-Of-British-Beers.png",
                           title="Beer",
                           time=time(),
                           date=date_object
                           )


@app.route("/recipes")
@login_required
def recipes():
    """Recipes Page Function"""
    return render_template("recipes.html", plhld="5F1A2766.jpg",
                           title="Recipes",
                           time=time(),
                           date=date_object
                           )


@app.route("/conference")
@login_required
def conference():
    """Conference Page Function"""
    thursday = pd.read_csv("THURSDAY_JUNE_18_2020.csv")
    friday = pd.read_csv("FRIDAY_JUNE_19_2020.csv")
    saturday = pd.read_csv("SATURDAY_JUNE_20_2020.csv")
    merged = pd.concat([thursday, friday, saturday])
    return render_template("conference.html", plhld="82052.png",
                           tables=merged.to_html(classes="con-table"),
                           title="Conference",
                           time=time(),
                           date=date_object
                           )


@app.route("/register", methods=['GET', 'POST'])
def register():
    """Register Page Function"""
    with open("user.csv", "r+") as d_f:
        add_user = len(d_f.readlines())
        if request.method == "POST":
            user = request.form
            u_n = request.form["username"].lower()
            with open("user.csv", "r") as file:
                reader = csv.reader(file)
                for row in reader:
                    if row[1].lower() == u_n:
                        flash("User already exists, please try another "
                              "username.")
                        return redirect(url_for("register"))
            missing = list()
            for row, _v in user.items():
                if _v == "":
                    missing.append(row)
            if missing:
                feedback = f"Missing fields for {', '.join(missing)} please " \
                           f"try again."
                return render_template("register.html",
                                       plhld="register-1627729_1920.png",
                                       feedback=feedback,
                                       title="Login",
                                       time=time(),
                                       date=date_object
                                       )
            p_a = request.form["password"]
            pas_check = check_strength(p_a)
            if pas_check == -1:
                flash("You have chosen an invalid password, please try "
                      "with the stated requirements.")
                return redirect(url_for("register"))
            hash_pass = sha256_crypt.hash(p_a)
            user_data = pd.DataFrame(user, index=[add_user])
            new_column = pd.Series([hash_pass], name="password",
                                   index=[add_user])
            user_data.update(new_column)
            user_data.to_csv(d_f, mode='a', header=False, line_terminator="\n")
            print(sha256_crypt.verify(p_a, hash_pass))
            flash("You are now registered, please sign in above.")
            return redirect(url_for("login"))
    return render_template("register.html", title="Register",
                           plhld="register-1627729_1920.png",
                           time=time(),
                           date=date_object
                           )


@app.route("/login", methods=['GET', 'POST'])
def login():
    """Login Page Function"""
    if request.method == "POST":
        logging.getLogger('werkzeug').disabled = True
        logging.basicConfig(filename="lab_eight.log",
                            level=logging.INFO,
                            datefmt='%m/%d/%Y %I:%M:%S %p',
                            format="%(asctime)s : %(message)s")
        u_n = request.form["username"].lower()
        p_a = request.form["password"]
        with open("user.csv", "r") as file:
            reader = csv.reader(file)
            for row in reader:
                if row[1].lower() == u_n:
                    compare_pw = (sha256_crypt.verify(p_a, row[5]))
                    if compare_pw:
                        session["logged_in"] = True
                        session["username"] = u_n
                        flash("You are now logged in!")
                        return redirect(url_for("home"))
                    flash("You have entered an incorrect password, "
                          "please try again.")
                    ip_address = request.environ.get("HTTP_X_REAL_IP",
                                                     request.remote_addr)
                    logging.info("Failed login attempt from IP address %s"
                                 " for username %s",
                                 ip_address, u_n)
                    return redirect(url_for("login"))
            flash("The username you entered does not exist, please "
                  "try again or register as a new user.")
            ip_address = request.environ.get("HTTP_X_REAL_IP",
                                             request.remote_addr)
            logging.info("Failed login attempt from IP address %s"
                         " for username %s",
                         ip_address, u_n)
            return redirect(url_for("login"))
    return render_template("login.html",
                           plhld="login-3938430_1920.jpg",
                           title="Login",
                           time=time(),
                           date=date_object,
                           )


@app.route("/secretpage", methods=['GET', 'POST'])
@login_required
def secretpage():
    """Secret Page Function"""
    user = session['username']
    if request.method == "POST":
        secret = request.form["secret"]
        with open("user.csv", "r") as infile:
            reader = csv.reader(infile)
            for row in reader:
                if row[1].lower() == user:
                    if row[6] == "":
                        session["secret_on"] = True
                        return redirect(url_for("change"))
                    compare_secret = (sha256_crypt.verify(secret, row[6]))
                    if compare_secret:
                        session["secret_on"] = True
                        return redirect(url_for("change"))
                    flash("This is not the secret for your account, please "
                          "try again.")
                    return redirect(url_for("secretpage"))
    return render_template("secret.html",
                           plhld="pexels-pixabay-60504.jpg",
                           title="Enter Secret",
                           time=time(),
                           date=date_object,
                           )


@app.route("/change", methods=['GET', 'POST'])
@login_required
@secret_required
def change():
    """Change Password Function"""
    user = session['username']
    if request.method == "POST":
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm"]
        p_a = request.form["password"]
        secret = request.form["secret"].strip()
        secret_low = secret.lower()
        with open("user.csv", "r") as infile:
            reader = csv.reader(infile)
            count = 0
            for row in reader:
                count += 1
                if row[1].lower() == user:
                    compare_pw = (sha256_crypt.verify(p_a, row[5]))
                    if compare_pw and new_password == confirm_password:
                        pas_check = check_strength(new_password)
                        if pas_check == -1:
                            flash("Use Password Requirements.")
                            return redirect(url_for("change"))
                        if check_common(secret_low.strip()) == \
                                secret_low.strip() or secret == "":
                            flash(secret)
                            flash("Your secret is too common to use, "
                                  "try again with something else.")
                            return redirect(url_for("change"))
                        hash_pass = sha256_crypt.hash(new_password)
                        hash_secret = sha256_crypt.hash(secret)
                        d_f = pd.read_csv("user.csv")
                        d_f.loc[count-2, "password"] = hash_pass
                        d_f.loc[count-2, "secret"] = hash_secret
                        d_f.to_csv("user.csv", index=False)
                        # Confirm hash's to those stored within user.csv
                        print(secret_low)
                        print(hash_pass)
                        print(hash_secret)
                        session.clear()
                        flash("Your password has been changed, "
                              "use the new password to login")
                        return redirect(url_for("login"))
                    flash("You have entered an incorrect password "
                          "for this account or your new passwords "
                          "do not match, please try again.")
                    return redirect(url_for("change"))
    return render_template("change.html",
                           plhld="pexels-pixabay-60504.jpg",
                           title="Reset Password",
                           time=time(),
                           date=date_object,
                           )


def check_common(check_input):
    """Check Common function"""
    flag = 0
    with open("CommonPassword.txt") as c_p:
        for line in c_p:
            if check_input == line.strip():
                flag = line.strip()
    return flag


def check_strength(pw_input):
    """Check password strength"""
    good = True
    flag = 0
    while good:
        if len(pw_input) < 12:
            flag = -1
            good = False
        elif len(pw_input) > 20:
            flag = -1
            good = False
        elif not re.search("[a-z]", pw_input):
            flag = -1
            good = False
        elif not re.search("[A-Z]", pw_input):
            flag = -1
            good = False
        elif not re.search("[0-9]", pw_input):
            flag = -1
            good = False
        elif not re.search("[!@#$%^&*()_+=]", pw_input):
            flag = -1
            good = False
        elif re.search(r"\s", pw_input):
            flag = -1
            good = False
        else:
            flag = 0
            good = False
    return flag


@app.route("/logout")
@login_required
def logout():
    """Logout Function"""
    session.clear()
    flash("You have been logged out!")
    gc.collect()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run()
