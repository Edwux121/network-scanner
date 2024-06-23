import functools
import re

from network import nmap_test

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db

bp = Blueprint("auth", __name__, url_prefix="/auth")

@bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        error = None
        user = db.execute(
            "SELECT * FROM user WHERE username = ?", (username,)
        ).fetchone()

        if user is None or not check_password_hash(user["password"], password):
            error = "Incorrect credentials!"

        if user["first_login"] == 1:
            session.clear()
            session["user_id"] = user["id"]
            session["password_changed"] = False
            return redirect(url_for("auth.reset_password"))

        if error is None:
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("index"))

        flash(error)

    return render_template("auth/login.html")

def check_password(password, re_password):
    if len(password) < 8 and len(re_password) < 8:
        return False
    elif not re.search("[a-z]", password) and not re.search("[a-z]", re_password):
        return False
    elif not re.search("[A-Z]", password) and not re.search("[A-Z]", re_password):
        return False
    elif not re.search("[0-9]", password) and not re.search("[0-9]", re_password):
        return False
    return True

@bp.route("/reset_password", methods=("GET", "POST"))
def reset_password():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        re_password = request.form["re-password"]
        db = get_db()
        user = db.execute(
            "SELECT * FROM user WHERE username = ?", (username,)
        ).fetchone()
        error = None

        if not check_password(password, re_password):
            error = ("Password must be at least 8 characters long and contain at least one lowercase letter, "
                     "one uppercase letter, and one number.")
        elif password != re_password:
            error = "Passwords do not match."

        if error is None:
            db.execute(
                "UPDATE user SET first_login = 0 WHERE username = ?", (username,)
            )
            db.execute(
                "UPDATE user SET password = ? WHERE username = ?", (generate_password_hash(password), username,)
            )
            db.commit()
            session.clear()
            session["user_id"] = user["id"]
            session["password_changed"] = True
            return redirect(url_for("index"))

        flash(error)

    return render_template("auth/reset_password.html")

@bp.route("/scan_network")
def scan_network():
    nmap_test.scan()
    return redirect(url_for("index"))

@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            "SELECT * FROM user WHERE id = ?", (user_id,)
        ).fetchone()

@bp.before_app_request
def check_password_change():
    if (request.endpoint != 'auth.reset_password' and
            request.endpoint != 'static' and
            session.get("password_changed") == False):
        session.clear()
        return redirect(url_for("auth.reset_password"))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))

        return view(**kwargs)

    return wrapped_view
