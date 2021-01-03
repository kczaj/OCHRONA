from flask import Flask, render_template, make_response, request, session, redirect
from flask_cors import CORS, cross_origin
import hashlib
import bcrypt
import os
import base64

from app.init import init

from app.dao import DAO

app = Flask(__name__)
cors = CORS(app)
app.secret_key = os.environ.get("SECRET_KEY")
app.config["SESSION_COOKIE_SECURE"] = True

dao = None


@app.before_first_request
def init_db():
    # init()
    global dao
    dao = DAO()


@app.route('/', methods=["GET"])
@cross_origin(origins=["https://localhost"])
def index():
    return make_response(render_template("index.html"), 200)


@app.route('/list/', methods=["GET"])
@cross_origin(origins=["https://localhost"])
def after_log():
    if "username" not in session.keys():
        return redirect("/")
    else:
        return make_response(render_template("after_log.html"), 200)


def check_if_sqli(value):
    if ";" in value or "#" in value or "--" in value or "/*" in value or "'" in value:
        return False
    else:
        return True


def prepare_password(password):
    base_form = base64.b64encode(hashlib.sha256(password.encode("utf-8")).hexdigest().encode("utf-8"))
    return str(hashlib.sha256(base_form).hexdigest()) + "." + str(os.environ.get("PEPPER"))


@app.route('/register/', methods=["POST"])
@cross_origin(origins=["https://localhost"])
def register():
    username = request.form.get("username")
    email = request.form.get("email")
    name = request.form.get("name")
    surname = request.form.get("surname")
    password = request.form.get("password")
    if username is None or email is None or name is None or surname is None or password is None:
        return make_response({
            "status": "403",
            "message": "Forbidden"
        }, 403)
    if not check_if_sqli(username) or not check_if_sqli(email) or not check_if_sqli(name) or not check_if_sqli(
            surname) or not check_if_sqli(password):
        return make_response({
            "status": "403",
            "message": "Forbidden"
        }, 403)

    dao.sql.execute(f"SELECT email FROM users WHERE email=\'{email}\'; ")
    emails = dao.sql.fetchall()
    if emails:
        return make_response({
            "status": "400",
            "message": "Email already used",
        }, 400)
    dao.sql.execute(f"SELECT username FROM users WHERE username=\'{username}\';")
    usernames = dao.sql.fetchall()
    if usernames:
        return make_response({
            "status": "400",
            "message": "Username already used"
        }, 400)

    password_to_db = prepare_password(password)
    password_to_db = bcrypt.hashpw(password_to_db.encode("utf-8"), bcrypt.gensalt(14)).decode("utf-8")

    dao.sql.execute(
        f"INSERT INTO users (email, name, surname, username, password) VALUES (\'{email}\', \'{name}\', \'{surname}\', \'{username}\', \'{password_to_db}\');")
    dao.db.commit()
    session["username"] = username
    return make_response({
        "status": "200",
        "message": "OK",
    }, 200)


@app.route("/login/", methods=["POST"])
@cross_origin(origins=["https://localhost"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if username is None or password is None:
        return make_response({
            "status": "403",
            "message": "Forbidden"
        }, 403)

    if not check_if_sqli(username) or not check_if_sqli(password):
        return make_response({
            "status": "403",
            "message": "Forbidden"
        }, 403)

    dao.sql.execute(f"SELECT password FROM users WHERE username=\'{username}\'; ")
    password_db = dao.sql.fetchone()
    if not password_db:
        return make_response({
            "status": "404",
            "message": "User not found"
        }, 404)
    else:
        password_form = prepare_password(password)
        if bcrypt.checkpw(password_form.encode("utf-8"), password_db[0].encode("utf-8")):
            session["username"] = username
            return make_response({
                "status": "200",
                "message": "Logged in"
            }, 200)
        else:
            return make_response({
                "status": "401",
                "message": "Unauthorized"
            }, 401)


@app.route("/logout/", methods=["POST"])
@cross_origin(origins=["https://localhost"])
def logout():
    session.pop("username", None)
    return redirect("/")
