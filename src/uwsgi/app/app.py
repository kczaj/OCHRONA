import json

from flask import Flask, render_template, make_response, request, session, redirect, jsonify
from flask_cors import CORS, cross_origin
import hashlib
import bcrypt
import os
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import redis

from app.init import init

from app.dao import DAO

app = Flask(__name__)
cors = CORS(app)
app.secret_key = os.environ.get("SECRET_KEY")
db = redis.Redis(host="redis", port=6379)
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


@app.route('/note/', methods=["GET"])
@cross_origin(origins=["https://localhost"])
def new_file():
    if "username" not in session.keys():
        return redirect("/")
    else:
        return make_response(render_template("new_note.html"), 200)


def check_if_sqli(value):
    if ";" in value or "#" in value or "--" in value or "/*" in value or "'" in value:
        return True
    else:
        return False


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
    if check_if_sqli(username) or check_if_sqli(email) or check_if_sqli(name) or check_if_sqli(
            surname) or check_if_sqli(password):
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
    dao.sql.execute(f"SELECT id FROM users WHERE username=\'{username}\'; ")
    data_db = dao.sql.fetchone()
    name = "user_" + str(data_db[0])
    db.hset(name, "count", 0)
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

    if check_if_sqli(username) or check_if_sqli(password):
        return make_response({
            "status": "403",
            "message": "Forbidden"
        }, 403)

    dao.sql.execute(f"SELECT id, password FROM users WHERE username=\'{username}\'; ")
    data_db = dao.sql.fetchone()
    if not data_db:
        return make_response({
            "status": "404",
            "message": "User not found"
        }, 404)
    else:
        id = str(data_db[0])
        name = "user_" + id
        lock = "lock_" + id

        if db.exists(lock) == 1:
            return make_response({
                "status": "403",
                "message": "Forbidden"
            }, 403)

        password_form = prepare_password(password)
        if bcrypt.checkpw(password_form.encode("utf-8"), data_db[1].encode("utf-8")):
            session["username"] = username
            db.hset(name, "count", 0)
            return make_response({
                "status": "200",
                "message": "Logged in"
            }, 200)
        else:
            count = int(db.hget(name, "count"))
            if count + 1 < 15:
                db.hset(name, "count", count + 1)
            else:
                db.hset(name, "count", 0)
                db.sadd(lock, "0")
                db.expire(lock, 120)
            return make_response({
                "status": "401",
                "message": "Unauthorized"
            }, 401)


@app.route("/logout/", methods=["POST"])
@cross_origin(origins=["https://localhost"])
def logout():
    session.pop("username", None)
    return redirect("/")


@app.route("/savenote/", methods=["POST"])
@cross_origin(origins=["https://localhost"])
def save_note():
    title = request.form.get("title")
    body = request.form.get("body")
    password = request.form.get("password")
    username = session["username"] if "username" in session.keys() else None

    if username is None:
        return make_response({
            "status": "401",
            "message": "Unauthorized"
        }, 403)

    if title is None or body is None:
        return make_response({
            "status": "403",
            "message": "Forbidden"
        }, 403)

    if check_if_sqli(title) or check_if_sqli(body) or check_if_sqli(username):
        return make_response({
            "status": "403",
            "message": "Forbidden"
        }, 403)

    dao.sql.execute(f"SELECT username FROM users WHERE username=\'{username}\'")
    usernames = dao.sql.fetchone()
    if not usernames:
        return make_response({
            "status": "404",
            "message": "Not found"
        }, 404)

    if password is None or password is "":
        dao.sql.execute(
            f"INSERT INTO notes (title, body) VALUES (\'{title}\', \'{body}\');")
        dao.db.commit()
        return make_response({
            "status": "201",
            "message": "Created",
        }, 201)
    else:
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt)
        iv = get_random_bytes(16)
        aes = AES.new(key, AES.MODE_CBC, iv=iv)
        encrypted_note = aes.encrypt(pad(body.encode("utf-8"), AES.block_size))
        note_to_db = base64.b64encode(iv + salt + encrypted_note).decode("utf-8")

        dao.sql.execute(
            f"INSERT INTO notes (title, body, owner) VALUES (\'{title}\', \'{note_to_db}\', \'{username} \');")
        dao.db.commit()
        return make_response({
            "status": "201",
            "message": "Created",
        }, 201)


@app.route("/notes/", methods=["GET"])
@cross_origin(origins=["https://localhost"])
def get_notes():
    if "username" not in session.keys():
        return make_response({
            "status": "401",
            "message": "Unauthorized",
        }, 401)
    username = session["username"]
    dao.sql.execute(f"SELECT username FROM users WHERE username = \'{username}\';")
    usernames = dao.sql.fetchall()
    if not usernames:
        return make_response({
            "status": "404",
            "message": "Not found"
        }, 404)

    dao.sql.execute(f"SELECT id, title FROM notes WHERE owner = \'{username}\';")
    numrows = dao.sql.rowcount

    notes = []
    for x in range(0, numrows):
        note_db = dao.sql.fetchone()
        note = {
            "id": str(note_db[0]),
            "title": str(note_db[1])
        }
        note = json.dumps(note)
        notes.append(note)

    return make_response(jsonify({"notes": notes}), 200)


@app.route("/public/", methods=["GET"])
@cross_origin(origins=["https://localhost"])
def get_public_notes():
    if "username" not in session.keys():
        return make_response({
            "status": "401",
            "message": "Unauthorized",
        }, 401)
    username = session["username"]
    dao.sql.execute(f"SELECT username FROM users WHERE username = \'{username}\';")
    usernames = dao.sql.fetchall()
    if not usernames:
        return make_response({
            "status": "404",
            "message": "Not found"
        }, 404)

    dao.sql.execute(f"SELECT id, title, body FROM notes WHERE owner IS NULL;")
    numrows = dao.sql.rowcount

    notes = []
    for x in range(0, numrows):
        note_db = dao.sql.fetchone()
        note = {
            "id": str(note_db[0]),
            "title": str(note_db[1]),
            "body": str(note_db[2])
        }
        note = json.dumps(note)
        notes.append(note)

    return make_response(jsonify({"notes": notes}), 200)
