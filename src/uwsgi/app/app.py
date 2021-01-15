import json
import uuid

from flask import Flask, render_template, make_response, request, session, redirect, jsonify, url_for
from flask_wtf.csrf import CSRFProtect
import hashlib
import bcrypt
import os
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import redis
from termcolor import colored
import re
from datetime import timedelta

from app.dao import DAO

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
db = redis.Redis(host="redis", port=6379)
app.config["SESSION_COOKIE_SECURE"] = True
app.config['UPLOAD_FOLDER'] = {'png', 'jpg', 'pdf', 'txt'}
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
csrf = CSRFProtect(app)

dao = DAO()

name = "user_1"
db.hset(name, "count", 0)


@app.after_request
def after_request(resp):
    resp.headers[
        'Content-Security-Policy'] = 'default-src \'self\'; style-src \'self\' https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/css/bootstrap.min.css'
    resp.headers['Server'] = None
    return resp


@app.route('/', methods=["GET"])
def index():
    resp = make_response(render_template("index.html"), 200)
    return resp


@app.route('/password/', methods=["GET", "POST"])
def password():
    if request.method == "POST":
        email = request.form.get("email") if request.form.get("email") is not "" or request.form.get(
            "email") is not None else None
        if email is None:
            resp = make_response({
                "status": "400",
                "message": "No email provided"
            }, 400)
            return resp
        if check_if_sqli(email):
            resp = make_response({
                "status": "403",
                "message": "Forbidden"
            }, 403)
            return resp
        dao.sql.execute("SELECT username FROM users WHERE email = %(email)s;", {'email': email})
        usernames = dao.sql.fetchall()
        if not usernames:
            resp = make_response({
                "status": "404",
                "message": "Not found"
            }, 404)
            return resp
        username = usernames[0]
        token = uuid.uuid4().__str__()
        db.sadd(token, username[0])
        db.expire(token, 300)
        print(colored(f"Token created for {email} and the reset website is https://localhost/password/{token}", "red"))
        resp = make_response({
            "status": "201",
            "message": "Token created"
        }, 201)
        return resp
    else:
        resp = make_response(render_template("forgot_password.html"), 200)
        return resp


@app.route('/password/<string:token>', methods=["GET", "POST"])
def reset_password(token):
    if request.method == "GET":
        if db.exists(token) == 1:
            resp = make_response(render_template("reset_password.html", token=token, visible="none"), 200)
            return resp
        else:
            return redirect("/")
    else:
        if db.exists(token) == 0:
            resp = make_response({
                "status": "404",
                "message": "Not found"
            }, 404)
            return resp
        password = request.form.get("password") if request.form.get("password") is not "" or request.form.get(
            "password") is not None else None
        if password is None:
            resp = make_response({
                "status": "400",
                "message": "No password provided"
            }, 400)
            return resp
        if check_if_sqli(password):
            resp = make_response({
                "status": "403",
                "message": "Forbidden"
            }, 403)
            return resp
        if check_password(password):
            resp = make_response({
                "status": "400",
                "message": "Wrong password format"
            }, 400)
            return resp

        username_list = list(db.smembers(token))
        username = username_list[0].decode("utf-8")
        dao.sql.execute("SELECT username FROM users WHERE username = %(username)s;", {'username': username})
        usernames = dao.sql.fetchone()
        if not usernames:
            resp = make_response({
                "status": "404",
                "message": "Not found"
            }, 404)
            return resp

        hashed_password = prepare_password(password)
        hashed_password = bcrypt.hashpw(hashed_password.encode("utf-8"), bcrypt.gensalt(14)).decode("utf-8")

        dao.sql.execute("UPDATE users SET password = %(hashed_password)s WHERE username = %(username)s;",
                        {'hashed_password': hashed_password, 'username': username})
        dao.db.commit()

        db.delete(token)
        resp = make_response(render_template("reset_password.html", token="uiwqd", visible="block"), 200)
        return resp


@app.route('/user/', methods=["GET"])
def after_log():
    if "username" not in session.keys():
        return redirect("/")

    username = session["username"]
    dao.sql.execute("SELECT username FROM users WHERE username = %(username)s;", {'username': username})
    usernames = dao.sql.fetchall()
    if not usernames:
        return redirect("/")

    resp = make_response(render_template("after_log.html"), 200)
    return resp


@app.route('/note/', methods=["GET"])
def new_file():
    if "username" not in session.keys():
        return redirect("/")

    username = session["username"]
    dao.sql.execute("SELECT username FROM users WHERE username = %(username)s;", {'username': username})
    usernames = dao.sql.fetchall()
    if not usernames:
        return redirect("/")

    resp = make_response(render_template("add.html"), 200)
    return resp


def check_if_sqli(value):
    if ";" in value or "#" in value or "--" in value or "/*" in value or "'" in value:
        return True
    else:
        return False


def check_xss(value):
    if "<" in value or ">" in value:
        return True
    else:
        return False


def check_password(value):
    if len(value) < 8 or not re.match('^[a-zA-Z0-9!@#$%&*]+$', value):
        return True
    else:
        return False


def check_name(value):
    if not re.match('^[a-zA-Z]+$', value):
        return True
    else:
        return False


def check_username(value):
    if not re.match('^[a-zA-Z0-9]+$', value):
        return True
    else:
        return False


def check_email(value):
    if not re.match('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}$', value):
        return True
    else:
        return False


def prepare_password(password):
    base_form = base64.b64encode(hashlib.sha256(password.encode("utf-8")).hexdigest().encode("utf-8"))
    return str(hashlib.sha256(base_form).hexdigest()) + "." + str(os.environ.get("PEPPER"))


@app.route('/register/', methods=["POST"])
def register():
    username = request.form.get("username")
    email = request.form.get("email")
    name = request.form.get("name")
    surname = request.form.get("surname")
    password = request.form.get("password")
    if username is None or email is None or name is None or surname is None or password is None:
        resp = make_response({
            "status": "403",
            "message": "Forbidden"
        }, 403)
        return resp
    if check_if_sqli(username) or check_if_sqli(email) or check_if_sqli(name) or check_if_sqli(
            surname) or check_if_sqli(password):
        resp = make_response({
            "status": "403",
            "message": "Forbidden"
        }, 403)
        return resp

    if check_email(email) or check_password(password) or check_name(name) or check_name(surname) or check_username(
            username):
        resp = make_response({
            "status": "400",
            "message": "Wrong format"
        }, 400)
        return resp

    dao.sql.execute("SELECT email FROM users WHERE email= %(email)s;", {'email': email})
    emails = dao.sql.fetchall()
    if emails:
        resp = make_response({
            "status": "400",
            "message": "Email already used",
        }, 400)
        return resp
    dao.sql.execute("SELECT username FROM users WHERE username = %(username)s;", {'username': username})
    usernames = dao.sql.fetchall()
    if usernames:
        resp = make_response({
            "status": "400",
            "message": "Username already used"
        }, 400)
        return resp

    password_to_db = prepare_password(password)
    password_to_db = bcrypt.hashpw(password_to_db.encode("utf-8"), bcrypt.gensalt(14)).decode("utf-8")

    dao.sql.execute(
        "INSERT INTO users (email, name, surname, username, password) VALUES (%(email)s, %(name)s, %(surname)s, %(username)s, %(password_to_db)s);",
        {'email': email, 'name': name, 'surname': surname, 'username': username, 'password_to_db': password_to_db})
    dao.sql.execute("SELECT id FROM users WHERE username=%(username)s;", {'username': username})
    data_db = dao.sql.fetchone()
    name = "user_" + str(data_db[0])
    db.hset(name, "count", 0)

    ip = request.remote_addr
    dao.sql.execute("SELECT ip FROM ips WHERE ip=%(ip)s;", {'ip': ip})
    ips = dao.sql.fetchall()
    if not ips:
        dao.sql.execute("INSERT INTO ips (ip, username) VALUES (%(ip)s, %(username)s);",
                        {'ip': ip, 'username': username})

    dao.db.commit()
    session["username"] = username
    session.permanent = True
    resp = make_response({
        "status": "200",
        "message": "OK",
    }, 200)
    return resp


@app.route("/login/", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if username is None or password is None:
        resp = make_response({
            "status": "403",
            "message": "Forbidden"
        }, 403)
        return resp

    if check_if_sqli(username) or check_if_sqli(password):
        resp = make_response({
            "status": "403",
            "message": "Forbidden"
        }, 403)
        return resp

    dao.sql.execute("SELECT id, password FROM users WHERE username=%(username)s;", {'username': username})
    data_db = dao.sql.fetchone()
    if not data_db:
        resp = make_response({
            "status": "404",
            "message": "User not found"
        }, 404)
        return resp
    else:
        id = str(data_db[0])
        name = "user_" + id
        lock = "lock_" + id

        if db.exists(lock) == 1:
            resp = make_response({
                "status": "403",
                "message": "Forbidden"
            }, 403)
            return resp

        password_form = prepare_password(password)
        if bcrypt.checkpw(password_form.encode("utf-8"), data_db[1].encode("utf-8")):
            session["username"] = username
            session.permanent = True
            db.hset(name, "count", 0)

            if username == "admin":
                print(colored("WARNING Someone hacked this app", "red"))

            ip = request.remote_addr
            dao.sql.execute("SELECT ip FROM ips WHERE ip=%(ip)s;", {'ip': ip})
            ips = dao.sql.fetchall()
            if not ips:
                dao.sql.execute("INSERT INTO ips (ip, username) VALUES ( %(ip)s, %(username)s);",
                                {'ip': ip, 'username': username})
                print(colored(f"New login to account {username} from address {ip}"))

            resp = make_response({
                "status": "200",
                "message": "Logged in"
            }, 200)
            return resp
        else:
            count = int(db.hget(name, "count"))
            if count + 1 < 5:
                db.hset(name, "count", count + 1)
            else:
                db.hset(name, "count", 0)
                db.sadd(lock, "0")
                db.expire(lock, 300)
            resp = make_response({
                "status": "401",
                "message": "Unauthorized"
            }, 401)
            return resp


@app.route("/logout/", methods=["POST"])
def logout():
    username = session.pop("username", None)
    session.clear()
    ip = request.remote_addr
    dao.sql.execute("DELETE FROM ips WHERE ip=%(ip)s AND username = %(username)s;", {'ip': ip, 'username': username})
    dao.db.commit()
    return redirect("/")


@app.route("/savenote/", methods=["POST"])
def save_note():
    title = request.form.get("title")
    body = request.form.get("body")
    password = request.form.get("password")
    username = session["username"] if "username" in session.keys() else None

    if username is None:
        resp = make_response({
            "status": "401",
            "message": "Unauthorized"
        }, 403)
        return resp

    if title is None or body is None:
        resp = make_response({
            "status": "403",
            "message": "Forbidden"
        }, 403)
        return resp

    if check_if_sqli(title) or check_if_sqli(body) or check_if_sqli(username) or check_if_sqli(password) or check_xss(
            title):
        resp = make_response({
            "status": "403",
            "message": "Forbidden"
        }, 403)
        return resp

    dao.sql.execute("SELECT username FROM users WHERE username = %(username)s;", {'username': username})
    usernames = dao.sql.fetchone()
    if not usernames:
        resp = make_response({
            "status": "404",
            "message": "Not found"
        }, 404)
        return resp

    if password is None or password is "":
        dao.sql.execute(
            "INSERT INTO notes (title, body) VALUES (%(title)s, %(body)s);", {'title': title, 'body': body})
        dao.db.commit()
        resp = make_response({
            "status": "201",
            "message": "Created",
        }, 201)
        return resp
    else:
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt)
        iv = get_random_bytes(16)
        aes = AES.new(key, AES.MODE_CBC, iv=iv)
        encrypted_note = aes.encrypt(pad(body.encode("utf-8"), AES.block_size))
        note_to_db = base64.b64encode(iv + salt + encrypted_note).decode("utf-8")

        dao.sql.execute(
            "INSERT INTO notes (title, body, owner) VALUES (%(title)s, %(note_to_db)s, %(username)s);",
            {'title': title, 'note_to_db': note_to_db, 'username': username})
        dao.db.commit()
        resp = make_response({
            "status": "201",
            "message": "Created",
        }, 201)
        return resp


@app.route("/decrypt/", methods=["POST"])
def decrypt_note():
    id = request.form.get("id")
    password = request.form.get("password")
    username = session["username"] if "username" in session.keys() else None

    if username is None:
        resp = make_response({
            "status": "401",
            "message": "Unauthorized"
        }, 403)
        return resp

    if password is None or id is None or password is "" or id is "":
        resp = make_response({
            "status": "403",
            "message": "Forbidden"
        }, 403)
        return resp

    if check_if_sqli(password) or check_if_sqli(id) or check_if_sqli(username):
        resp = make_response({
            "status": "403",
            "message": "Forbidden"
        }, 403)
        return resp

    dao.sql.execute("SELECT username FROM users WHERE username = %(username)s;", {'username': username})
    usernames = dao.sql.fetchone()
    if not usernames:
        resp = make_response({
            "status": "404",
            "message": "Not found"
        }, 404)
        return resp

    dao.sql.execute("SELECT body FROM notes WHERE id = %(id)s AND  owner = %(username)s;",
                    {'id': id, 'username': username})
    note = dao.sql.fetchone()

    if not note:
        resp = make_response({
            "status": "404",
            "message": "Not found"
        }, 404)
        return resp
    try:
        note_db = base64.b64decode(note[0])
        byte_note = bytes(note_db)
        iv = byte_note[0:16]
        salt = byte_note[16:32]
        encrypted_note = byte_note[32:]

        key = PBKDF2(password, salt)
        aes = AES.new(key, AES.MODE_CBC, iv=iv)
        og_data = unpad(aes.decrypt(encrypted_note), AES.block_size).decode("utf-8")
        resp = make_response({
            "status": "200",
            "message": og_data,
        }, 200)
        return resp
    except Exception:
        resp = make_response({
            "status": "400",
            "message": "Bad request",
        }, 400)
        return resp


@app.route("/notes/", methods=["GET"])
def get_notes():
    username = session["username"] if "username" in session.keys() else None
    if username is None:
        resp = make_response({
            "status": "401",
            "message": "Unauthorized",
        }, 401)
        return resp

    dao.sql.execute("SELECT username FROM users WHERE  username = %(username)s;", {'username': username})
    usernames = dao.sql.fetchall()
    if not usernames:
        resp = make_response({
            "status": "404",
            "message": "Not found"
        }, 404)
        return resp

    dao.sql.execute("SELECT id, title FROM notes WHERE  owner = %(username)s;", {'username': username})
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

    resp = make_response(jsonify({"notes": notes}), 200)
    return resp


@app.route("/public/", methods=["GET"])
def get_public_notes():
    username = session["username"] if "username" in session.keys() else None
    if username is None:
        resp = make_response({
            "status": "401",
            "message": "Unauthorized",
        }, 401)
        return resp
    dao.sql.execute("SELECT username FROM users WHERE  username = %(username)s;", {'username': username})
    usernames = dao.sql.fetchall()
    if not usernames:
        resp = make_response({
            "status": "404",
            "message": "Not found"
        }, 404)
        return resp

    dao.sql.execute("SELECT id, title, body FROM notes WHERE owner IS NULL;")
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

    resp = make_response(jsonify({"notes": notes}), 200)
    return resp


@app.route("/ips/", methods=["GET"])
def get_ips():
    username = session["username"] if "username" in session.keys() else None
    if username is None:
        resp = make_response({
            "status": "401",
            "message": "Unauthorized",
        }, 401)
        return resp
    dao.sql.execute("SELECT username FROM users WHERE  username = %(username)s;", {'username': username})
    usernames = dao.sql.fetchall()
    if not usernames:
        resp = make_response({
            "status": "404",
            "message": "Not found"
        }, 404)
        return resp

    dao.sql.execute("SELECT ip FROM ips WHERE  username = %(username)s;", {'username': username})
    numrows = dao.sql.rowcount

    ips = []
    for x in range(0, numrows):
        ip_db = dao.sql.fetchone()
        ip = {
            "ip": str(ip_db[0]),
        }
        ip = json.dumps(ip)
        ips.append(ip)

    resp = make_response(jsonify({"ips": ips}), 200)
    return resp


@app.route("/file/", methods=["GET", "POST"])
def save_file():
    if request.method == "POST":
        file = request.files["file"] if "file" in request.files else None

        if file is None:
            resp = make_response({
                "status": "400",
                "message": "Bad request",
            }, 400)
            return resp

        username = session["username"] if "username" in session.keys() else None
        if username is None:
            resp = make_response({
                "status": "401",
                "message": "Unauthorized",
            }, 401)
            return resp

        file_name = file.filename.split(".")[0]

        if check_if_sqli(file_name) or check_if_sqli(username):
            resp = make_response({
                "status": "403",
                "message": "Forbidden"
            }, 403)
            return resp

        dao.sql.execute("SELECT username FROM users WHERE  username = %(username)s;", {'username': username})
        usernames = dao.sql.fetchall()
        if not usernames:
            resp = make_response({
                "status": "404",
                "message": "Not found"
            }, 404)
            return resp

        if not os.path.exists("app/files/"):
            os.mkdir("app/files/")

        file_id = generate_id()

        filename = file_id + "." + file.filename.split(".")[1]

        path_to_file = os.path.join("app/files/", filename)

        file.save(path_to_file)

        dao.sql.execute(
            "INSERT INTO files (path, og_name, owner) VALUES (%(path_to_file)s, %(filename)s, %(username)s);",
            {"path_to_file": path_to_file, 'filename': file.filename, 'username': username})
        dao.db.commit()
        resp = make_response({
            "status": "201",
            "message": "Created",
        }, 201)
        return resp
    elif request.method == "GET":
        username = session["username"] if "username" in session.keys() else None
        if username is None:
            resp = make_response({
                "status": "401",
                "message": "Unauthorized",
            }, 401)
            return resp

        if check_if_sqli(username):
            resp = make_response({
                "status": "403",
                "message": "Forbidden"
            }, 403)
            resp.headers['Server'] = None
            return resp

        dao.sql.execute("SELECT username FROM users WHERE username = %(username)s;", {'username': username})
        usernames = dao.sql.fetchall()
        if not usernames:
            resp = make_response({
                "status": "404",
                "message": "Not found"
            }, 404)
            return resp

        dao.sql.execute("SELECT og_name FROM files WHERE owner = %(username)s;", {'username': username})
        numrows = dao.sql.rowcount

        files = []
        for x in range(0, numrows):
            file_db = dao.sql.fetchone()
            file = {
                "name": str(file_db[0])
            }
            file = json.dumps(file)
            files.append(file)

        resp = make_response(jsonify({"files": files}), 200)
        return resp


def generate_id():
    dao.sql.execute("SELECT path FROM files;")
    numrows = dao.sql.rowcount
    ids = []
    for x in range(0, numrows):
        element = dao.sql.fetchone()[0]
        ids.append(element)

    while True:
        file_id = uuid.uuid4().__str__()
        if file_id not in ids:
            return file_id
