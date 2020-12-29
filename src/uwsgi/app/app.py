from flask import Flask, render_template, make_response

from app.init import init

app = Flask(__name__)


@app.before_first_request
def init_db():
    init()


@app.route('/')
def index():
    return make_response(render_template("index.html"), 200)

