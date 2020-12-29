from flask import Flask

from app.init import init

app = Flask(__name__)


@app.before_first_request
def costa():
    init()


@app.route('/')
def index():
    return "hello world"


@app.route("/costam")
def fei():
    return "costam"
