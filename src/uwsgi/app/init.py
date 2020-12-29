import mysql.connector as mariadb
import os


def init():
    db = mariadb.connect(host="db", user="root", password=os.environ.get("MYSQL_ROOT_PASSWORD"))
    sql = db.cursor()
    sql.execute("DROP DATABASE IF EXISTS ochrona;")
    sql.execute("CREATE DATABASE ochrona;")
    sql.execute("USE ochrona;")

    sql.execute("DROP TABLE IF EXISTS users")
    sql.execute("CREATE TABLE users (username VARCHAR(32), password VARCHAR(150));")
    db.commit()
