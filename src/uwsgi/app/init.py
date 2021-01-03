import mysql.connector as mariadb
import os


def init():
    db = mariadb.connect(host="db", user="root", password=os.environ.get("MYSQL_ROOT_PASSWORD"))
    sql = db.cursor()
    sql.execute("DROP DATABASE IF EXISTS ochrona;")
    sql.execute("CREATE DATABASE ochrona;")
    sql.execute("USE ochrona;")

    sql.execute("DROP TABLE IF EXISTS users")
    sql.execute(
        "CREATE TABLE users (email VARCHAR(30), name VARCHAR(20), surname VARCHAR(30), username VARCHAR(32), password VARCHAR(150));")
    sql.execute("CREATE TABLE notes (title VARCHAR (30), body VARCHAR(1000), owner VARCHAR(32));")
    db.commit()
