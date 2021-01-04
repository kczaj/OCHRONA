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
        "CREATE TABLE users (id INT NOT NULL PRIMARY KEY AUTO_INCREMENT, email VARCHAR(30) NOT NULL , name VARCHAR(20) NOT NULL, surname VARCHAR(30) NOT NULL, username VARCHAR(32) NOT NULL, password VARCHAR(150) NOT NULL);")
    sql.execute("CREATE TABLE notes (id INT NOT NULL PRIMARY KEY AUTO_INCREMENT, title VARCHAR (30) NOT NULL, body VARCHAR(1000) NOT NULL, owner VARCHAR(32));")
    db.commit()
