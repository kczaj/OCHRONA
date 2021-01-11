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
    sql.execute(
        "CREATE TABLE notes (id INT NOT NULL PRIMARY KEY AUTO_INCREMENT, title VARCHAR (30) NOT NULL, body VARCHAR(1000) NOT NULL, owner VARCHAR(32), password VARCHAR(150));")
    sql.execute(
        "CREATE TABLE files (id INT NOT NULL PRIMARY KEY AUTO_INCREMENT, path VARCHAR (70) NOT NULL, og_name VARCHAR(50) NOT NULL, owner VARCHAR(32) NOT NULL);")
    sql.execute("CREATE TABLE ips (id INT NOT NULL PRIMARY KEY AUTO_INCREMENT, ip VARCHAR (15), username VARCHAR(32));")
    sql.execute(
        f"INSERT INTO users (email, name, surname, username, password) VALUES (\'jakis@mail.com\', \'imie\', \'nazwisko\', \'admin\', \'$2b$14$cON4hh1yS4WGQ0aIbK.X.uw754.6ZN6p3DUsvIxb9/LUKQgRQoANO\');")
    db.commit()
