import mysql.connector as mariadb
import os


class DAO:

    def __init__(self):
        self.db = mariadb.connect(host="db", user="root", password=os.environ.get("MYSQL_ROOT_PASSWORD"))
        self.sql = self.db.cursor(buffered=True)
        # self.init()
        self.sql.execute("USE ochrona;")

    def init(self):
        self.sql = self.db.cursor()
        self.sql.execute("DROP DATABASE IF EXISTS ochrona;")
        self.sql.execute("CREATE DATABASE ochrona;")
        self.sql.execute("USE ochrona;")

        self.sql.execute("DROP TABLE IF EXISTS users")
        self.sql.execute(
            "CREATE TABLE users (email VARCHAR(30), name VARCHAR(20), surname VARCHAR(30), username VARCHAR(32), password VARCHAR(150));")
        self.db.commit()


