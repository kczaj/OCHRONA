import mysql.connector as mariadb
import os


class DAO:

    def __init__(self):
        self.db = mariadb.connect(host="db", user="root", password=os.environ.get("MYSQL_ROOT_PASSWORD"))
        self.sql = self.db.cursor(buffered=True)

        self.sql.execute("USE ochrona;")
