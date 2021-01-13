import mysql.connector as mariadb
import os

from app.init import init


class DAO:

    def __init__(self):
        self.db = None
        while self.db is None:
            try:
                self.db = mariadb.connect(host="db", user="root", password=os.environ.get("MYSQL_ROOT_PASSWORD"))
                self.sql = self.db.cursor(buffered=True)
            except Exception:
                self.db = None
        init()
        self.sql.execute("USE ochrona;")
