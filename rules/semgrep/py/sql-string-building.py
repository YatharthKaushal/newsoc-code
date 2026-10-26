def a(cursor, name):
    # ruleid: newsoc.py.sql-string-building
    cursor.execute(f"SELECT * FROM t WHERE name = '{name}'")


def b(cursor, uid):
    # ruleid: newsoc.py.sql-string-building
    cursor.execute("SELECT * FROM t WHERE id = %s" % uid)


def c(cursor, uid):
    # ruleid: newsoc.py.sql-string-building
    cursor.execute("SELECT * FROM t WHERE id = {}".format(uid))


def d(cursor, uid):
    # ruleid: newsoc.py.sql-string-building
    cursor.execute("SELECT * FROM t WHERE id = " + uid)


def ok1(cursor, uid):
    # ok: newsoc.py.sql-string-building
    cursor.execute("SELECT * FROM t WHERE id = %s", (uid,))


def ok2(cursor):
    # ok: newsoc.py.sql-string-building
    cursor.execute("SELECT * FROM t")
