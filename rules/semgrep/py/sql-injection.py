from flask import request


def a(cursor):
    name = request.args["name"]
    # ruleid: newsoc.py.sql-injection
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")


def b(cursor):
    # ruleid: newsoc.py.sql-injection
    cursor.execute("DELETE FROM t WHERE id = " + request.form["id"])


def c(User):
    q = "SELECT * FROM auth_user WHERE username = '%s'" % request.GET["u"]
    # ruleid: newsoc.py.sql-injection
    return User.objects.raw(q)


def ok1(cursor):
    # ok: newsoc.py.sql-injection
    cursor.execute("SELECT * FROM users WHERE name = %s", (request.args["name"],))


def ok2(cursor):
    # ok: newsoc.py.sql-injection
    cursor.execute("SELECT * FROM users WHERE id = ?", [request.args["id"]])


def ok3(cursor):
    # ok: newsoc.py.sql-injection
    cursor.execute("SELECT 1")
