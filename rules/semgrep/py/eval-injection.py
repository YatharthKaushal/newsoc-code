import ast
from flask import request


def a():
    # ruleid: newsoc.py.eval-injection
    return eval(request.args["expr"])


def b():
    code = request.form["code"]
    # ruleid: newsoc.py.eval-injection
    exec(code)


def c():
    # ruleid: newsoc.py.eval-injection
    return eval("1 + " + request.json["n"])


def ok1():
    # ok: newsoc.py.eval-injection
    return eval("1 + 1")


def ok2():
    # ok: newsoc.py.eval-injection
    return ast.literal_eval(request.args["value"])


def ok3():
    # ok: newsoc.py.eval-injection
    return int(request.args["n"]) + 1
