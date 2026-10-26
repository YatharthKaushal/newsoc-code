import os
from flask import request, send_file
from werkzeug.utils import secure_filename


def a():
    # ruleid: newsoc.py.path-traversal
    return open(request.args["file"]).read()


def b():
    name = request.form["name"]
    # ruleid: newsoc.py.path-traversal
    return send_file(os.path.join("/uploads", name))


def c():
    # ruleid: newsoc.py.path-traversal
    os.remove("/tmp/" + request.args["f"])


def ok1():
    # ok: newsoc.py.path-traversal
    return send_file(os.path.join("/uploads", secure_filename(request.args["f"])))


def ok2():
    # ok: newsoc.py.path-traversal
    return open("/etc/app/config.yml").read()


def ok3():
    # ok: newsoc.py.path-traversal
    return open(os.path.join("/data", os.path.basename(request.args["f"])))
