import pickle
from flask import request


def a():
    # ruleid: newsoc.py.pickle-untrusted
    return pickle.loads(request.data)


def b():
    blob = request.form["state"].encode()
    # ruleid: newsoc.py.pickle-untrusted
    return pickle.loads(blob)


def c():
    # ruleid: newsoc.py.pickle-untrusted
    return pickle.load(request.files["f"])


def ok1(path):
    with open(path, "rb") as f:
        # ok: newsoc.py.pickle-untrusted
        return pickle.load(f)


def ok2(cached):
    # ok: newsoc.py.pickle-untrusted
    return pickle.loads(cached)


def ok3():
    # ok: newsoc.py.pickle-untrusted
    return pickle.dumps({"a": 1})
