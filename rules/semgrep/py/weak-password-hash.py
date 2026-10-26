import hashlib


def a(password):
    # ruleid: newsoc.py.weak-password-hash
    return hashlib.md5(password.encode()).hexdigest()


def b(user_password):
    # ruleid: newsoc.py.weak-password-hash
    return hashlib.sha1(user_password.encode("utf-8")).hexdigest()


def c(pwd):
    # ruleid: newsoc.py.weak-password-hash
    return hashlib.md5(pwd).hexdigest()


def ok1(data):
    # ok: newsoc.py.weak-password-hash
    return hashlib.md5(data).hexdigest()


def ok2(password):
    # ok: newsoc.py.weak-password-hash
    return hashlib.sha256(password.encode()).hexdigest()


def ok3(blob):
    # ok: newsoc.py.weak-password-hash
    return hashlib.sha1(blob).hexdigest()
