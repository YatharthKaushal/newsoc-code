import jwt


def a(token):
    # ruleid: newsoc.py.jwt-verify-disabled
    return jwt.decode(token, options={"verify_signature": False})


def b(token, key):
    # ruleid: newsoc.py.jwt-verify-disabled
    return jwt.decode(token, key, algorithms=["HS256"], options={"verify_signature": False, "verify_exp": True})


def c(token, key):
    # ruleid: newsoc.py.jwt-verify-disabled
    return jwt.decode(token, key, verify=False)


def ok1(token, key):
    # ok: newsoc.py.jwt-verify-disabled
    return jwt.decode(token, key, algorithms=["RS256"])


def ok2(token, key):
    # ok: newsoc.py.jwt-verify-disabled
    return jwt.decode(token, key, algorithms=["HS256"], options={"verify_exp": True})


def ok3(token, key):
    # ok: newsoc.py.jwt-verify-disabled
    return jwt.decode(token, key, algorithms=["ES256"], options={"verify_signature": True})
