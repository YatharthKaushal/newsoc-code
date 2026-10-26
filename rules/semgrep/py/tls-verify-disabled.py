import requests
import ssl


def a(url):
    # ruleid: newsoc.py.tls-verify-disabled
    return requests.get(url, verify=False)


def b(url, data):
    # ruleid: newsoc.py.tls-verify-disabled
    return requests.post(url, json=data, timeout=5, verify=False)


def c():
    # ruleid: newsoc.py.tls-verify-disabled
    return ssl._create_unverified_context()


def d(session):
    # ruleid: newsoc.py.tls-verify-disabled
    session.verify = False


def ok1(url):
    # ok: newsoc.py.tls-verify-disabled
    return requests.get(url, verify=True)


def ok2(url):
    # ok: newsoc.py.tls-verify-disabled
    return requests.get(url, verify="/etc/ssl/ca.pem")


def ok3(url):
    # ok: newsoc.py.tls-verify-disabled
    return requests.get(url)
