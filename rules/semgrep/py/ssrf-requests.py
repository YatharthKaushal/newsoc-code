import requests
import urllib.request
from flask import request


def a():
    # ruleid: newsoc.py.ssrf-requests
    return requests.get(request.args["url"]).text


def b():
    target = request.json["callback"]
    # ruleid: newsoc.py.ssrf-requests
    return requests.post(target, json={"ok": True})


def c():
    # ruleid: newsoc.py.ssrf-requests
    return urllib.request.urlopen("http://" + request.args["host"] + "/x")


def ok1():
    # ok: newsoc.py.ssrf-requests
    return requests.get("https://api.example.com/items")


def ok2():
    # ok: newsoc.py.ssrf-requests
    return requests.get("https://api.example.com/items", params={"q": request.args["q"]})


def ok3(item_id):
    # ok: newsoc.py.ssrf-requests
    return requests.get(f"https://api.example.com/items/{item_id}")
