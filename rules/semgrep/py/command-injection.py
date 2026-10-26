import os
import subprocess
from flask import request


def a():
    # ruleid: newsoc.py.command-injection
    os.system("ping " + request.args["host"])


def b():
    cmd = request.form.get("cmd")
    # ruleid: newsoc.py.command-injection
    return subprocess.check_output(cmd, shell=True)


def c():
    host = request.json["host"]
    # ruleid: newsoc.py.command-injection
    os.popen(f"nslookup {host}")


def ok1():
    # ok: newsoc.py.command-injection
    os.system("uptime")


def ok2():
    # ok: newsoc.py.command-injection
    return subprocess.check_output(["ping", "-c", "1", request.args["host"]])


def ok3():
    # ok: newsoc.py.command-injection
    return subprocess.run("ls -la /tmp", shell=True)
