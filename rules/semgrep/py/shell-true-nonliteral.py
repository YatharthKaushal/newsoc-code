import subprocess


def a(cmd):
    # ruleid: newsoc.py.shell-true-nonliteral
    subprocess.call(cmd, shell=True)


def b(name):
    # ruleid: newsoc.py.shell-true-nonliteral
    subprocess.Popen("grep " + name + " file.txt", shell=True)


def c(host):
    # ruleid: newsoc.py.shell-true-nonliteral
    subprocess.run(f"ping {host}", shell=True, check=True)


def ok1():
    # ok: newsoc.py.shell-true-nonliteral
    subprocess.call("ls -la", shell=True)


def ok2(cmd):
    # ok: newsoc.py.shell-true-nonliteral
    subprocess.call(cmd)


def ok3(cmd):
    # ok: newsoc.py.shell-true-nonliteral
    subprocess.call(["echo", cmd], shell=False)
