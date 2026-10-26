from flask import render_template_string, request
from jinja2 import Template


def a():
    # ruleid: newsoc.py.ssti-template-string
    return render_template_string("Hello " + request.args["name"])


def b():
    tpl = request.form["tpl"]
    # ruleid: newsoc.py.ssti-template-string
    return Template(tpl).render()


def c():
    # ruleid: newsoc.py.ssti-template-string
    return render_template_string(request.data.decode())


def ok1():
    # ok: newsoc.py.ssti-template-string
    return render_template_string("Hello {{ name }}", name=request.args["name"])


def ok2():
    # ok: newsoc.py.ssti-template-string
    return Template("static").render()


def ok3():
    # ok: newsoc.py.ssti-template-string
    return render_template_string("<p>{{ q }}</p>", q=request.args["q"])
