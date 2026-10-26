import yaml


def a(data):
    # ruleid: newsoc.py.yaml-unsafe-load
    return yaml.load(data)


def b(data):
    # ruleid: newsoc.py.yaml-unsafe-load
    return yaml.load(data, Loader=yaml.Loader)


def c(data):
    # ruleid: newsoc.py.yaml-unsafe-load
    return yaml.load(data, yaml.UnsafeLoader)


def ok1(data):
    # ok: newsoc.py.yaml-unsafe-load
    return yaml.safe_load(data)


def ok2(data):
    # ok: newsoc.py.yaml-unsafe-load
    return yaml.load(data, Loader=yaml.SafeLoader)


def ok3(data):
    # ok: newsoc.py.yaml-unsafe-load
    return yaml.load(data, yaml.SafeLoader)
