from lxml import etree
import lxml.etree


def a():
    # ruleid: newsoc.py.xxe-lxml
    return etree.XMLParser(resolve_entities=True)


def b():
    # ruleid: newsoc.py.xxe-lxml
    return etree.XMLParser(load_dtd=True, resolve_entities=True, no_network=False)


def c():
    # ruleid: newsoc.py.xxe-lxml
    return lxml.etree.XMLParser(resolve_entities=True)


def ok1():
    # ok: newsoc.py.xxe-lxml
    return etree.XMLParser(resolve_entities=False)


def ok2():
    # ok: newsoc.py.xxe-lxml
    return etree.XMLParser()


def ok3():
    # ok: newsoc.py.xxe-lxml
    return etree.XMLParser(no_network=True, huge_tree=False)
