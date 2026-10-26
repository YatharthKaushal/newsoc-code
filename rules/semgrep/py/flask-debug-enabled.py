from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    # ruleid: newsoc.py.flask-debug-enabled
    app.run(debug=True)

if __name__ == "__main__":
    # ruleid: newsoc.py.flask-debug-enabled
    app.run(host="0.0.0.0", port=5000, debug=True)

if __name__ == "__main__":
    # ruleid: newsoc.py.flask-debug-enabled
    app.run("0.0.0.0", debug=True, use_reloader=True)

if __name__ == "__main__":
    # ok: newsoc.py.flask-debug-enabled
    app.run(debug=False)

if __name__ == "__main__":
    # ok: newsoc.py.flask-debug-enabled
    app.run(host="127.0.0.1")

# ok: newsoc.py.flask-debug-enabled
something_else.run(debug=True)
