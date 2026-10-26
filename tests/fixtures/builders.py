"""Deterministic fixture projects with seeded weaknesses.

Fixtures are built into a temporary directory at test time instead of being committed, so the
repository never contains a literal secret (GitHub push protection and Gitleaks would flag it).
Fake credentials are assembled from fragments.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

# Fake credentials, split so no complete token exists in this source file.
AWS_KEY = "AKIA" + "Z3MXQPRSTUVWXY27"
AWS_SECRET = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCYzQ4w9Ke2Ab"
GITHUB_TOKEN = "ghp_" + "R7tK2mNq9XvB4cLd8WsE1yHj5PfA3uZg6TaV"

GIT_ENV = {
    "GIT_AUTHOR_NAME": "fixture",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "fixture",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "PATH": "/usr/bin:/bin:/usr/local/bin",
}


def git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env=GIT_ENV,
    )
    return out.stdout.strip()


def init_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    git(repo, "init", "-q", "-b", "main")


def commit_all(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _npm_entry(name: str, version: str) -> dict[str, str]:
    return {
        "version": version,
        "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
    }


def make_js_app(dst: Path) -> Path:
    """Node project: vulnerable dependencies, injection sinks, a hard-coded token."""
    write(
        dst / "package.json",
        json.dumps(
            {
                "name": "js-app",
                "version": "1.0.0",
                "dependencies": {"lodash": "4.17.15", "minimist": "1.2.0", "express": "4.17.1"},
            },
            indent=2,
        ),
    )
    packages = {
        "": {
            "name": "js-app",
            "version": "1.0.0",
            "dependencies": {"lodash": "4.17.15", "minimist": "1.2.0", "express": "4.17.1"},
        },
        # `resolved` matters: OSV-Scanner skips lockfile entries that look like local packages.
        "node_modules/lodash": _npm_entry("lodash", "4.17.15"),
        "node_modules/minimist": _npm_entry("minimist", "1.2.0"),
        "node_modules/express": _npm_entry("express", "4.17.1"),
    }
    write(
        dst / "package-lock.json",
        json.dumps(
            {"name": "js-app", "lockfileVersion": 3, "requires": True, "packages": packages},
            indent=2,
        ),
    )
    write(
        dst / "src" / "app.js",
        """\
const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/ls', (req, res) => {
  exec('ls ' + req.query.dir, (err, out) => res.send(out));
});

app.get('/hello', (req, res) => {
  res.send('<h1>Hello ' + req.query.name + '</h1>');
});

app.post('/calc', (req, res) => {
  res.send(String(eval(req.body.expr)));
});

app.get('/user', (req, res) => {
  const sql = "SELECT * FROM users WHERE id = '" + req.query.id + "'";
  db.query(sql, (e, rows) => res.json(rows));
});

app.listen(3000);
""",
    )
    write(
        dst / "src" / "config.js",
        f"""\
module.exports = {{
  awsAccessKeyId: "{AWS_KEY}",
  awsSecretAccessKey: "{AWS_SECRET}",
  githubToken: "{GITHUB_TOKEN}",
}};
""",
    )
    return dst


def make_py_app(dst: Path) -> Path:
    """Python project: vulnerable pins, shell injection, unsafe yaml, SQL by f-string."""
    write(dst / "requirements.txt", "flask==0.12.2\npyyaml==5.3\nrequests==2.19.0\njinja2==2.10\n")
    write(
        dst / "app.py",
        """\
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    return subprocess.check_output(request.args["cmd"], shell=True)


@app.route("/load", methods=["POST"])
def load():
    return str(yaml.load(request.data))


@app.route("/user")
def user():
    name = request.args["name"]
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return "ok"


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"], verify=False).text


if __name__ == "__main__":
    app.run(debug=True)
""",
    )
    return dst


def make_tf_infra(dst: Path) -> Path:
    """Terraform and a Dockerfile with classic misconfigurations."""
    write(
        dst / "main.tf",
        """\
resource "aws_s3_bucket" "data" {
  bucket = "example-public-data"
  acl    = "public-read"
}

resource "aws_security_group" "ssh" {
  name = "open-ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "db" {
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
  storage_encrypted   = false
}
""",
    )
    write(
        dst / "Dockerfile",
        """\
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
ADD https://example.invalid/install.sh /tmp/install.sh
COPY . /app
CMD ["/app/run.sh"]
""",
    )
    return dst


def make_clean_app(dst: Path) -> Path:
    """A project with nothing to report; used for 'scanner ran, no findings' cases."""
    write(dst / "package.json", json.dumps({"name": "clean", "version": "1.0.0"}))
    write(dst / "src" / "index.js", "module.exports = (a, b) => a + b;\n")
    return dst


def make_mixed(dst: Path) -> Path:
    """All of the above side by side, as a monorepo."""
    make_js_app(dst / "web")
    make_py_app(dst / "api")
    make_tf_infra(dst / "infra")
    return dst


BUILDERS = {
    "js-app": make_js_app,
    "py-app": make_py_app,
    "tf-infra": make_tf_infra,
    "clean-app": make_clean_app,
    "mixed": make_mixed,
}
