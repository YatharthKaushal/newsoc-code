# newsoc application image: the webhook receiver and the scan worker (same code, different command).
#
#   docker build -t newsoc-app .
#
# The worker starts scanner containers on the Docker HOST through the mounted docker.sock, so
# this image carries the Docker CLI (pinned by digest, from the official image) and runs as an
# unprivileged user who belongs to the host's `docker` group. Set DOCKER_GID to that group's id
# (`getent group docker` on the host); the default is Ubuntu's usual value.
FROM docker:29.1.3-cli@sha256:4fa0ee1f3a7e4354c4ea34558b6d4ee32859baf4973d4c8ccc8e7fe3dd730c04 AS dockercli

FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70

ARG DOCKER_GID=109
ARG APP_UID=1000
ARG APP_GID=1000
ARG UV_VERSION=0.12.7

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir "uv==${UV_VERSION}"

COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins/docker-buildx /usr/local/libexec/docker/cli-plugins/docker-buildx

# The scanner containers the worker starts run as this same uid:gid (see DockerRunner), so files
# the worker writes into the shared data directory are readable and writable by them.
RUN groupadd --gid "${DOCKER_GID}" hostdocker \
 && groupadd --gid "${APP_GID}" newsoc \
 && useradd --uid "${APP_UID}" --gid "${APP_GID}" --groups hostdocker --create-home newsoc

WORKDIR /app
ENV UV_PYTHON_DOWNLOADS=never UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:${PATH}" PYTHONUNBUFFERED=1

COPY pyproject.toml uv.lock .python-version ./
COPY src ./src
RUN uv sync --frozen --no-dev

COPY alembic.ini ./
COPY alembic ./alembic
COPY rules ./rules
COPY docker/scanners.Dockerfile ./docker/scanners.Dockerfile

USER newsoc
EXPOSE 8000
CMD ["newsoc", "--help"]
