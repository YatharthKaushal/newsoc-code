# newsoc scanner image: four scanners at pinned versions, built to run with no network.
#
#   docker build -f docker/scanners.Dockerfile -t newsoc/scanners:dev .
#
# Semgrep and Checkov live in separate virtual environments because their dependency
# trees conflict. OSV-Scanner and Gitleaks are release binaries verified by SHA-256.
# Licences: Semgrep CE engine LGPL-2.1, Checkov Apache-2.0, OSV-Scanner Apache-2.0,
# Gitleaks MIT. Semgrep Registry rules are NOT used (see docs/MVP_PLAN.md); the worker
# mounts our own rule pack at /rules.
FROM python:3.12-slim-bookworm

ARG UV_VERSION=0.12.7
ARG SEMGREP_VERSION=1.182.1
ARG CHECKOV_VERSION=3.3.30
ARG OSV_SCANNER_VERSION=2.7.0
ARG OSV_SCANNER_SHA256=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "uv==${UV_VERSION}" \
 && mkdir -p /opt/venvs /opt/tools/bin \
 && uv venv /opt/venvs/semgrep && uv pip install --python /opt/venvs/semgrep/bin/python "semgrep==${SEMGREP_VERSION}" \
 && uv venv /opt/venvs/checkov && uv pip install --python /opt/venvs/checkov/bin/python "checkov==${CHECKOV_VERSION}" \
 && ln -s /opt/venvs/semgrep/bin/semgrep /opt/tools/bin/semgrep \
 && ln -s /opt/venvs/checkov/bin/checkov /opt/tools/bin/checkov \
 && pip uninstall -y uv

RUN curl -fsSL -o /opt/tools/bin/osv-scanner \
      "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
 && echo "${OSV_SCANNER_SHA256}  /opt/tools/bin/osv-scanner" | sha256sum -c - \
 && chmod 0755 /opt/tools/bin/osv-scanner

RUN curl -fsSL -o /tmp/gitleaks.tgz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
 && echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tgz" | sha256sum -c - \
 && tar -xzf /tmp/gitleaks.tgz -C /opt/tools/bin gitleaks \
 && rm /tmp/gitleaks.tgz && chmod 0755 /opt/tools/bin/gitleaks

# curl was only needed to download the binaries
RUN apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# No telemetry, no update checks, no cloud lookups. The container also runs with --network none.
ENV PATH=/opt/tools/bin:/usr/local/bin:/usr/bin:/bin \
    HOME=/tmp/home \
    XDG_CACHE_HOME=/tmp/home/.cache \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    SEMGREP_SETTINGS_FILE=/tmp/home/.semgrep/settings.yml \
    BC_SKIP_MAPPING=TRUE \
    CHECKOV_NO_UPDATE_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    GIT_TERMINAL_PROMPT=0

LABEL org.opencontainers.image.title="newsoc scanners" \
      newsoc.semgrep="${SEMGREP_VERSION}" newsoc.checkov="${CHECKOV_VERSION}" \
      newsoc.osv-scanner="${OSV_SCANNER_VERSION}" newsoc.gitleaks="${GITLEAKS_VERSION}"

USER 65534:65534
WORKDIR /src
