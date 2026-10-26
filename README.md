# newsoc Code arm (MVP)

A GitHub App that scans every pull request and default-branch push with four sandboxed
scanners, applies a per-repository policy (`.secpolicy.yml`), and reports the result as a check
run with inline annotations plus one pull request comment. It can block merges when a repository
requires the `newsoc/security` check.

It reports technical evidence ("scanner X ran with no findings at commit Y"). It is not a
certification and never says a system is "secure" or "compliant".

The full plan is in [`docs/MVP_PLAN.md`](docs/MVP_PLAN.md).

## How it fits together

```
GitHub --webhook--> newsoc serve (FastAPI) --> Postgres (jobs, findings)
                                                  ^
                                   newsoc worker -+  claims a job, then:
                                     git fetch (token stays outside containers)
                                     docker run  Semgrep | OSV-Scanner | Gitleaks | Checkov
                                                 (no network, read-only source, non-root)
                                     policy from the BASE branch -> decision
                                     check run + annotations + PR comment
```

- The web process never scans; it verifies the signature, records the delivery, queues, returns.
- A new push to a pull request supersedes the older scan and stops its containers.
- Policy is read from the base branch, so a pull request cannot loosen its own gate.

## Requirements

Linux, Docker (your user in the `docker` group; after `usermod -aG docker $USER` run
`newgrp docker` or log in again), [uv](https://docs.astral.sh/uv/), Python 3.12 (uv installs it).

## Set up

```bash
uv sync
docker compose up -d db                       # Postgres on 127.0.0.1:55432
uv run alembic upgrade head
docker build -f docker/scanners.Dockerfile -t newsoc/scanners:dev .
uv run newsoc refresh-osv --db-root ~/.local/share/newsoc/osvdb   # vulnerability data, needs network
```

## Scan a folder (no GitHub needed)

```bash
uv run newsoc scan ./some-repo --osv-db ~/.local/share/newsoc/osvdb \
    --policy some-repo/.secpolicy.yml --sarif out.sarif
```

Exit status: 0 would pass, 1 would fail, 2 newsoc could not run.

## Run against GitHub (development)

Creating the app and installing it are browser steps only you can do.

1. Get a webhook channel at <https://smee.io/new> (dev only: smee has no delivery guarantee).
2. `uv run newsoc create-app --webhook-url https://smee.io/<channel>` opens your browser;
   confirm the app. Credentials go to `~/.config/newsoc/dev/` (files 0600), never into this repo.
3. Install the app on a throwaway repository (the command prints the link).
4. In three terminals:
   ```bash
   npx smee-client --url https://smee.io/<channel> --target http://127.0.0.1:8000/webhooks/github
   uv run newsoc serve
   uv run newsoc worker
   ```
5. Open a pull request. Add `.secpolicy.yml` to the base branch to choose a mode:
   ```yaml
   version: 1
   mode: observe        # observe = report only; enforce = blocking findings fail the check
   gates:
     merge:
       block_on: [critical, high]
       new_findings_only: true
   ```
   Without a policy file a repository runs in observe mode.

`uv run newsoc replay-webhook payload.json --event pull_request` re-sends a saved payload,
signed with the local secret.

## Tests

```bash
uv run pytest                                    # unit tests, plus Postgres tests if db is up
NEWSOC_OSV_DB=~/.local/share/newsoc/osvdb/current uv run pytest   # also the Docker tests
```

Postgres tests skip themselves when the database is unreachable and Docker tests when the
daemon or image is missing, so check the skip count in the summary.

## Layout

| Path | What |
|---|---|
| `src/newsoc_code/scanners/` | one adapter per tool: when it applies, how to run it, how to parse it |
| `src/newsoc_code/runner/` | the sandbox (`DockerRunner`); adapters never touch Docker |
| `src/newsoc_code/policy/` | `.secpolicy.yml` loader and the decision engine (pure function) |
| `src/newsoc_code/github/` | API client, webhook parsing and signature, safe git fetch, app setup |
| `src/newsoc_code/queue/` | Postgres job queue and the worker loop |
| `src/newsoc_code/pipeline.py` | one job from claim to published check |
| `rules/semgrep/` | our own Semgrep rules, each with a test file (`scripts/test_rules.sh`) |
| `contracts/` | language-neutral JSON Schemas and policy conformance vectors |

## Known limits of this MVP

- A renamed file's existing findings look new (fingerprints include the path).
- Semgrep Community Edition has no cross-file analysis, and the rule pack covers about 30
  weakness classes in JavaScript/TypeScript and Python.
- Draft pull requests are scanned when marked ready for review.
- One worker process, one job at a time; no dashboard yet.
- The checkout size cap is checked after the fetch, not during it.
