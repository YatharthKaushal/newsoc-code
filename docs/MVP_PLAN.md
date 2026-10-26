# Plan: build the Code arm MVP (newsoc), Python modular monolith

## Context
`plan.md` and the 15-page PDF in `/home/yatharth/Documents/AIB/newsoc-temp/` define the product. The next step is to build the **Code arm MVP** (plan.md section 3.9): a hosted GitHub App that scans every push and pull request, posts a check run and a pull request comment, and gates merging according to `.secpolicy.yml`. It is never a certification tool. Intended outcome (exit check): it runs on **5 real repositories without breaking their CI/CD**, with measured precision and speed.

**Decisions made with the user**
- **Shape:** a hosted, webhook-driven service plus a GitHub App (the "bot"). It is not an agent (agents belong to the Endpoint arm). The scan engine stays separable so a CLI or GitHub Action wrapper can follow.
- **Stack:** Python 3.12 (pinned with `uv`) modular monolith: FastAPI web process plus a worker process, Postgres, scanners in containers. `contracts/` holds language-neutral JSON Schemas and shared test vectors so a later Go endpoint agent can prove it agrees with the Python policy engine. Next.js dashboard comes in v1 behind the same API.
- **Location:** `/home/yatharth/Documents/AIB/newsoc-temp/code-arm/`, its own local git repository, nothing pushed anywhere.
- **Sandbox:** Docker from day one. The user ran `sudo usermod -aG docker $USER`; the group is not active in this session until `newgrp docker` or a re-login. Verified: the daemon works through `sg docker` and containers run with `--network none`.
- **Test repos:** 2 real repositories plus 3 forks of vulnerable-by-design projects (OWASP Juice Shop, NodeGoat, pygoat) under the user's GitHub account.
- **Machine:** Linux, 4 cores, 7.5 GB RAM, `uv`, Node 24, Go 1.27, `gh` logged in (repo, workflow scopes). Nothing else installed; scanners come from our own image.

## Corrections to the earlier plan (found in design review)
Apply to plan.md as the last step (section "Doc sync").
1. **Policy is read from the base branch**, never from the pull request head, or a PR could loosen its own gate or approve its own waiver.
2. **A `neutral` check passes a required status check.** Fail-closed outcomes must be `failure` or `action_required`.
3. **Targets:** replace "recall at least 70%" with **in-scope recall** (only the weakness classes our rules claim). Semgrep CE has no cross-file taint and we start with about 25 rules. Keep precision at least 85%, and let a rule **block** only at 90% precision or better; new rules run warn-only first.
4. **Events:** add `merge_group` (or a merge queue stalls); drop `deployment` from the MVP. Inline comments become **check annotations**. SARIF is exported, not uploaded (upload needs `security_events: write`, and private repos need GitHub Advanced Security).
5. **Policy subset:** add `mode: observe | enforce` and `on_scanner_error: warn | block`; MVP actions are only `warn` and `block` (other keys such as `suggest-fix` are accepted with a warning); every waiver needs `expires`, at most 365 days out.
6. **Semgrep licence:** use the Semgrep CE engine (LGPL 2.1) with **our own clean-room rule pack**. The Semgrep Rules License v1.0 forbids registry rules in a product that is sold; some third-party registry rules are AGPL. A CI lint rejects any non-local `--config`.
7. **"Verified"** means "scanner X ran with no findings at commit Y", never "secure" or "compliant". Empty categories say "Not assessed (no applicable files)".

## Architecture
```
GitHub --webhook--> web (FastAPI) --> Postgres (jobs, findings, installs, deliveries)
                       | enqueue            ^
                       v                    |
                    worker (Python) --------+
                     +- git fetch (installation token stays OUTSIDE containers)
                     +- docker run --> Semgrep(+own rules) | OSV-Scanner | Gitleaks | Checkov
                     |                 no network, read-only source, non-root
                     +- normalise -> fingerprint -> baseline diff
                     +- policy engine (.secpolicy.yml from BASE branch) -> decision
                     +- reporter --> GitHub: check run + annotations + PR comment, SARIF file
contracts/  JSON Schema (Finding, Policy) + conformance test vectors
Later: Next.js dashboard -> same API | LLM triage = Python module | Go endpoint agent -> same ingest API
```

## Repository layout (`code-arm/`)
```
pyproject.toml, uv.lock, .python-version, alembic/, docker-compose.yml (Postgres), .gitignore
contracts/                 finding.schema.json, policy.schema.json, vectors/*.json
src/newsoc_code/
  config.py                pydantic-settings, secret file paths
  app/main.py, app/webhooks.py     HMAC check, delivery dedupe, enqueue, 202
  github/{client,fetch,checks,comments}.py   githubkit App auth, token cache, retries, annotation batching
  db/{models,session}.py   queue/{queue,worker}.py   (Postgres queue, SELECT ... FOR UPDATE SKIP LOCKED)
  runner/{base,docker,local}.py    Runner protocol; docker is the MVP runner; local only for unit tests
  scanners/{base,semgrep,osv,gitleaks,checkov}.py   adapter: applicable, argv, parse -> ScanResult
  findings/{schema,fingerprint,baseline}.py
  policy/{schema,loader,engine}.py
  report/{check_run,pr_comment,sarif}.py
  cli.py                   newsoc scan | serve | worker | replay-webhook | refresh-osv
rules/semgrep/{js,py}/*.yaml + test files
docker/scanners.Dockerfile       pinned versions + sha256 (semgrep and checkov in separate venvs)
scripts/{create_app.py,refresh_osv_db.sh}   deploy/{compose.prod.yml,Caddyfile,systemd/}
tests/{unit,golden,integration,e2e,fixtures}   docs/MVP_PLAN.md (copy of this plan)
```
Key design choices: runner and adapter are separate interfaces (swap sandboxes freely); the webhook process never scans (GitHub drops a delivery after 10 s); the CLI runs the identical pipeline without GitHub, so most testing is offline.

## Scan semantics
**Normalisation** (parse each tool's native JSON, never trust empty or truncated output; bad output means `failed`, not zero findings).

| Tool | Severity | Confidence | Fingerprint (no line numbers) |
|---|---|---|---|
| Semgrep (own rules) | `metadata.severity`, else ERROR/WARNING/INFO to high/medium/low | `metadata.confidence` (required in every rule) | rule_id, path, normalised match text, occurrence index |
| OSV-Scanner | CVSS 9+ critical, 7+ high, 4+ medium, else low; `MAL-*` critical | exact lockfile version high, range medium | ecosystem, package, project directory (not the lockfile), canonical vuln id |
| Gitleaks | high; critical for private keys and cloud/VCS tokens | specific rule high, generic or entropy medium | rule_id + salted hash of the value; secret values never stored or posted |
| Checkov | our curated table of about 60 check ids (OSS severity is null), default medium | curated high, else medium | check_id, path, resource address |

Extra fields: `category` (sast, sca, secrets, iac), path, line range, `cwe[]`, `vuln_ids[]`, rule and scanner versions, commit.

**new_findings_only:** compare a head scan with a base scan at the merge-base by fingerprint (base results cached by repo, sha, scanner and rule-pack versions; default-branch pushes pre-warm the cache). SAST and IaC scan changed files (renames mapped with `git diff -M`) at head and base. SCA compares base and head lockfiles by (package, vuln id): a version bump with the same advisory is not new, a newly published advisory on an unchanged dependency is "existing". Secrets scan the commit range `merge-base..head`; a secret added then deleted still blocks ("rotate; history rewrite needed"). If the base scan fails, fall back to changed-line mapping and label it "baseline unavailable".

**Policy engine:** `blocks = in_scope ∧ ¬waived ∧ action(category)=block ∧ severity ∈ block_on ∧ confidence ≥ medium`. Waivers match a rule id, CWE, CVE or GHSA plus a path glob, valid through `expires` (UTC, inclusive); expired waivers are ignored and flagged. Safe YAML loader, 64 KB limit, strict model. Invalid policy: defaults plus a failing title; missing policy: defaults plus a notice. Defaults: `block_on [critical, high]`, `new_findings_only true`, secrets, sca, sast `block`, iac `warn`, `mode observe`.

**Check conclusions:** `failure` = blocking finding or invalid policy; `action_required` = a blocking category was Not assessed (with a Re-run action); `neutral` = warnings only, observe mode, or a warn-only scanner error; `success` = every applicable category assessed and clean. A watchdog completes any check still `in_progress` after 15 minutes (neutral in observe, `action_required` in enforce). Timeouts: 5 min per scanner, 15 min per job. Gitleaks failure under `secrets: block` fails closed.

## Docker sandbox (day one)
- One image `newsoc/scanners` with pinned, checksum-verified tools. Run flags: `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit --memory --cpus --user 65534`, source mounted `:ro`, a tmpfs and one rw output directory, OSV database mounted `:ro`.
- Clone happens in the worker, outside the container (`git fetch --depth` with the installation token, `core.hooksPath=/dev/null`, no submodules, LFS skipped, fork PRs fetched from `refs/pull/N/head`). The token never enters a container. Scanners only parse code; nothing is executed (Checkov external modules off).
- Disable tool networking anyway: Semgrep `--metrics=off --disable-version-check` and local `--config` only; Checkov `--skip-download --download-external-modules false`; OSV `--offline` with a database refreshed every 6 hours by a timer **outside** the sandbox (snapshot age over 48 h warns, over 7 days makes SCA Not assessed). Verify exact flag names on the pinned versions.
- Limits: two concurrent jobs, Semgrep `--jobs 2 --max-memory 2500`. Cancel with `docker kill`. Later hardening: gVisor (`runsc`) or rootless Docker. The worker needs the Docker socket, which is root-equivalent on the host, so it runs as a dedicated user.

## GitHub App
- **Permissions:** Checks r/w, Contents r, Metadata r, Pull requests r/w, Merge queues r. No Administration, Actions, Secrets or Workflows. **Events:** pull_request (opened, synchronize, reopened, ready_for_review), push (default branch builds the baseline, does not gate), check_run and check_suite (rerequested), merge_group; installation events arrive automatically.
- `scripts/create_app.py` runs the manifest flow on 127.0.0.1 and writes `app.pem`, `webhook_secret` and `app.env` to `~/.config/newsoc/<env>/` (0600). Two apps: `newsoc-dev` (smee URL) and `newsoc` (pilot). Secrets never enter the repo.
- **Lifecycle:** verify `X-Hub-Signature-256` with `hmac.compare_digest`; insert the delivery id (primary key = idempotency); the worker creates check `newsoc/security` `in_progress` immediately so a required check never sits at "expected"; a new `synchronize` marks older jobs for the PR superseded and completes their checks as `cancelled`; annotations go 50 per Update call, severity-sorted, capped at 500, the summary truncated under 65,535 characters; the PR comment is upserted via a `<!-- newsoc:summary -->` marker; 403/429 honour `Retry-After` with backoff; write calls serialised per installation.
- **Gating:** a repository ruleset with `required_status_checks` pinned by `integration_id` to our app, created per pilot repo with `gh api`. Roll out `mode: observe` for a week, ruleset in `evaluate` (or created later if unavailable), then `enforce`.

## Own Semgrep rule pack (clean-room, about 25 rules first, about 50 by week 5)
JS/TS: command injection via `exec`, `eval`/`new Function`, SQL built into `pg`/`mysql`/`sequelize.query`/`knex.raw`, Mongo `$where` or `find(req.body)`, reflected XSS from `req.*`, `dangerouslySetInnerHTML` and `innerHTML` with non-literals, path traversal in `fs`/`sendFile`, SSRF from `req.*`, open redirect, JWT `none` or `decode` as verify, `rejectUnauthorized:false`, weak cipher or ECB, permissive CORS with credentials, unsafe deserialisation. Python: `shell=True` or `os.system`, `eval`/`exec`, SQL by f-string or `.raw`/`text()`, `pickle`/unsafe `yaml.load`, `verify=False`, Flask `debug=True`, `render_template_string` with request data, weak password hashing, path traversal and SSRF from `request.*`, XXE in `lxml`, `@csrf_exempt`.
Each rule has a test file (`ruleid:`, `ok:`, `todoruleid:`, at least 3 positive and 3 near-miss negative), mandatory `cwe`, `severity`, `confidence` metadata, taint mode with sources limited to `req.*`/`request.*`, default ignores (tests, fixtures, `node_modules`, `dist`, minified, migrations). CI runs `semgrep --validate` and `--test`. Triage hits on about 20 popular clean repos; a rule may block only at 90% precision; provenance notes per rule.

## Build order (8 weeks, riskiest first)
| Wk | Deliverable | Test | Human step |
|---|---|---|---|
| 0 (1 to 2 days) | `git init code-arm`, uv project, `docker-compose.yml` Postgres, contracts draft, copy of this plan | `newgrp docker`; `docker run --network none hello-world` | Re-login or `newgrp docker`; pick the 2 real repos; OK to fork Juice Shop, NodeGoat, pygoat |
| 1 | `newsoc/scanners` image, `DockerRunner`, adapters, `newsoc scan PATH` on 3 fixture repos (py, node, terraform+Dockerfile), OSV offline refresh | `curl` inside the sandbox fails; golden file per adapter incl. crash cases | none |
| 2 | Finding schema, fingerprint, baseline, policy loader and engine, SARIF export, first 25 rules | Policy matrix + Hypothesis properties (expired waiver never applies; head-policy edits never change the decision); SARIF schema validation; `semgrep --test` | none (I read the Checkov, Gitleaks and OSV data licences) |
| 3 | `create_app.py`, webhook receiver, delivery dedupe, queue, worker, fetch, check run in_progress then completed | Signed webhook fixtures; duplicate delivery ignored; PR on a sandbox repo completes a check | Browser: create `newsoc-dev`, install it on a sandbox repo |
| 4 | Annotation batching, truncation, comment upsert, stale-run cancel, re-run, merge_group, fork PRs | 120 findings = 3 update calls; two quick pushes cancel the first; fork PR works | A second GitHub account for the fork PR |
| 5 | Hardening: timeouts, Not assessed paths, watchdog, rate limits, size and file caps, cleanup, secret redaction; rules to about 50 | Fault injection (exit 2, hang, OOM) gives neutral or action_required, never success; no secret value in DB or comments | none |
| 6 | Pilot host (VM + Docker + Caddy + systemd), production app, rulesets in evaluate, benchmark labelling | Smoke test via the public URL; restart mid-scan resumes or ends cleanly | VM and DNS; production app in the browser; confirm the 5 repos |
| 7 | Pilot: observe week then enforce week on 5 repos | p50 push-to-comment under 3 min and p95 under 5 over 30 PRs; zero stuck checks | Repo owners triage findings |
| 8 | Tune false positives, waiver workflow, docs, buffer | **Exit check** (below) | Sign-off |

## Local dev loop and pilot
`uv sync`, `docker compose up -d` (Postgres), `alembic upgrade head`, `newsoc serve`, `newsoc worker`, `npx smee-client --url https://smee.io/<chan> --target http://127.0.0.1:8000/webhooks/github`; `newsoc replay-webhook <fixture>` for signed local replays; `newsoc scan ./repo --policy x.yml --sarif out.sarif` needs no GitHub. Pilot: one VM (4 vCPU, 8 GB, Ubuntu 24.04) running the compose stack behind Caddy, systemd for the OSV refresh timer, nightly `pg_dump`. smee is dev-only (no delivery guarantee).

## Verification (end to end)
- **Unit and golden:** `uv run pytest`, `semgrep --test rules/`, per-tool golden files from the pinned versions (incl. truncated JSON, exit 2, 137, timeout), fingerprint stability across line shifts and renames, annotation chunking and truncation.
- **GitHub contract tests:** mocked client validated against GitHub's OpenAPI; signature check, comment upsert, redelivery, retries, token refresh, watchdog.
- **Fixture repos:** deterministic `js-app`, `py-app`, `tf-infra`, `mixed` with scenario branches (add SQL injection, rename, add then remove a secret, lockfile bump, loosen policy, add or expire a waiver, invalid policy, injected scanner fault), each with `expected.yaml`.
- **E2E:** `gh repo create newsoc-e2e-N --private`, push fixtures, ruleset requires `newsoc/security` pinned to the app, open PRs, poll check runs, assert conclusion, annotations, comment text and `mergeable_state=blocked`.
- **Benchmark:** tune on Juice Shop and NodeGoat; hold out DVNA and pygoat (and terragoat for IaC, noting vendor bias). Ground truth at a pinned commit (Juice Shop code-fix snippets, documented vulnerabilities elsewhere); match on same file, line within 3, same CWE family; two reviewers adjudicate every unmatched hit; report in-scope and overall recall per category.
- **Exit check, per repo:** at least 2 languages and 1 Terraform repo across the 5; at least 20 PRs each; one observe week then one enforce week; zero workflows modified or slowed; zero false failures needing an override; zero stuck `in_progress`; every injected scanner crash shows as Not assessed or `action_required`; merge queue and fork PRs work; no secret value in any comment or log; each maintainer signs off.

## Risks and mitigations
1. **Own rule-pack quality and effort** (biggest): start week 2, precision gate, shadow mode, per-rule kill switch; Bandit and gosec (Apache-2.0) as optional extras after a licence check.
2. **Breaking pilot CI:** always complete a check (watchdog), fail open in observe, ruleset in evaluate first, merge_group supported.
3. **False positives:** new-findings-only, waivers, 90% precision gate.
4. **Hostile repos:** no network, read-only mounts, token outside containers, rlimits, symlink and YAML-bomb defences, output caps. Docker socket is root-equivalent: dedicated user, then gVisor or rootless Docker.
5. **7.5 GB RAM:** two jobs, sequential per job, Semgrep memory cap.
6. **Licences:** Gitleaks CLI only (not the Action), Checkov licence read from its repo, OSV data attribution, Semgrep engine only, a `THIRD_PARTY_NOTICES` file.
7. **Timeline:** benchmark labelling takes 1 to 1.5 weeks of the 8.
8. **Unverified until implementation:** exact OSV-Scanner v2 offline flags, Checkov flags, and the ruleset API shape for `integration_id`; pin versions and check each in week 1 or 3.

## Doc sync (last step)
Update `plan.md` sections 1.4, 3.4, 3.7, 3.9 with the corrections above and link this MVP plan; if the PDF's Code-arm pages mention the old targets, edit `doc-src` and rebuild with `python3 doc-src/build.py`.

---

## Status and deviations (updated 2026-10-26)

**Done (weeks 0 to 3, except the human steps):** scanner image and `DockerRunner` (with cancel and
orphan sweep), four adapters, OSV offline refresh, finding schema, fingerprints, baselines, policy
loader and engine (with conformance vectors), SARIF export, 31 own Semgrep rules, GitHub client,
rendering and publishing, Postgres schema (alembic), job queue, webhook receiver, safe git fetch,
job pipeline, worker, `newsoc serve | worker | replay-webhook | create-app`. 527 tests pass,
including the full pipeline with the real scanners in Docker (clean PR about 12 s end to end).

**Waiting on a human:** create the `newsoc-dev` app (`newsoc create-app`), install it on a sandbox
repository, and watch one real pull request complete. Nothing has run against real GitHub yet.

**Deviations from the plan above (apply to plan.md in the doc sync):**
- The queue module is `queue/jobs.py`, not `queue/queue.py`. The pipeline is `pipeline.py`.
- App creation is `newsoc create-app`, not `scripts/create_app.py`.
- Draft pull requests are skipped until `ready_for_review`.
- The check run is created by the worker when it starts the job, not by the web process.
- Head scans cover the changed files only (SAST, IaC); SCA covers the lockfiles; secrets scan the
  commit range `merge-base..head`. The baseline is the cached full scan of the merge base from a
  default-branch push, or a scoped scan of the base when none is cached. The cache key includes
  tool versions, the rule pack hash and the OSV snapshot name.
- The installation token is limited to `contents: read` on the one repository.
- A failure closes the check as `neutral` in observe mode and `action_required` otherwise,
  including when the mode is not yet known.
- SCA reports a vulnerable dependency once per project directory, not once per lockfile. Hits
  with the same ecosystem, package, exact version and canonical advisory id whose lockfiles share
  a directory are one finding (a repository that keeps `package-lock.json` and `yarn.lock` side
  by side used to get every finding twice). The finding sits on the preferred lockfile
  (`npm-shrinkwrap.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`; then `poetry.lock`,
  `uv.lock`, `pdm.lock`, `Pipfile.lock`, `requirements.txt`; unknown names last, then by path)
  and lists the others in `extra["also_in"]`, in the message and in the evidence. The SCA
  fingerprint is (ecosystem, package, project directory, advisory id): it does not name a
  lockfile, so adding or removing a duplicate lockfile never turns a baselined finding into a new
  one, and it still has no version or line (a bump that leaves the advisory unfixed is not new).
  The cost: a vulnerable version that appears only in a second lockfile of a directory, for a
  package and advisory already reported there, counts as existing; and a waiver that names a
  lockfile path must name the primary one. The same package in another directory (a monorepo) or
  another ecosystem stays a separate finding, and so does the same package at another version
  (those findings share one fingerprint, because the fingerprint has no version). Fingerprints
  changed with this, so cached baselines are keyed on `fingerprint.SCHEME_VERSION` and are
  rebuilt once.
- Verified against GitHub's OpenAPI description: `merge_queues` is a valid permission key.
- Postgres 15 or later is required (`NULLS NOT DISTINCT` on the active-job index).

**Not yet done:** the checkout size cap is applied after the fetch, not during it; a renamed
file's existing findings look new; one concurrent job per worker; weeks 4 to 8 of the plan.

**Deployment (added 2026-10-26):** `Dockerfile`, `deploy/compose.prod.yml` and `synq.json` deploy
the stack on a Synq host. Decisions: the worker mounts the host Docker socket (accepted for a
test on a shared host; a separate server is the recommended home); the worker runs unprivileged
and refuses to start scanners as root; secrets come from environment variables (`SecretStr`) with
no built-in salt outside `dev`; the worker builds the scanner image, installs the rule pack and
refreshes the OSV database itself, all on a directory shared at the same path with the host.
A topology test caught one real bug (the OSV seed project was created in the container's own
`/tmp`, invisible to the host's Docker), now covered by a regression test.

**Coverage honesty (added 2026-10-26).** A replay of a 100% Java repository gave `success` with
"No new findings" although only the secrets scanner had run (static analysis (SAST), dependency
scanning (SCA) and infrastructure-as-code scanning (IaC) were "not applicable"). Decisions:
- **Presentation only; gating is unchanged.** No input changes its conclusion (the policy vectors
  are a contract with the future Go agent). A matrix of 7,776 inputs recorded from the engine at
  commit ba49715 proves it (`tests/unit/test_policy_conclusion_matrix.py`). Making a missing code
  analysis block would be a policy option, decided separately.
- The engine computes a `Coverage` (assessed categories; each gap is not applicable, failed, timed
  out or not run). When no code-analysis category (SAST, SCA, IaC) was assessed, a clean result's
  title is "No new findings; only secrets were assessed (no SAST, SCA or IaC coverage)" (or
  "Nothing was assessed ..."). Every other title is unchanged; new vectors pin the wording.
- The check summary and the comment get a "Coverage" line (the reason per scanner stays in the
  category table, which now shows "-" instead of "0" findings for a scanner that did not run).
  "Verified" keeps its meaning: scanner X ran with no findings at commit Y.
- **Unsupported-language note: yes.** When no code analysis ran because nothing applied, the note
  also lists what newsoc supports: JavaScript, TypeScript and Python code; npm and PyPI dependencies
  (lockfiles); Terraform files and Dockerfiles; secrets in every language. Partial gaps and scanner
  failures get the Coverage line only, so routine pull requests stay short.
