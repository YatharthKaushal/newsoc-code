# Conformance vectors

Language-neutral test cases for the policy engine. Any implementation of the engine, in any
language, must produce the `expected` block for each case. The Python tests in
`tests/unit/test_policy_vectors.py` run them against `newsoc_code.policy.engine`; a Go endpoint
agent runs the same files to prove it agrees.

Each file is one case:

| Field | Meaning |
|---|---|
| `policy_yaml` | the policy text exactly as read from the base branch |
| `today` | the evaluation date (UTC); the engine has no clock of its own |
| `baseline` | fingerprints present on the base branch, or `null` if unavailable |
| `results` | per-scanner results: `status` is `ok`, `failed`, `timeout` or `not_applicable` |
| `expected.conclusion` | `success`, `neutral`, `failure` or `action_required` |
| `expected.title` | the one-line summary |
| `expected.outcomes` | fingerprint to `blocked`, `would_block`, `warned`, `waived` or `baselined` |

## The success title

`expected.title` is compared exactly, and one rule decides the title of a clean (`success`) result.
It is wording only: it never changes the conclusion. A category counts as assessed when a scanner
for it has status `ok` and no scanner for it failed or timed out.

| Assessed categories | Title |
|---|---|
| at least one of `sast`, `sca`, `iac` | `No new findings` |
| only `secrets` | `No new findings; only secrets were assessed (no SAST, SCA or IaC coverage)` |
| none | `Nothing was assessed (no scanner had anything to analyse)` |

Every other title (blocking findings, observe mode, not assessed, findings reported, invalid
policy) is the same whatever was assessed. The vectors `only-secrets-assessed-is-not-an-all-clear`,
`nothing-assessed-is-not-an-all-clear`, `one-code-analysis-category-assessed-keeps-the-plain-title`
and `every-scanner-failed-is-not-success` pin the rule.

Write expected values by hand from the rules in `docs/MVP_PLAN.md`; never generate them by
running the engine, or the vectors would only prove the engine agrees with itself.
