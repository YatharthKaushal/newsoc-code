"""Render a policy outcome as a check-run summary, check annotations and a pull request comment.

Everything here is a pure function of the scan results and the policy outcome.

Finding messages contain text we did not write (CVE summaries, rule descriptions, code
snippets from a hostile repository), and the result is shown as Markdown on a pull request.
``md_text`` therefore neutralises HTML, ``@mentions``, pipes and newlines before anything is
placed in a table or sentence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from newsoc_code.findings.schema import AssessmentStatus, Category, Finding, ScanResult, Severity
from newsoc_code.policy.engine import CODE_ANALYSIS, Decision, GapKind, Outcome, PolicyOutcome

COMMENT_MARKER = "<!-- newsoc:summary -->"
CHECK_NAME = "newsoc/security"
MAX_SUMMARY_CHARS = 60_000  # GitHub allows 65,535; leave headroom for the truncation note
MAX_COMMENT_CHARS = 60_000
MAX_ANNOTATIONS = 500
ANNOTATION_BATCH = 50
TOP_FINDINGS_IN_SUMMARY = 15
TOP_FINDINGS_IN_COMMENT = 10
FOOTER = (
    "newsoc reports technical evidence from automated scanners. It is not a certification and "
    "does not show that a system is secure or compliant."
)

# What newsoc can look at today; keep in step with the scanner adapters (see docs/MVP_PLAN.md).
SUPPORTED_NOTE = (
    "newsoc analyses JavaScript, TypeScript and Python code, npm and PyPI dependencies "
    "(from lockfiles), and Terraform files and Dockerfiles. Secrets are checked in every language."
)
_CATEGORY_NAME = {
    Category.SAST: "SAST",
    Category.SCA: "SCA",
    Category.SECRETS: "secrets",
    Category.IAC: "IaC",
}

_LEVEL = {
    Outcome.BLOCKED: "failure",
    Outcome.WOULD_BLOCK: "warning",
    Outcome.WARNED: "warning",
}
_OUTCOME_ORDER = {Outcome.BLOCKED: 0, Outcome.WOULD_BLOCK: 1, Outcome.WARNED: 2}
_OUTCOME_LABEL = {
    Outcome.BLOCKED: "blocking",
    Outcome.WOULD_BLOCK: "would block (observe mode)",
    Outcome.WARNED: "warning",
    Outcome.WAIVED: "waived",
    Outcome.BASELINED: "existing",
}


def md_text(text: str, limit: int = 300) -> str:
    """Make untrusted text safe to place in a Markdown sentence or table cell."""
    flat = " ".join(str(text).split())
    flat = flat.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    flat = flat.replace("|", "\\|").replace("`", "'").replace("@", "@​")
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def _sort_key(d: Decision) -> tuple[int, int, str, int]:
    f = d.finding
    return (_OUTCOME_ORDER.get(d.outcome, 9), -f.severity.rank, f.path, f.start_line)


def reportable(outcome: PolicyOutcome) -> list[Decision]:
    """Decisions worth showing a developer: blocking first, then by severity. Excludes waived
    and existing findings, which would only add noise to the pull request."""
    keep = [d for d in outcome.decisions if d.outcome in _OUTCOME_ORDER]
    return sorted(keep, key=_sort_key)


@dataclass(frozen=True)
class CheckOutput:
    title: str
    summary: str
    annotations: list[dict[str, Any]]
    truncated_annotations: int


def render_check(
    outcome: PolicyOutcome, results: list[ScanResult], *, rules_version: str | None = None
) -> CheckOutput:
    shown = reportable(outcome)
    annotations = [_annotation(d) for d in shown[:MAX_ANNOTATIONS]]
    return CheckOutput(
        title=outcome.title,
        summary=_summary(outcome, results, shown, rules_version),
        annotations=annotations,
        truncated_annotations=max(len(shown) - MAX_ANNOTATIONS, 0),
    )


def annotation_batches(annotations: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    return [
        annotations[i : i + ANNOTATION_BATCH] for i in range(0, len(annotations), ANNOTATION_BATCH)
    ]


def _annotation(d: Decision) -> dict[str, Any]:
    f = d.finding
    level = _LEVEL[d.outcome]
    if d.outcome is Outcome.WARNED and f.severity in (Severity.MEDIUM, Severity.LOW):
        level = "notice"
    details = "\n".join(f.evidence)[:1000]
    note: dict[str, Any] = {
        "path": f.path,
        "start_line": f.start_line,
        "end_line": max(f.end_line, f.start_line),
        "annotation_level": level,
        "title": md_text(f"{f.severity.value.upper()}: {f.rule_id}", 255),
        "message": md_text(f.message, 2000),
    }
    if details:
        note["raw_details"] = details
    return note


def _category_rows(outcome: PolicyOutcome, results: list[ScanResult]) -> list[str]:
    rows = ["| Category | Scanner | Result | Findings |", "|---|---|---|---|"]
    status_by_scanner = {c.scanner: c for c in outcome.categories}
    for r in results:
        cat = status_by_scanner.get(r.scanner)
        word = r.assessment().value
        count = str(len(r.findings))
        if r.assessment() is AssessmentStatus.NOT_ASSESSED:
            word += f" ({md_text(cat.detail if cat else r.reason or 'unknown', 120)})"
            count = "-"  # a scanner that did not run has not found "0"
        rows.append(f"| {r.category.value} | {r.scanner} | {word} | {count} |")
    return rows


def _coverage_lines(outcome: PolicyOutcome) -> list[str]:
    """Which categories were assessed and which were not. The reason for each gap is in the
    category table, so only its kind (not applicable, failed, timed out) is repeated here.

    When no code-analysis category (SAST, SCA, IaC) was assessed, say so plainly and list what
    newsoc does support, so a green check on an unsupported language is not read as a review.
    """
    cov = outcome.coverage
    names = ", ".join(_CATEGORY_NAME[c] for c in cov.assessed)
    if not cov.gaps:
        return [f"**Coverage:** all categories assessed ({names})."]
    missing = ", ".join(f"{_CATEGORY_NAME[g.category]} ({g.kind.value})" for g in cov.gaps)
    lines = [f"**Coverage:** assessed: {names or 'none'}. Not assessed: {missing}."]
    if cov.code_analysis_assessed:
        return lines
    only = (
        "Only secrets were checked."
        if Category.SECRETS in cov.assessed
        else "Secrets were not assessed either."
    )
    lines += [
        "",
        "> **No code analysis ran.** SAST (static analysis), SCA (dependency scanning) and IaC "
        "(infrastructure-as-code scanning) were not assessed, so this result does not cover "
        f"code, dependencies or infrastructure files. {only}",
    ]
    if any(g.category in CODE_ANALYSIS and g.kind is GapKind.NOT_APPLICABLE for g in cov.gaps):
        lines += [">", f"> {SUPPORTED_NOTE}"]
    return lines


def _finding_line(d: Decision) -> str:
    f: Finding = d.finding
    return (
        f"- **{f.severity.value}** `{md_text(f.rule_id, 80)}` "
        f"in `{md_text(f.path, 120)}:{f.start_line}` "
        f"({_OUTCOME_LABEL[d.outcome]}): {md_text(f.message, 200)}"
    )


def _counts(outcome: PolicyOutcome) -> str:
    parts = []
    for o in (
        Outcome.BLOCKED,
        Outcome.WOULD_BLOCK,
        Outcome.WARNED,
        Outcome.WAIVED,
        Outcome.BASELINED,
    ):
        n = len(outcome.of(o))
        if n:
            parts.append(f"{n} {_OUTCOME_LABEL[o]}")
    return ", ".join(parts) or "no findings"


def _summary(
    outcome: PolicyOutcome,
    results: list[ScanResult],
    shown: list[Decision],
    rules_version: str | None,
) -> str:
    lines = [f"**{md_text(outcome.title)}**", "", f"Findings: {_counts(outcome)}.", ""]
    lines += [*_coverage_lines(outcome), ""]
    lines += _category_rows(outcome, results)
    if shown:
        lines += [
            "",
            f"### Top findings (showing {min(len(shown), TOP_FINDINGS_IN_SUMMARY)}"
            f" of {len(shown)})",
        ]
        lines += [_finding_line(d) for d in shown[:TOP_FINDINGS_IN_SUMMARY]]
    if outcome.notes:
        lines += ["", "### Notes"] + [f"- {md_text(n, 300)}" for n in outcome.notes]
    versions = ", ".join(
        sorted({f"{r.scanner} {r.tool_version}" for r in results if r.tool_version})
    )
    lines += ["", "---", FOOTER]
    if versions or rules_version:
        lines.append(f"Scanners: {versions or 'n/a'}. Rule pack: {rules_version or 'n/a'}.")
    text = "\n".join(lines)
    if len(text) > MAX_SUMMARY_CHARS:
        text = (
            text[: MAX_SUMMARY_CHARS - 80].rstrip()
            + "\n\n(Summary truncated; see the check annotations.)"
        )
    return text


def render_comment(
    outcome: PolicyOutcome, results: list[ScanResult], *, check_url: str | None = None
) -> str:
    """The pull request comment. It carries a marker so the next run updates it in place."""
    shown = reportable(outcome)
    lines = [
        COMMENT_MARKER,
        f"### newsoc security check: {outcome.conclusion.value.replace('_', ' ')}",
        "",
        f"{md_text(outcome.title)}. Findings: {_counts(outcome)}.",
        "",
        *_coverage_lines(outcome),
        "",
        *_category_rows(outcome, results),
    ]
    if shown:
        lines += [
            "",
            f"**Top findings** ({min(len(shown), TOP_FINDINGS_IN_COMMENT)} of {len(shown)}):",
        ]
        lines += [_finding_line(d) for d in shown[:TOP_FINDINGS_IN_COMMENT]]
    if check_url:
        lines += ["", f"Full details and inline annotations: {check_url}"]
    lines += ["", f"<sub>{FOOTER}</sub>"]
    text = "\n".join(lines)
    if len(text) > MAX_COMMENT_CHARS:
        text = text[: MAX_COMMENT_CHARS - 60] + "\n\n(Comment truncated.)\n"
    return text
