"""A scanner's own notes must reach the developer in the check summary."""

from __future__ import annotations

from datetime import date

from newsoc_code.findings.schema import Category
from newsoc_code.policy.engine import PolicyOutcome, evaluate
from newsoc_code.policy.loader import load_policy
from newsoc_code.report.render import MAX_NOTES, all_notes, render_check
from tests.factories import result

TODAY = date(2026, 10, 26)


def outcome_for(results) -> PolicyOutcome:
    return evaluate(load_policy("mode: enforce\n", TODAY), results, frozenset(), TODAY)


def with_notes(category: Category, *notes: str):
    return result(category).model_copy(update={"notes": list(notes)})


def notes_section(summary: str) -> list[str]:
    lines = summary.splitlines()
    start = lines.index("### Notes") + 1
    out = []
    for line in lines[start:]:
        if not line.startswith("- "):
            break
        out.append(line[2:])
    return out


def test_the_engine_does_not_copy_scanner_notes_so_render_must_gather_them():
    results = [with_notes(Category.SAST, "3 file(s) were only partly parsed")]
    assert outcome_for(results).notes == []  # why render has to merge them in


def test_a_scanner_note_appears_in_the_check_summary():
    results = [
        with_notes(
            Category.SAST,
            "2 file(s) were only partly parsed, so findings in them may be missing: a.tsx, b.tsx",
        )
    ]

    summary = render_check(outcome_for(results), results).summary

    assert "### Notes" in summary
    assert notes_section(summary) == [
        "2 file(s) were only partly parsed, so findings in them may be missing: a.tsx, b.tsx"
    ]


def test_policy_notes_come_first_then_every_scanners_notes():
    results = [with_notes(Category.SAST, "from sast"), with_notes(Category.SECRETS, "from secrets")]
    outcome = outcome_for(results)
    outcome.notes.append("from the pipeline")

    assert notes_section(render_check(outcome, results).summary) == [
        "from the pipeline",
        "from sast",
        "from secrets",
    ]


def test_repeated_notes_are_shown_once():
    results = [
        with_notes(Category.SAST, "same  note", "same note"),
        with_notes(Category.SECRETS, "same note"),
    ]
    outcome = outcome_for(results)
    outcome.notes.append("same note")  # e.g. the OSV freshness warning the pipeline also adds

    assert all_notes(outcome, results) == ["same note"]
    assert notes_section(render_check(outcome, results).summary) == ["same note"]


def test_scanner_notes_are_escaped_like_any_untrusted_text():
    nasty = "<img src=x onerror=1> ping @victim | `x`\nsecond line: weird.tsx"
    results = [with_notes(Category.SAST, nasty)]

    summary = render_check(outcome_for(results), results).summary

    [line] = notes_section(summary)
    assert "<img" not in line and "`" not in line and "\n" not in line
    assert "@victim" not in line  # a zero-width space breaks the mention
    assert "\\|" in line and "weird.tsx" in line


def test_a_flood_of_notes_is_capped_and_says_so():
    results = [with_notes(Category.SAST, *(f"note {i}" for i in range(MAX_NOTES + 6)))]

    summary = render_check(outcome_for(results), results).summary

    shown = notes_section(summary)
    assert len(shown) == MAX_NOTES + 1  # the cap, then the "not shown" line
    assert shown[0] == "note 0" and shown[MAX_NOTES - 1] == f"note {MAX_NOTES - 1}"
    assert shown[-1] == "(6 more note(s) not shown)"
    assert f"note {MAX_NOTES}" not in summary


def test_a_very_long_note_is_truncated():
    results = [with_notes(Category.SAST, "x" * 5000)]

    [line] = notes_section(render_check(outcome_for(results), results).summary)

    assert len(line) <= 700 and line.endswith("…")


def test_no_notes_means_no_notes_section():
    results = [result(Category.SAST)]
    assert "### Notes" not in render_check(outcome_for(results), results).summary
