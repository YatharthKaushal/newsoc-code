"""Files Semgrep could only partly parse must show up as a note, never as a plain "ok"."""

from __future__ import annotations

import json

import builders as fx

from newsoc_code.findings.schema import ScanStatus
from newsoc_code.scanners.semgrep import MAX_NOTE_PATHS, SemgrepAdapter
from tests.conftest import run_output


def parse(ctx, errors):
    report = {"version": "1.182.1", "results": [], "errors": errors, "paths": {"scanned": []}}
    (ctx.out_dir / "semgrep.json").write_text(json.dumps(report), encoding="utf-8")
    return SemgrepAdapter().parse(ctx, run_output(0))


def partial(path: str) -> dict:
    return {"code": 3, "level": "warn", "type": ["PartialParsing", []], "path": path}


def test_golden_partial_parses_are_counted_per_distinct_file(tmp_path, make_ctx, place_report):
    ctx = make_ctx(tmp_path)
    place_report(ctx, "semgrep/partial-parse-errors.json", "semgrep.json")

    result = SemgrepAdapter().parse(ctx, run_output(0))

    assert result.status is ScanStatus.OK  # the run itself worked; the note says what it missed
    assert result.findings == []
    syntax, partly, other = result.notes
    # seven files, one of them reported twice: counted once, listed repo-relative, sorted
    assert partly.startswith(
        "7 file(s) were only partly parsed, so findings in them may be missing"
    )
    assert (
        "web/components/Dashboard.tsx, web/components/Settings Panel.tsx, web/pages/Admin.js, "
        "web/pages/Checkout.js, web/pages/Landing.js (+2 more)"
    ) in partly
    assert "/src" not in partly  # the container path prefix is gone
    assert "Orders.js" not in partly  # beyond the cap
    assert syntax == "1 file(s) could not be parsed, so they were not analysed: legacy/broken.js"
    assert other == "semgrep reported 1 other non-fatal error(s)"


def test_the_note_never_lists_more_than_the_cap(tmp_path, make_ctx):
    errors = [partial(f"/src/pkg/file{i:02d}.tsx") for i in range(40)]

    [note] = parse(make_ctx(tmp_path), errors).notes

    assert note.startswith("40 file(s) were only partly parsed")
    assert note.count(".tsx") == MAX_NOTE_PATHS
    assert note.endswith(f"(+{40 - MAX_NOTE_PATHS} more)")


def test_a_clean_run_has_no_notes(tmp_path, make_ctx, place_report):
    fx.make_py_app(tmp_path)
    ctx = make_ctx(tmp_path)
    place_report(ctx, "semgrep/py-shell-true.json", "semgrep.json")

    assert SemgrepAdapter().parse(ctx, run_output(0)).notes == []


def test_a_file_that_is_both_partly_and_wholly_unparsed_counts_as_unparsed(tmp_path, make_ctx):
    errors = [partial("/src/a.js"), {"type": "SyntaxError", "path": "/src/a.js"}]

    result = parse(make_ctx(tmp_path), errors)

    assert result.notes == ["1 file(s) could not be parsed, so they were not analysed: a.js"]


def test_the_path_falls_back_to_the_first_span_and_odd_entries_are_counted_not_crashed_on(
    tmp_path, make_ctx
):
    errors = [
        {"type": ["PartialParsing", []], "spans": [{"file": "/src/from/span.tsx"}]},
        {"type": ["PartialParsing", []]},  # no path at all
        "not a dict",
        {"type": 7},
        {"type": []},
    ]

    result = parse(make_ctx(tmp_path), errors)

    [partly, other] = result.notes
    assert partly.startswith("2 file(s) were only partly parsed")
    assert "from/span.tsx" in partly and "(unknown file)" in partly
    assert other == "semgrep reported 3 other non-fatal error(s)"


def test_a_missing_or_malformed_errors_field_is_not_a_failure(tmp_path, make_ctx):
    ctx = make_ctx(tmp_path)
    (ctx.out_dir / "semgrep.json").write_text('{"results": [], "errors": null}', encoding="utf-8")
    assert SemgrepAdapter().parse(ctx, run_output(0)).notes == []
    (ctx.out_dir / "semgrep.json").write_text('{"results": []}', encoding="utf-8")
    assert SemgrepAdapter().parse(ctx, run_output(0)).notes == []
    (ctx.out_dir / "semgrep.json").write_text('{"results": [], "errors": "x"}', encoding="utf-8")
    assert SemgrepAdapter().parse(ctx, run_output(0)).notes == []
