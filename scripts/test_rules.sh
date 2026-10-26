#!/usr/bin/env bash
# Validate and test the Semgrep rule pack inside the scanner image (no network, read-only).
#   scripts/test_rules.sh            # all rules
#   scripts/test_rules.sh js         # one language directory
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE=${NEWSOC_IMAGE:-newsoc/scanners:dev}
SUB=${1:-}
RUN=(docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges
     --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,size=256m,mode=1777
     -v "$PWD/rules/semgrep:/rules:ro" "$IMAGE")
TARGET=/rules${SUB:+/$SUB}
# Note: `semgrep --validate` is deliberately not used. It downloads Semgrep's registry lint
# pack, which needs a network and is not part of our clean-room pack. `--test` parses every
# rule (an invalid rule fails) and checks the annotated test files.
echo "== test $TARGET"
"${RUN[@]}" semgrep --test --config "$TARGET" "$TARGET" --metrics=off --disable-version-check
