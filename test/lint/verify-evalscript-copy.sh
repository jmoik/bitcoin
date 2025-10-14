#!/bin/bash
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Verifies that a commit copies EvalScript() without modifying the function body.
# Usage: ./verify-evalscript-copy.sh <commit_hash>

export LC_ALL=C

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <commit_hash>"
    exit 1
fi

COMMIT="$1"
PARENT="${COMMIT}^"
FILE="src/script/interpreter.cpp"

TMPDIR="${TMPDIR:-/tmp}"
ORIGINAL_BODY=$(mktemp "${TMPDIR}/original_body.XXXXXX")
COPIED_BODY=$(mktemp "${TMPDIR}/copied_body.XXXXXX")

cleanup() {
    rm -f "$ORIGINAL_BODY" "$COPIED_BODY"
}
trap cleanup EXIT

echo "=== Verifying EvalScript copy in commit $COMMIT ==="
echo

echo "Locating original EvalScript in parent commit..."
ORIG_START=$(git show ${PARENT}:${FILE} | grep -n "^bool EvalScript.*ScriptExecutionData& execdata, ScriptError" | head -1 | cut -d: -f1)
if [ -z "$ORIG_START" ]; then
    echo "ERROR: Could not find original EvalScript in parent commit"
    exit 1
fi
echo "  Found at line $ORIG_START"

echo "Extracting original EvalScript body..."
git show ${PARENT}:${FILE} | tail -n +${ORIG_START} | awk '
    BEGIN { brace_count = 0; started = 0 }
    /^bool EvalScript/ { started = 1; next }
    started {
        print
        brace_count += gsub(/{/, "{")
        brace_count -= gsub(/}/, "}")
        if (brace_count == 0 && NR > 1) exit
    }
' > "$ORIGINAL_BODY"

echo "Locating copied EvalScript in commit..."
COPY_START=$(git show ${COMMIT}:${FILE} | grep -n "^bool EvalScript.*varops_budget" | head -1 | cut -d: -f1)
if [ -z "$COPY_START" ]; then
    echo "ERROR: Could not find copied EvalScript with varops_budget in commit"
    exit 1
fi
echo "  Found at line $COPY_START"

echo "Extracting copied EvalScript body..."
git show ${COMMIT}:${FILE} | tail -n +${COPY_START} | awk '
    BEGIN { brace_count = 0; started = 0 }
    /^bool EvalScript/ { started = 1; next }
    started {
        print
        brace_count += gsub(/{/, "{")
        brace_count -= gsub(/}/, "}")
        if (brace_count == 0 && NR > 1) exit
    }
' > "$COPIED_BODY"

echo
echo "Original body: $(wc -l < "$ORIGINAL_BODY" | tr -d ' ') lines"
echo "Copied body:   $(wc -l < "$COPIED_BODY" | tr -d ' ') lines"

echo
BODY_DIFF=$(diff "$ORIGINAL_BODY" "$COPIED_BODY" 2>&1 || true)

if [ -z "$BODY_DIFF" ]; then
    echo "=== RESULT ==="
    echo "SUCCESS: Function bodies are IDENTICAL"
else
    echo "=== RESULT ==="
    echo "FAILURE: Function bodies DIFFER"
    echo
    echo "Differences:"
    echo "$BODY_DIFF"
    exit 1
fi
