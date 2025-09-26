#!/bin/sh

# Usage: run-semgrep.sh <workspace> <rules.yml> <language>
set -e

WORKSPACE="${1:-/tmp/repo}"
RULES="${2:-/app/scanner-scripts/rules}"
LANG="${3:-generic}"

EXCLUDES=""

case "$LANG" in
    python)
        EXCLUDES="--exclude venv --exclude .venv --exclude __pycache__"
        ;;
    javascript|typescript|node)
        EXCLUDES="--exclude node_modules --exclude dist --exclude build"
        ;;
    java)
        EXCLUDES="--exclude target --exclude out --exclude build"
        ;;
    go)
        EXCLUDES="--exclude vendor"
        ;;
    generic)
        EXCLUDES="--exclude node_modules --exclude dist --exclude build --exclude venv --exclude .venv --exclude __pycache__ --exclude target --exclude out --exclude vendor"
        ;;
    *)
        EXCLUDES=""
        ;;
esac

semgrep --config "$RULES" \
    --json --output "$WORKSPACE/semgrep-out.json" \
    $EXCLUDES \
    "$WORKSPACE" >/dev/null 2>&1 || true

cat "$WORKSPACE/semgrep-out.json" 2>/dev/null || echo "{}"
