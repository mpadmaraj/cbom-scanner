#!/bin/sh
set -e
WORKSPACE="${1:-/tmp/repo}"
cyclonedx create --output-format json --output-file "$WORKSPACE/cbomkit-out.json" "$WORKSPACE" >/dev/null 2>&1 || true
cat "$WORKSPACE/cbomkit-out.json" 2>/dev/null || echo "{}"
