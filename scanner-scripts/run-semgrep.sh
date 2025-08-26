#!/bin/sh
WORKSPACE="${1:-/tmp/repo}"
docker run --rm -v "$WORKSPACE":/src -v /app/scanner-scripts/rules:/rules returntocorp/semgrep   semgrep --config /rules --json --output /src/semgrep-out.json /src >/dev/null 2>&1
cat "$WORKSPACE/semgrep-out.json" || echo "{}"
